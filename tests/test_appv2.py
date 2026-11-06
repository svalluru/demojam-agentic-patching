"""Applications v2: the parts that decide what reaches a server.

    python3 -m unittest discover -s tests
"""
import hashlib
import hmac
import re
import json
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import appv2  # noqa: E402


def demo(**extra):
    # Every test gets its own state directory: a live-mode test must never write into the repo's runs/, where a
    # local console would restore it at startup.
    extra.setdefault('APPV2_STATE_DIR', tempfile.mkdtemp(prefix='appv2-test-'))
    appv2.configure(env=lambda k, d='': extra.get(k, d), demo_mode=lambda: True,
                    demo_pause=lambda f=1.0: None, llm=None, ao_call=None, fixed_cves=None)
    appv2.reset()
    appv2._BOM_UPDATES.clear()


class Versions(unittest.TestCase):
    def test_upstream(self):
        self.assertEqual(appv2.upstream('2.24.3.rhlw-00004'), '2.24.3')
        self.assertEqual(appv2.upstream('5.3.17.rhlw-00001-n0001'), '5.3.17')
        self.assertEqual(appv2.upstream('2.24.3'), '2.24.3')
        self.assertTrue(appv2.is_lightwell('2.11.0.rhlw-00009'))
        self.assertFalse(appv2.is_lightwell('2.11.0'))


class Webhook(unittest.TestCase):
    BODY = json.dumps({'action': 'CREATED', 'repositoryName': 'lightwell-remediated',
                       'component': {'format': 'maven2', 'group': 'org.apache.logging.log4j',
                                     'name': 'log4j-core', 'version': '2.24.3.rhlw-00004'}}).encode()

    def sign(self, body, secret='s3cret'):
        return hmac.new(secret.encode(), body, hashlib.sha1).hexdigest()

    def test_signature(self):
        self.assertTrue(appv2.verify_signature(self.BODY, self.sign(self.BODY), 's3cret'))
        self.assertFalse(appv2.verify_signature(self.BODY, self.sign(self.BODY, 'other'), 's3cret'))
        self.assertFalse(appv2.verify_signature(self.BODY, '', 's3cret'))
        self.assertFalse(appv2.verify_signature(self.BODY, self.sign(self.BODY), ''))

    def test_rejects_bad_signature_when_secret_set(self):
        demo(NEXUS_WEBHOOK_SECRET='s3cret')
        code, _ = appv2.accept_webhook(self.BODY, 'deadbeef')
        self.assertEqual(code, 401)
        code, body = appv2.accept_webhook(self.BODY, self.sign(self.BODY))
        self.assertEqual(code, 200)
        self.assertEqual(body['event']['artifact'], 'log4j-core')

    def test_live_without_secret_trusts_nothing(self):
        demo()
        appv2.configure(demo_mode=lambda: False)
        appv2.EVENTS = appv2.EventStore(None)
        code, _ = appv2.accept_webhook(self.BODY, '')
        self.assertEqual(code, 503)

    def test_parse_only_new_lightwell_builds(self):
        p = json.loads(self.BODY)
        self.assertIsNotNone(appv2.parse_nexus(p))
        self.assertIsNone(appv2.parse_nexus({**p, 'action': 'UPDATED'}))
        self.assertIsNone(appv2.parse_nexus({**p, 'component': {**p['component'], 'version': '2.24.3'}}))
        self.assertIsNone(appv2.parse_nexus({**p, 'component': {**p['component'], 'group': ''}}))
        self.assertIsNone(appv2.parse_nexus('nope'))

    def test_duplicate_delivery_is_one_event(self):
        demo()
        store = appv2.EventStore(None)
        before = len(store.all())
        a = store.add(appv2.parse_nexus(json.loads(self.BODY)))
        b = store.add(appv2.parse_nexus(json.loads(self.BODY)))
        self.assertEqual(a['id'], b['id'])
        self.assertEqual(len(store.all()), before)        # the demo inbox already holds this build


class Impact(unittest.TestCase):
    def setUp(self):
        demo()

    def test_exact_version_only(self):
        ev = next(e for e in appv2.DEMO_EVENTS if e['artifact'] == 'log4j-core')
        imp = appv2.impact(ev, appv2.load_bom())
        self.assertEqual(imp['apps'], ['billing-api', 'orders-api', 'orders-service'])
        self.assertEqual(len(imp['targets']), 5)
        self.assertEqual(len({t['key'] for t in imp['targets']}), 5)          # two apps share orders-qa-01
        self.assertEqual(imp['targets'][0]['env'], 'qa')                  # QA first
        self.assertEqual([o['app'] for o in imp['other']], ['catalog-web'])  # 2.25.1, left alone

    def test_write_back_removes_app_from_next_impact(self):
        ev = next(e for e in appv2.DEMO_EVENTS if e['artifact'] == 'log4j-core')
        appv2._BOM_UPDATES['billing-api|org.apache.logging.log4j:log4j-core'] = ev['version']
        imp = appv2.impact(ev, appv2.load_bom())
        self.assertEqual(imp['apps'], ['orders-api', 'orders-service'])
        self.assertIn('already on this build', [o['why'] for o in imp['other']])


class Playbook(unittest.TestCase):
    def setUp(self):
        demo()
        ev = appv2.DEMO_EVENTS[0]
        self.text = appv2.render_playbook(ev, appv2.impact(ev, appv2.load_bom())['targets'][0])

    def ok(self, text):
        return {c['id']: c['ok'] for c in appv2.check_playbook(text)}

    def test_template_passes(self):
        self.assertTrue(all(self.ok(self.text).values()), appv2.check_playbook(self.text))

    def test_rejects_shell(self):
        bad = self.text.replace('ansible.builtin.systemd_service:', 'ansible.builtin.shell: systemctl restart x\n          ansible.builtin.systemd_service:', 1)
        self.assertFalse(self.ok(bad)['modules'])
        bad = self.text.replace('        - name: Restart the service\n',
                                '        - name: Restart the service\n          shell: rm -rf /\n', 1)
        self.assertFalse(self.ok(bad)['modules'])

    def test_rejects_unknown_collection(self):
        bad = self.text.replace('ansible.builtin.uri:', 'community.general.something:', 1)
        self.assertFalse(self.ok(bad)['modules'])

    def test_requires_verify_and_rollback(self):
        no_rescue = self.text.split('      rescue:')[0]
        self.assertFalse(self.ok(no_rescue)['rollback'])
        no_verify = self.text.replace('ansible.builtin.uri:', 'ansible.builtin.debug:')
        self.assertFalse(self.ok(no_verify)['verify'])
        no_pin = self.text.replace('checksum: "sha256:', 'checksum_off: "')
        self.assertFalse(self.ok(no_pin)['checksum'])

    def test_tasks_only_draft_is_rejected(self):
        # What the live LLM produced on 2026-11-05: the task list, without the play header or its vars.
        tasks_only = '\n'.join(l[4:] for l in self.text.split('\n  tasks:\n', 1)[1].splitlines())
        ok = {c['id']: c['ok'] for c in appv2.check_playbook(tasks_only, self.text)}
        self.assertFalse(ok['play'])
        self.assertFalse(ok['pinned'])

    def test_changed_path_is_rejected(self):
        moved = re.sub(r'lib_dir: \S+', 'lib_dir: /tmp/lib', self.text, count=1)
        self.assertNotEqual(moved, self.text)
        ok = {c['id']: c['ok'] for c in appv2.check_playbook(moved, self.text)}
        self.assertTrue(ok['play'])
        self.assertFalse(ok['pinned'])

    def test_template_passes_with_pinning(self):
        self.assertTrue(all(c['ok'] for c in appv2.check_playbook(self.text, self.text)))

    def test_bad_llm_draft_falls_back_to_template(self):
        appv2.configure(demo_mode=lambda: False, llm=lambda prompt: '- hosts: all\n  tasks:\n    - shell: curl x | sh\n')
        ev = appv2.DEMO_EVENTS[0]
        target = appv2.impact(ev, json.loads(json.dumps(appv2.DEMO_BOM)))['targets'][0]
        text, source, checks, note = appv2.draft_playbook(ev, target)
        self.assertEqual(source, 'template')
        self.assertTrue(all(c['ok'] for c in checks))
        self.assertIn('failed', note)


class DemoRun(unittest.TestCase):
    def wait(self, status, timeout=5):
        end = time.time() + timeout
        while time.time() < end:
            if appv2.state().get('status') in status:
                return appv2.state()
            time.sleep(0.02)
        self.fail(f"stuck at {appv2.state().get('status')}")

    def test_full_staged_run(self):
        demo()
        self.assertEqual(appv2.start_assess('evt-log4j-core')[0], 200)
        self.wait({'assessed'})
        self.assertEqual(appv2.start_generate()[0], 200)
        self.wait({'generated'})
        self.assertEqual(appv2.start_dispatch()[0], 200)
        st = self.wait({'awaiting_approval'})
        gated = [h['key'] for h in st['hosts'] if h['outcome'] == 'awaiting_approval']
        self.assertEqual(len(gated), 3)
        self.assertEqual(appv2.decide('orders-qa-01.acme.internal', 'approved')[0], 409)   # QA is not gated
        for h in gated:
            self.assertEqual(appv2.decide(h, 'approved')[0], 200)
        st = self.wait({'complete'})
        self.assertEqual(st['summary'], {'patched': 4, 'rolled_back': 1, 'rejected': 0, 'failed': 0, 'skipped': 0})
        self.assertEqual(st['stages']['verify'], 'failed')
        # Only the app with every server patched is written back.
        self.assertIn('billing-api|org.apache.logging.log4j:log4j-core', appv2._BOM_UPDATES)
        self.assertNotIn('orders-service|org.apache.logging.log4j:log4j-core', appv2._BOM_UPDATES)

    def test_order_is_enforced(self):
        demo()
        self.assertEqual(appv2.start_generate()[0], 409)
        self.assertEqual(appv2.start_dispatch()[0], 409)
        self.assertEqual(appv2.start_assess('no-such-event')[0], 404)


class Poller(unittest.TestCase):
    META = ('<metadata><versioning><versions><version>2.24.3.rhlw-00004</version>'
            '<version>2.25.1.rhlw-00002</version><version>2.24.3</version></versions></versioning></metadata>')

    def test_requests_only_builds_of_installed_versions(self):
        demo(NEXUS_URL='https://nexus.lab', NEXUS_EVENTS='poller')
        asked = []

        def fetch(url):
            asked.append(url)
            if url.endswith('log4j-core/maven-metadata.xml'):
                return self.META.encode()
            if url.endswith('.jar'):
                return b'jar'
            raise OSError('404')

        apps = [{'app': 'a', 'dependencies': [{'group': 'org.apache.logging.log4j', 'artifact': 'log4j-core', 'version': '2.24.3'}]}]
        seen = set()
        found = appv2.poll_nexus(fetch, seen, apps)
        self.assertEqual([f['version'] for f in found], ['2.24.3.rhlw-00004'])   # not 2.25.1: nothing runs it
        self.assertTrue(any(u.endswith('log4j-core-2.24.3.rhlw-00004.jar') for u in asked))
        self.assertTrue(any(e['version'] == '2.24.3.rhlw-00004' for e in appv2.events().all()))
        self.assertEqual(appv2.poll_nexus(fetch, seen, apps), [])                 # seen: not requested twice


class LiveFollow(unittest.TestCase):
    """The live path against a fake AO that walks one Prod execution through the App Patch v2 nodes."""

    def test_prod_host_stops_at_gate_then_patches(self):
        demo()
        phase = {'n': 'gate'}
        signals = []

        def ao(path, method='GET', body=None):
            if path == '/api/v1/workflows':
                return {'resources': [{'id': 'wf1', 'name': 'App Patch v2'}]}
            if path == '/api/v1/executions' and method == 'POST':
                return {'id': 'ex1'}
            if path.endswith('/signal'):
                signals.append((path, body))
                phase['n'] = 'done'
                return {}
            if path == '/api/v1/executions/ex1':
                return {'status': 'running' if phase['n'] == 'gate' else 'completed'}
            if path == '/api/v1/executions/ex1/activities':
                commit = {'temporal_activity_id': 'commit_to_gitea', 'status': 'completed', 'started_at': 't',
                          'output_data': {'artifacts': {'commit_sha': 'abc123', 'jar_sha256': 'f' * 64,
                                                        'provenance_verified': True, 'commit_url': 'https://g/c'}}}
                gate = {'temporal_activity_id': 'approval_prod', 'node_type': 'approval', 'started_at': 't',
                        'status': 'waiting' if phase['n'] == 'gate' else 'completed'}
                run = {'temporal_activity_id': 'run_app_patch_prod', 'status': 'completed', 'started_at': 't',
                       'output_data': {'artifacts': {'patched': True, 'version': 'x.jar'}}}
                return {'resources': [commit, gate] + ([run] if phase['n'] == 'done' else [])}
            raise AssertionError(path)

        appv2.configure(demo_mode=lambda: False, ao_call=ao)
        # Only appv2's clock: its poll interval goes to zero, the test's own waits stay real.
        appv2.time = types.SimpleNamespace(sleep=lambda s: None, time=time.time)
        try:
            appv2.EVENTS = appv2.EventStore(None)
            ev = dict(appv2.DEMO_EVENTS[0])
            target = {'key': 'billing-api|billing-prod-01', 'app': 'billing-api', 'host': 'billing-prod-01',
                      'env': 'prod', 'installed': '2.24.3',
                      'path': '/opt/apps/billing-api', 'service': 'billing-api', 'health_url': 'http://x'}
            with appv2._LOCK:
                appv2._RUN.clear()
                appv2._RUN.update(status='generated', run_id='r1', event=ev, events=[],
                                  stages={k: 'pending' for k in appv2.STAGES},
                                  impact={'targets': [target], 'apps': ['billing-api'], 'other': []},
                                  playbooks=[{'app': 'billing-api', 'filename': 'app-v2/b.yml', 'text': 'x',
                                              'sha256': '0' * 64, 'ok': True}])
            appv2.start_dispatch()
            for _ in range(200):
                if appv2.state()['hosts'][0]['outcome'] == 'awaiting_approval':
                    break
                time.sleep(0.01)
            h = appv2.state()['hosts'][0]
            self.assertEqual(h['outcome'], 'awaiting_approval')
            self.assertEqual(h['commit_sha'], 'abc123')
            self.assertEqual(h['provenance'], 'verified')
            self.assertEqual(appv2.decide('billing-prod-01', 'approved')[0], 200)
            self.assertEqual(signals[0][1], {'signal_data': {'decision': 'approved'}})
            for _ in range(200):
                if appv2.state().get('status') == 'complete':
                    break
                time.sleep(0.01)
            st = appv2.state()
            self.assertEqual(st['status'], 'complete')
            self.assertEqual(st['hosts'][0]['outcome'], 'patched')
            self.assertEqual(st['hosts'][0]['steps']['verify'], 'done')
        finally:
            appv2.time = time


class Restart(unittest.TestCase):
    """Live mode: the run outlives a console restart. A restart is simulated by emptying the in-memory run and
    calling restore(), which is what a new process does at startup."""

    def setUp(self):
        import tempfile
        self.dir = tempfile.mkdtemp()
        self.signals = []
        self.phase = 'running'

        def ao(path, method='GET', body=None):
            if path.endswith('/signal'):
                self.signals.append(body)
                return {}
            if path.endswith('/activities'):
                run = {'temporal_activity_id': 'run_app_patch', 'status': 'completed', 'started_at': 't',
                       'output_data': {'artifacts': {'patched': True, 'version': 'x.jar'}}}
                return {'resources': [run] if self.phase == 'done' else []}
            return {'status': 'completed' if self.phase == 'done' else 'running'}

        demo(APPV2_STATE_DIR=self.dir)
        appv2.configure(demo_mode=lambda: False, ao_call=ao)
        self.clock = appv2.time
        appv2.time = types.SimpleNamespace(sleep=lambda s: None, time=time.time)

    def tearDown(self):
        appv2.time = self.clock
        appv2.reset()

    def saved_run(self, status, hosts):
        with appv2._LOCK:
            appv2._RUN.clear()
            appv2._RUN.update(status=status, run_id='r1', event=dict(appv2.DEMO_EVENTS[0]), events=[],
                              stages={k: 'pending' for k in appv2.STAGES}, hosts=hosts,
                              impact={'targets': [], 'apps': ['sample-app'], 'other': []}, playbooks=[])
        appv2._persist()
        with appv2._LOCK:                       # the process "dies": memory is gone, the file is not
            appv2._RUN.clear()
            appv2._RUN['status'] = 'idle'

    def host(self, name, env, outcome):
        return {'key': f'sample-app|{name}', 'host': name, 'app': 'sample-app', 'env': env, 'outcome': outcome,
                'steps': {},
                'execution_id': f'ex-{name}'}

    def test_gate_survives_and_can_be_approved(self):
        self.saved_run('awaiting_approval', [self.host('node2', 'prod', 'awaiting_approval')])
        r = appv2.restore()
        self.assertTrue(r['restored'])
        self.assertEqual(appv2.state()['status'], 'awaiting_approval')
        self.assertEqual(appv2.decide('node2', 'rejected')[0], 200)
        self.assertEqual(self.signals, [{'signal_data': {'decision': 'rejected'}}])

    def test_running_execution_is_followed_again(self):
        self.phase = 'done'
        self.saved_run('running', [self.host('node1', 'qa', 'running')])
        self.assertEqual(appv2.restore()['resumed'], ['sample-app|node1'])
        for _ in range(300):
            if appv2.state()['status'] == 'complete':
                break
            time.sleep(0.01)
        self.assertEqual(appv2.state()['hosts'][0]['outcome'], 'patched')
        self.assertIn('sample-app|org.apache.logging.log4j:log4j-core', json.loads(
            (Path(self.dir) / 'appv2-bom-updates.json').read_text()))

    def test_step_inside_the_console_is_reported_interrupted(self):
        self.saved_run('generating', [])
        appv2.restore()
        st = appv2.state()
        self.assertEqual(st['status'], 'failed')
        self.assertIn('restarted during generate', st['error'])

    def test_bom_write_backs_survive(self):
        (Path(self.dir) / 'appv2-bom-updates.json').write_text(json.dumps({'a|g:x': '1.rhlw-00001'}))
        appv2._BOM_UPDATES.clear()
        appv2.restore()
        self.assertEqual(appv2._BOM_UPDATES.get('a|g:x'), '1.rhlw-00001')

    def test_demo_mode_writes_nothing(self):
        appv2.configure(demo_mode=lambda: True)
        appv2._set(status='assessed')
        self.assertFalse((Path(self.dir) / 'appv2-run.json').exists())


class Subset(unittest.TestCase):
    def wait(self, statuses, timeout=5):
        end = time.time() + timeout
        while time.time() < end:
            if appv2.state().get('status') in statuses:
                return appv2.state()
            time.sleep(0.02)
        self.fail(f"stuck at {appv2.state().get('status')}")

    def test_only_selected_pairs_run(self):
        demo()
        appv2.start_assess('evt-log4j-core'); self.wait({'assessed'})
        appv2.start_generate(); self.wait({'generated'})
        self.assertEqual(appv2.start_dispatch([])[0], 400)                       # nothing selected
        self.assertEqual(appv2.start_dispatch(['orders-api|orders-qa-01.acme.internal', 'not|known'])[0], 200)
        st = self.wait({'complete'})
        by = {h['key']: h for h in st['hosts']}
        self.assertEqual(by['orders-api|orders-qa-01.acme.internal']['outcome'], 'patched')
        self.assertEqual(by['orders-service|orders-qa-01.acme.internal']['outcome'], 'skipped')
        self.assertFalse(by['orders-service|orders-qa-01.acme.internal']['execution_id'])   # never sent to AO
        self.assertEqual(st['summary']['skipped'], 4)
        # orders-api's only server was patched; orders-service was not touched, so its BOM stays.
        self.assertIn('orders-api|org.apache.logging.log4j:log4j-core', appv2._BOM_UPDATES)
        self.assertNotIn('orders-service|org.apache.logging.log4j:log4j-core', appv2._BOM_UPDATES)

    def test_reasoning_is_on_every_target(self):
        demo()
        appv2.start_assess('evt-log4j-core'); st = self.wait({'assessed'})
        self.assertTrue(all(t.get('reasoning') for t in st['impact']['targets']))
        self.assertIn('60s', next(t for t in st['impact']['targets']
                                  if t['host'] == 'orders-prod-02.acme.internal')['reasoning'])


class Reasoning(unittest.TestCase):
    T = [{'key': 'sample-app|node2', 'app': 'sample-app', 'host': 'node2'},
         {'key': 'orders-api|node1', 'app': 'orders-api', 'host': 'node1'}]

    def setUp(self):
        demo(APP_VECTOR_DB_ID='vs_apps')
        appv2.configure(demo_mode=lambda: False)

    def test_keeps_only_records_about_that_app_and_server(self):
        hits = {'sample-app': ['App: sample-app Server: node2\nLessons:\nAllow 60 seconds.',
                               'App: sample-app Server: node1\nLessons:\nQuick on QA.'],
                'orders-api': ['App: sample-app Server: node3\nLessons:\nStandby.']}
        appv2.configure(rag_search=lambda store, q: hits['sample-app' if 'sample-app' in q else 'orders-api'],
                        llm=lambda prompt: '{"1": "Give node2 a 60s health window."}')
        notes, source = appv2.reasoning(self.T)
        self.assertEqual(notes['sample-app|node2'], 'Give node2 a 60s health window.')
        self.assertEqual(notes['orders-api|node1'], 'No history found for this app on this server.')
        self.assertEqual(source, 'rag+llm')

    def test_falls_back_to_the_records_own_words(self):
        appv2.configure(rag_search=lambda store, q: ['App: sample-app Server: node2\nLessons:\nAllow 60 seconds.'],
                        llm=lambda prompt: 'not json at all')
        notes, _ = appv2.reasoning(self.T[:1])
        self.assertEqual(notes['sample-app|node2'], 'Allow 60 seconds.')

    def test_no_store_says_so(self):
        demo()
        appv2.configure(demo_mode=lambda: False)
        notes, source = appv2.reasoning(self.T)
        self.assertEqual(source, 'none')
        self.assertIn('APP_VECTOR_DB_ID', notes['sample-app|node2'])


class Catalog(unittest.TestCase):
    def test_demo_marks_builds_the_apps_need(self):
        demo()
        mine = appv2.catalog('mine')
        builds = {r['build']: r['affects'] for r in mine['rows']}
        self.assertEqual(builds['2.24.3.rhlw-00004'], ['billing-api', 'orders-api', 'orders-service'])
        self.assertEqual(builds['2.11.0.rhlw-00009'], ['billing-api', 'catalog-web'])
        everything = appv2.catalog('all')
        self.assertGreater(everything['total'], mine['total'])

    def test_live_mine_asks_per_library_version(self):
        demo()
        asked = []

        def lw(path, **params):
            asked.append((path, params.get('package_name'), params.get('package_version')))
            if params.get('package_name') == 'org.apache.logging.log4j:log4j-core':
                return {'data': [{'advisory_id': 'x', 'aliases': ['CVE-2026-1'], 'fixed_versions': ['2.24.3.rhlw-00004']}]}
            return {'data': []}

        appv2.configure(demo_mode=lambda: False, lightwell_get=lw,
                        env=lambda k, d='': {'BOM_DIR': str(Path(__file__).resolve().parents[1] / 'app-data' / 'bom'),
                                             'APPV2_STATE_DIR': tempfile.mkdtemp()}.get(k, d))
        out = appv2.catalog('mine')
        self.assertEqual([(r['build'], r['cves'], r['affects']) for r in out['rows']],
                         [('2.24.3.rhlw-00004', ['CVE-2026-1'], ['orders-api', 'sample-app'])])
        self.assertIn(('/advisories', 'commons-io:commons-io', '2.11.0'), asked)


class History(unittest.TestCase):
    def test_runs_newest_first_and_detail(self):
        demo()
        before = appv2.runs()
        self.assertEqual(len(before), 2)                                          # the staged past runs
        appv2.start_assess('evt-commons-io')
        for _ in range(200):
            if appv2.state().get('status') == 'assessed':
                break
            time.sleep(0.02)
        self.assertTrue(appv2.runs()[0]['current'])
        appv2.start_generate()
        for _ in range(200):
            if appv2.state().get('status') == 'generated':
                break
            time.sleep(0.02)
        appv2.start_dispatch(['catalog-web|catalog-qa-01.acme.internal'])
        for _ in range(300):
            if appv2.state().get('status') == 'complete':
                break
            time.sleep(0.02)
        runs = appv2.runs()
        self.assertEqual(len(runs), 3)
        self.assertFalse(runs[0]['current'])
        self.assertEqual(runs[0]['run_id'], appv2.state()['run_id'])
        self.assertEqual(appv2.run_detail(runs[0]['run_id'])['status'], 'complete')
        self.assertEqual(appv2.run_detail('past1')['event']['artifact'], 'commons-io')


if __name__ == '__main__':
    unittest.main()
