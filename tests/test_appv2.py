"""Applications v2: the parts that decide what reaches a server.

    python3 -m unittest discover -s tests
"""
import hashlib
import hmac
import json
import sys
import time
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import appv2  # noqa: E402


def demo(**extra):
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
        self.assertEqual(imp['apps'], ['billing-api', 'orders-service'])
        self.assertEqual(len(imp['targets']), 4)
        self.assertEqual(imp['targets'][0]['env'], 'qa')                  # QA first
        self.assertEqual([o['app'] for o in imp['other']], ['catalog-web'])  # 2.25.1, left alone

    def test_write_back_removes_app_from_next_impact(self):
        ev = next(e for e in appv2.DEMO_EVENTS if e['artifact'] == 'log4j-core')
        appv2._BOM_UPDATES['billing-api|org.apache.logging.log4j:log4j-core'] = ev['version']
        imp = appv2.impact(ev, appv2.load_bom())
        self.assertEqual(imp['apps'], ['orders-service'])
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
        gated = [h['host'] for h in st['hosts'] if h['outcome'] == 'awaiting_approval']
        self.assertEqual(len(gated), 3)
        self.assertEqual(appv2.decide('orders-qa-01.acme.internal', 'approved')[0], 409)   # QA is not gated
        for h in gated:
            self.assertEqual(appv2.decide(h, 'approved')[0], 200)
        st = self.wait({'complete'})
        self.assertEqual(st['summary'], {'patched': 3, 'rolled_back': 1, 'rejected': 0, 'failed': 0})
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
            target = {'app': 'billing-api', 'host': 'billing-prod-01', 'env': 'prod', 'installed': '2.24.3',
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


if __name__ == '__main__':
    unittest.main()
