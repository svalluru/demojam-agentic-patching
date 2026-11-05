"""Applications v2: the parts that decide what reaches a server.

    python3 -m unittest discover -s tests
"""
import hashlib
import hmac
import json
import sys
import time
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


if __name__ == '__main__':
    unittest.main()
