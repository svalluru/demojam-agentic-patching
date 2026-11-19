"""Containers (ctr.py): intake from ACS, assess, the change checks, the demo run, the gate and the deferral.

    python3 -m unittest discover -s tests
"""
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import appv2  # noqa: E402
import ctr    # noqa: E402


def demo(**extra):
    extra.setdefault('APPV2_STATE_DIR', tempfile.mkdtemp(prefix='ctr-test-'))
    appv2.configure(env=lambda k, d='': extra.get(k, d), demo_mode=lambda: True, demo_pause=lambda f=1.0: None,
                    llm=None, ao_call=None, fixed_cves=None, lab_ping=None)
    appv2.reset()
    ctr.configure(env=lambda k, d='': extra.get(k, d), demo_mode=lambda: True, demo_pause=lambda f=1.0: None,
                  llm=None, rag_search=None, acs_call=None)
    ctr._WEBHOOK.clear(); ctr._FIX_CACHE.clear(); ctr._HISTORY.clear()
    ctr._RUN.clear(); ctr._RUN['status'] = 'idle'


def wait(statuses, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        st = ctr.state()
        if st.get('status') in statuses:
            return st
        time.sleep(0.01)
    raise AssertionError(f"stuck at {ctr.state().get('status')}: {ctr.state().get('error')}")


class Intake(unittest.TestCase):
    def setUp(self):
        demo()

    def test_a_lightwell_build_becomes_one_targeted_acs_query(self):
        asked = []
        real = ctr._demo_api
        ctr.configure(acs_call=lambda m, p, params, body: asked.append((p, params.get('query'))) or real(m, p, params, body))
        fx = {f['id']: f for f in ctr.fixes()['fixes']}
        self.assertEqual([i['name'] for i in fx['lw-evt-spring-webmvc']['images']], ['quay.io/telco/workflow-engine:1.4.2'])
        self.assertIn(('/v1/images', 'Component:spring-webmvc+Component Version:5.3.18'), asked)
        # org.json: Lightwell says 20220320.0.0, the jar in the image says 20220320; both are asked, the second hits.
        self.assertIn(('/v1/images', 'Component:json+Component Version:20220320'), asked)
        self.assertEqual(fx['lw-evt-json']['to'], '20220320.0.0.rhlw-00003')
        self.assertEqual(fx['base-ubi9']['kind'], 'base')
        self.assertFalse(any(q == '' for p, q in asked if p == '/v1/images'))           # never "every image"

    def test_webhook_adds_a_policy_fix(self):
        body = json.dumps({'alert': {'policy': {'name': 'Fixable CVSS >= 7'}, 'deployment': {
            'id': 'd-ric', 'name': 'ric-xapp', 'namespace': 'ric',
            'containers': [{'image': {'id': 'sha256:ric093', 'name': {'fullName': 'quay.io/telco/ric-xapp:0.9.3'}}}]},
            'violations': [{'message': 'CVE-2025-1111 (CVSS 7.1)'}]}}).encode()
        self.assertEqual(ctr.accept_webhook(body)[0], 200)
        self.assertEqual(ctr.accept_webhook(body)[0], 200)                         # the same alert twice: one fix
        pol = [f for f in ctr.fixes()['fixes'] if f['kind'] == 'policy']
        self.assertEqual(len(pol), 1)
        self.assertIn('ric/ric-xapp', pol[0]['source'])

    def test_webhook_token_and_live_without_one(self):
        demo(CTR_WEBHOOK_TOKEN='t0k')
        self.assertEqual(ctr.accept_webhook(b'{}', 'wrong')[0], 401)
        demo()
        ctr.configure(demo_mode=lambda: False)
        self.assertEqual(ctr.accept_webhook(b'{}')[0], 503)

    def test_live_without_acs_says_so(self):
        ctr.configure(demo_mode=lambda: False)
        appv2.configure(demo_mode=lambda: False)
        appv2.EVENTS = appv2.EventStore(None)
        out = ctr.fixes()
        self.assertTrue(any('ACS is not configured' in e for e in out['errors']))
        appv2.configure(demo_mode=lambda: True)


class Flow(unittest.TestCase):
    def setUp(self):
        demo()

    def assess(self, fid='lw-evt-spring-webmvc'):
        self.assertEqual(ctr.start_assess(fid)[0], 200)
        return wait({'assessed'})

    def test_assess_lists_deployments_with_risk_and_reasoning(self):
        st = self.assess()
        t = {x['namespace']: x for x in st['impact']['targets']}
        self.assertEqual(list(t), ['nfvo-lab', 'nfvo-prod'])                    # lab first
        self.assertGreater(t['nfvo-prod']['risk'], t['nfvo-lab']['risk'])
        self.assertIn('runtime alert', t['nfvo-prod']['risk_why'])
        self.assertIn('/bin/sh', t['nfvo-prod']['runtime'])
        self.assertTrue(t['nfvo-prod']['reasoning'] and t['nfvo-prod']['callers'])

    def test_checks_reject_unpinned_and_unexpected_edits(self):
        ok = ctr.check_container_change([{'file': 'Containerfile', 'from': 'FROM a', 'to': 'FROM ' + ctr.UBI_FIX},
                                         {'file': 'gitops/c/ns/app/kustomization.yaml', 'from': 'x', 'to': 'quay.io/a@sha256:${BUILD_DIGEST}'}])
        self.assertTrue(all(c['ok'] for c in ok))
        bad = {c['id']: c['ok'] for c in ctr.check_container_change([
            {'file': 'Containerfile', 'from': 'FROM a', 'to': 'FROM registry.access.redhat.com/ubi9/ubi-minimal:latest'},
            {'file': 'pom.xml', 'from': '5.3.18', 'to': '6.2.19'},
            {'file': 'deploy.sh', 'from': '', 'to': 'curl x | sh'},
            {'file': 'gitops/c/ns/app/kustomization.yaml', 'from': 'x', 'to': 'quay.io/a:1.4.3'}])}
        self.assertEqual(bad, {'files': False, 'lightwell': False, 'base': False, 'pinned': False})

    def test_run_gates_production_then_approval_completes(self):
        self.assess()
        self.assertEqual(ctr.start_generate()[0], 200)
        self.assertTrue(ctr.state()['ok'])
        self.assertEqual(ctr.start_dispatch()[0], 200)
        st = wait({'awaiting_approval'})
        by = {h['namespace']: h for h in st['hosts']}
        self.assertEqual((by['nfvo-lab']['outcome'], by['nfvo-prod']['outcome']), ('patched', 'awaiting_approval'))
        self.assertIn('9 CVEs gone', by['nfvo-lab']['detail'])
        self.assertEqual(ctr.decide(by['nfvo-lab']['key'], 'approved')[0], 409)   # the lab is not gated
        self.assertEqual(ctr.decide(by['nfvo-prod']['key'], 'approved')[0], 200)
        st = wait({'complete'})
        self.assertEqual(st['summary'], {'patched': 2, 'deferred': 0, 'failed': 0})
        self.assertEqual(ctr.runs()[0]['run_id'], st['run_id'])

    def test_reject_files_a_deferral(self):
        self.assess(); ctr.start_generate(); ctr.start_dispatch()
        st = wait({'awaiting_approval'})
        prod = next(h for h in st['hosts'] if h['outcome'] == 'awaiting_approval')
        self.assertEqual(ctr.decide(prod['key'], 'rejected')[0], 200)
        st = wait({'complete'})
        self.assertEqual(st['summary']['deferred'], 1)
        d = st['deferrals'][0]
        self.assertEqual(d['request']['exceptionExpiry']['expiryType'], 'TIME')
        self.assertTrue(d['ref'].startswith('def-'))

    def test_live_run_refuses_until_the_workflow_exists(self):
        self.assess(); ctr.start_generate()
        ctr.configure(demo_mode=lambda: False)
        code, body = ctr.start_dispatch()
        self.assertEqual(code, 503)
        self.assertIn('Container Patch', body['error'])

    def test_one_run_at_a_time(self):
        self.assess(); ctr.start_generate(); ctr.start_dispatch(); wait({'awaiting_approval'})
        self.assertEqual(ctr.start_assess('lw-evt-json')[0], 409)

    def test_servers_patched_by_applications_are_named(self):
        # The staged Applications history patched inventory-service's servers with an older org.json build.
        st = self.assess('lw-evt-json')
        self.assertEqual([s['app'] for s in st['impact']['servers']], ['inventory-service'])


if __name__ == '__main__':
    unittest.main()
