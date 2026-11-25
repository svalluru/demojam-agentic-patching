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
                                         {'file': 'apps/c/ns/app/kustomization.yaml', 'from': 'x', 'to': 'quay.io/a@sha256:${BUILD_DIGEST}'}])
        self.assertTrue(all(c['ok'] for c in ok))
        bad = {c['id']: c['ok'] for c in ctr.check_container_change([
            {'file': 'Containerfile', 'from': 'FROM a', 'to': 'FROM registry.access.redhat.com/ubi9/ubi-minimal:latest'},
            {'file': 'pom.xml', 'from': '5.3.18', 'to': '6.2.19'},
            {'file': 'deploy.sh', 'from': '', 'to': 'curl x | sh'},
            {'file': 'apps/c/ns/app/kustomization.yaml', 'from': 'x', 'to': 'quay.io/a:1.4.3'}])}
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
        self.assertEqual({k: v for k, v in st['summary'].items() if v}, {'patched': 2})
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
        self.assertIn('Automation Orchestrator is not configured', body['error'])

    def test_one_run_at_a_time(self):
        self.assess(); ctr.start_generate(); ctr.start_dispatch(); wait({'awaiting_approval'})
        self.assertEqual(ctr.start_assess('lw-evt-json')[0], 409)

    def test_servers_patched_by_applications_are_named(self):
        # The staged Applications history patched inventory-service's servers with an older org.json build.
        st = self.assess('lw-evt-json')
        self.assertEqual([s['app'] for s in st['impact']['servers']], ['inventory-service'])


class LiveRun(unittest.TestCase):
    """The live run against a fake AO that walks each execution through the Container Patch nodes."""

    def setUp(self):
        demo(CTR_POLL_SECONDS='0')
        self.signals, self.created = [], []
        self.phase = {}                         # execution id -> 'gate' | 'done'
        self.plan = {}                          # execution id -> 'patched' | 'rolled_back' | 'build_failed'

        def ao(path, method='GET', body=None):
            if path == '/api/v1/workflows':
                return {'resources': [{'id': 'wf-ctr', 'name': 'Container Patch'}]}
            if path == '/api/v1/executions' and method == 'POST':
                eid = f"ex-{body['input_data']['namespace']}"
                self.created.append(body)
                self.phase[eid] = 'gate' if body['input_data']['group'] == 'prod_review' else 'done'
                self.plan.setdefault(eid, 'patched')
                return {'id': eid}
            if path.endswith('/signal'):
                eid = path.split('/')[4]
                self.signals.append((eid, body))
                self.phase[eid] = 'done' if body['signal_data']['decision'] == 'approved' else 'rejected'
                return {}
            eid = path.split('/')[4]
            ph, plan, prod = self.phase.get(eid), self.plan.get(eid), eid.endswith('prod')
            sfx = '_prod' if prod else ''
            def a(node, status='completed', art=None):
                return {'temporal_activity_id': node, 'status': status, 'output_data': {'artifacts': art or {}}}
            acts = [a('commit', art={'commit_sha': 'abc'}),
                    a('build_scan', art={'build_outcome': 'failed' if plan == 'build_failed' else 'passed',
                                         'image_digest': 'sha256:' + 'b' * 64, 'scan_summary': 'roxctl image check passed',
                                         'failed_reason': 'roxctl: 1 CVE not fixed by Lightwell' if plan == 'build_failed' else ''})]
            if plan == 'build_failed':
                acts.append(a('notify_build_failed'))
            elif prod and ph == 'gate':
                acts.append(a('approval_prod', 'waiting'))
            elif prod and ph == 'rejected':
                acts.append(a('approval_prod'))
            else:
                if prod:
                    acts.append(a('approval_prod'))
                acts.append(a('deploy' + sfx, art={'previous_digest': 'sha256:' + 'a' * 64}))
                if plan == 'rolled_back':
                    acts += [a('health' + sfx, art={'outcome': 'failed', 'failed_step': 'Wait for every replica', 'failed_reason': 'timed out'}),
                             a('rollback' + sfx, art={'rolled_back': True, 'restored': 'nfvo-lab/workflow-engine on sha256:aaaa'}),
                             a('notify_rolled_back' + sfx)]
                else:
                    acts += [a('health' + sfx, art={'outcome': 'patched', 'health': '{"status":"UP"}'}),
                             a('verify' + sfx, art={'verified': True, 'detail': 'ACS: runs the digest with spring-webmvc 5.3.18.rhlw-00010'}),
                             a('notify_patched' + sfx)]
            if path.endswith('/activities'):
                return {'resources': acts}
            running = prod and ph == 'gate' and plan != 'build_failed'     # a failed build ends the execution
            return {'status': 'running' if running else 'completed'}
        ctr.configure(ao_call=ao)

    def tearDown(self):
        ctr.configure(demo_mode=lambda: True, ao_call=None)

    def prepared(self):
        self.assertEqual(ctr.start_assess('lw-evt-spring-webmvc')[0], 200)
        wait({'assessed'})
        self.assertEqual(ctr.start_generate()[0], 200)
        ctr.configure(demo_mode=lambda: False)            # the run goes to AO; intake was answered from fixtures

    def test_a_long_wait_at_the_gate_is_not_a_timeout(self):
        base = ctr.H.env
        ctr.configure(env=lambda k, d='': '1' if k == 'AO_POLL_TIMEOUT' else base(k, d))
        self.prepared()
        self.assertEqual(ctr.start_dispatch()[0], 200)
        wait({'awaiting_approval'})
        time.sleep(2.5)                                         # well past the follow budget
        prod = next(h for h in ctr.state()['hosts'] if h['namespace'] == 'nfvo-prod')
        self.assertEqual(prod['outcome'], 'awaiting_approval')
        self.assertEqual(ctr.decide(prod['key'], 'approved')[0], 200)
        self.assertEqual(wait({'complete'})['summary']['patched'], 2)

    def test_lab_patches_and_prod_waits_then_approval_completes(self):
        self.prepared()
        self.assertEqual(ctr.start_dispatch()[0], 200)
        st = wait({'awaiting_approval'})
        by = {h['namespace']: h for h in st['hosts']}
        self.assertEqual(by['nfvo-lab']['outcome'], 'patched')
        self.assertIn('rhlw-00010', by['nfvo-lab']['detail'])
        self.assertEqual(by['nfvo-lab']['evidence']['image_digest'], 'sha256:' + 'b' * 64)
        self.assertEqual(by['nfvo-prod']['outcome'], 'awaiting_approval')
        inp = {c['input_data']['namespace']: c['input_data'] for c in self.created}
        self.assertEqual((inp['nfvo-lab']['group'], inp['nfvo-prod']['group']), ('lab_auto', 'prod_review'))
        self.assertEqual(inp['nfvo-prod']['gitops_path'], 'apps/cluster-x8v2s/nfvo-prod/workflow-engine/kustomization.yaml')
        self.assertEqual(inp['nfvo-lab']['port'], '8090')
        self.assertIn('CVE-2023-20860', inp['nfvo-lab']['lightwell_fixed'])
        # Every Lightwell build in the rebuild goes to verify, with its group (ACS names Lightwell jars group:artifact).
        import json as _json
        self.assertEqual(_json.loads(inp['nfvo-lab']['fixes_json'])[0],
                         {'group': 'org.springframework', 'component': 'spring-webmvc', 'version': '5.3.18.rhlw-00010'})
        self.assertEqual(ctr.decide(by['nfvo-prod']['key'], 'approved')[0], 200)
        self.assertEqual(self.signals, [('ex-nfvo-prod', {'signal_data': {'decision': 'approved'}})])
        st = wait({'complete'})
        self.assertEqual(st['summary']['patched'], 2)

    def test_unhealthy_rollout_is_rolled_back(self):
        self.plan['ex-nfvo-lab'] = 'rolled_back'
        self.prepared()
        ctr.start_dispatch()
        st = wait({'awaiting_approval'})
        lab = next(h for h in st['hosts'] if h['namespace'] == 'nfvo-lab')
        self.assertEqual(lab['outcome'], 'rolled_back')
        self.assertIn('timed out', lab['detail'])
        self.assertEqual(lab['steps']['rollback'], 'done')

    def test_a_failed_build_deploys_nothing(self):
        self.plan['ex-nfvo-lab'] = self.plan['ex-nfvo-prod'] = 'build_failed'
        self.prepared()
        ctr.start_dispatch()
        st = wait({'complete'})
        self.assertTrue(all(h['outcome'] == 'failed' and 'nothing deployed' in h['detail'] for h in st['hosts']))

    def test_reject_signals_ao_and_files_a_deferral(self):
        self.prepared()
        ctr.start_dispatch()
        st = wait({'awaiting_approval'})
        prod = next(h for h in st['hosts'] if h['namespace'] == 'nfvo-prod')
        ctr.configure(acs_call=lambda m, p, params, body: {'exception': {'id': 'def-1'}})
        self.assertEqual(ctr.decide(prod['key'], 'rejected')[0], 200)
        st = wait({'complete'})
        self.assertEqual(next(h for h in st['hosts'] if h['namespace'] == 'nfvo-prod')['outcome'], 'deferred')
        self.assertEqual(self.signals[-1][1], {'signal_data': {'decision': 'rejected'}})

    def test_no_workflow_in_ao_says_how_to_import_it(self):
        self.prepared()
        ctr._WF.clear()
        ctr.configure(ao_call=lambda path, method='GET', body=None: {'resources': []})
        code, body = ctr.start_dispatch()
        self.assertEqual(code, 503)
        self.assertIn('create-ao-workflow.sh', body['error'])


class AoListsEveryNode(unittest.TestCase):
    """AO's activities list has every node from the start: pending (not reached) and skipped (branch not taken).
    Copied from the lab's first live run, where the follower read them as having run."""

    def test_pending_and_skipped_nodes_do_not_count(self):
        demo()
        def a(node, status, art=None):
            return {'temporal_activity_id': node, 'status': status, 'output_data': {'artifacts': art or {}}}
        lab = [a('notify_rolled_back_prod', 'skipped'), a('deploy_prod', 'skipped'), a('approval_prod', 'skipped'),
               a('notify_build_failed', 'skipped'), a('rollback', 'skipped'),
               a('commit', 'completed'), a('build_scan', 'completed', {'build_outcome': 'passed', 'image_digest': 'sha256:' + 'c' * 64}),
               a('deploy', 'completed'), a('health', 'completed', {'outcome': 'patched'}),
               a('verify', 'completed', {'verified': 'True', 'detail': 'ACS: runs with 5.3.18.rhlw-00010'}), a('notify_patched', 'completed')]
        prod = [a('deploy_prod', 'pending'), a('verify_prod', 'pending'), a('notify_build_failed', 'skipped'),
                a('deploy', 'skipped'), a('approval_prod', 'waiting'), a('commit', 'completed'),
                a('build_scan', 'completed', {'build_outcome': 'passed', 'image_digest': 'sha256:' + 'c' * 64})]
        runs = {'ex-lab': ('completed', lab), 'ex-prod': ('paused', prod)}
        ctr.configure(ao_call=lambda path, method='GET', body=None:
                      {'resources': runs[path.split('/')[4]][1]} if path.endswith('/activities') else {'status': runs[path.split('/')[4]][0]})
        with ctr._LOCK:
            ctr._RUN.update(status='running', hosts=[{'key': 'lab', 'execution_id': 'ex-lab', 'outcome': 'running', 'steps': {}},
                                                     {'key': 'prod', 'execution_id': 'ex-prod', 'outcome': 'running', 'steps': {}}])
        self.assertTrue(ctr._read_execution('lab'))
        self.assertFalse(ctr._read_execution('prod'))
        by = {h['key']: h for h in ctr.state()['hosts']}
        self.assertEqual(by['lab']['outcome'], 'patched')
        self.assertNotIn('rollback', by['lab']['steps'])
        self.assertEqual(by['prod']['outcome'], 'awaiting_approval')
        self.assertNotIn('deploy', by['prod']['steps'])
        ctr.configure(ao_call=None)


class StaleAoRecord(unittest.TestCase):
    def test_an_approved_gate_ao_still_shows_is_settled_from_aap(self):
        # Seen on the lab: approved, the prod steps ran in AAP, but AO's record stayed "paused" at the gate.
        demo()
        ctr.configure(ao_call=lambda path, method='GET', body=None: {'resources': [
            {'temporal_activity_id': 'approval_prod', 'status': 'waiting'}]} if path.endswith('/activities') else {'status': 'paused'})
        jobs = {'CTR - Notify': [{'status': 'successful', 'extra_vars': json.dumps({'run_id': 'r1', 'namespace': 'nfvo-prod', 'outcome': 'patched'})}],
                'CTR - Verify (ACS)': [{'status': 'successful', 'extra_vars': json.dumps({'run_id': 'r0', 'namespace': 'nfvo-prod'}),
                                        'artifacts': {'verified': True, 'detail': 'an earlier run'}},
                                       {'status': 'successful', 'extra_vars': json.dumps({'run_id': 'r1', 'namespace': 'nfvo-prod'}),
                                        'artifacts': {'verified': True, 'detail': 'ACS: runs with 5.3.18.rhlw-00010'}}]}
        ctr.configure(aap_call=lambda path, method='GET', body=None:
                      {'results': next(v for k, v in jobs.items() if k.replace(' ', '%20').replace('(', '%28').replace(')', '%29') in path)})
        with ctr._LOCK:
            ctr._RUN.update(status='awaiting_approval', run_id='r1', hosts=[{'key': 'p', 'namespace': 'nfvo-prod', 'execution_id': 'ex',
                                                                             'outcome': 'running', 'steps': {}, 'approved_at': time.time() - 120}])
        self.assertTrue(ctr._read_execution('p'))
        h = ctr.state()['hosts'][0]
        self.assertEqual((h['outcome'], h['detail']), ('patched', 'ACS: runs with 5.3.18.rhlw-00010'))
        ctr.configure(ao_call=None, aap_call=None)


class ResetDemo(unittest.TestCase):
    def setUp(self):
        demo(CTR_POLL_SECONDS='0')
        ctr._RESET.clear()

    def tearDown(self):
        ctr.configure(demo_mode=lambda: True, aap_call=None)
        ctr._RESET.clear()

    def test_demo_mode_clears_the_run(self):
        ctr.start_assess('lw-evt-spring-webmvc'); wait({'assessed'})
        code, body = ctr.reset_demo()
        self.assertEqual((code, ctr.state()['status'], body['demo_reset']['status']), (200, 'idle', 'done'))

    def aap(self, final='successful', artifacts=None):
        self.calls = []
        def call(path, method='GET', body=None):
            self.calls.append((method, path))
            if path.startswith('/job_templates/?name='):
                return {'results': [{'id': 77, 'name': 'CTR - Reset Demo'}]}
            if path == '/job_templates/77/launch/':
                return {'id': 501}
            if path == '/jobs/501/':
                return {'status': final, 'artifacts': artifacts if artifacts is not None else
                        {'reset_ok': True, 'reset': [{'app': 'workflow-engine', 'namespace': 'nfvo-lab', 'ready': True}]}}
            raise AssertionError(path)
        ctr.configure(demo_mode=lambda: False, aap_call=call)

    def wait_reset(self):
        for _ in range(200):
            if ctr._RESET.get('status') != 'running':
                return dict(ctr._RESET)
            time.sleep(0.01)
        raise AssertionError('reset still running')

    def test_live_launches_the_aap_job_and_clears_the_run(self):
        with ctr._LOCK:
            ctr._RUN.update(status='complete', run_id='old')
        ctr._FIX_CACHE['v'] = (time.time(), {'fixes': []})
        self.aap()
        code, body = ctr.reset_demo()
        self.assertEqual((code, body['demo_reset']['job_id']), (200, 501))
        self.assertIn(('POST', '/job_templates/77/launch/'), self.calls)
        r = self.wait_reset()
        self.assertEqual((r['status'], r['reset'][0]['namespace']), ('done', 'nfvo-lab'))
        self.assertEqual(ctr.state()['status'], 'idle')
        self.assertEqual(ctr._FIX_CACHE, {})                      # the inbox re-reads ACS

    def test_a_failed_job_is_reported(self):
        self.aap(final='failed', artifacts={})
        ctr.reset_demo()
        r = self.wait_reset()
        self.assertEqual(r['status'], 'failed')
        self.assertIn('501', r['note'])

    def test_refused_while_a_run_is_at_the_gate(self):
        with ctr._LOCK:
            ctr._RUN.update(status='awaiting_approval')
        self.aap()
        self.assertEqual(ctr.reset_demo()[0], 409)


class Siblings(unittest.TestCase):
    def test_every_lightwell_build_for_the_image_rides_one_rebuild(self):
        demo()
        ctr.start_assess('lw-evt-json'); wait({'assessed'})
        ctr.start_generate()
        st = ctr.state()
        poms = {e['what']: (e['from'], e['to']) for e in st['change'] if e['file'] == 'pom.xml'}
        # org.json's pom.xml says 20220320 (Lightwell: 20220320.0.0); json-path rides the same rebuild.
        self.assertEqual(poms['json version'], ('20220320', '20220320.0.0.rhlw-00003'))
        self.assertEqual(poms['json-path version'], ('2.8.0', '2.8.0.rhlw-00001'))
        self.assertIn('CVE-2023-51074', st['lightwell_fixed'])
        self.assertTrue(st['ok'])

    def test_assess_already_names_the_other_builds(self):
        demo()
        ctr.start_assess('lw-evt-json'); wait({'assessed'})
        sib = {x['component']: x for x in ctr.state()['siblings']}
        self.assertIn('json-path', sib)
        self.assertEqual(sib['json-path']['to'], '2.8.0.rhlw-00001')
        self.assertIn('CVE-2023-51074', sib['json-path']['cves'])


class ReviewFixes(unittest.TestCase):
    """The corner cases a review found: decisions, resets, restores, scopes, policy fixes."""

    def setUp(self):
        demo(CTR_POLL_SECONDS='0')

    def tearDown(self):
        ctr.configure(demo_mode=lambda: True, ao_call=None, aap_call=None)
        ctr._RESET.clear()

    def gate(self, lab_outcome='patched', decided=''):
        with ctr._LOCK:
            ctr._RUN.clear()
            ctr._RUN.update(status='awaiting_approval', run_id='r1', fix={'kind': 'lightwell', 'cves': ['CVE-1']}, stages={},
                            hosts=[{'key': 'lab', 'env': 'lab', 'image': 'r/x@sha256:1', 'outcome': lab_outcome, 'steps': {}},
                                   {'key': 'prod', 'env': 'prod', 'image': 'r/x@sha256:1', 'outcome': 'awaiting_approval',
                                    'steps': {}, 'execution_id': 'ex', 'decided': decided}])

    def test_a_decision_is_taken_once(self):
        self.gate()
        self.assertEqual(ctr.decide('prod', 'rejected')[0], 200)
        self.assertEqual(ctr.decide('prod', 'rejected')[0], 409)
        self.assertEqual(len(ctr.state().get('deferrals') or []), 1)

    def test_a_rejection_survives_the_finished_execution(self):
        ctr.configure(demo_mode=lambda: False, aap_call=None, ao_call=lambda path, method='GET', body=None: {'resources': [
            {'temporal_activity_id': 'approval_prod', 'status': 'completed'}]} if path.endswith('/activities') else {'status': 'completed'})
        self.gate(decided='rejected')
        ctr._host('prod', outcome='deferred', detail='deferred in ACS until …')
        self.assertTrue(ctr._read_execution('prod'))
        self.assertEqual(ctr.state()['hosts'][1]['outcome'], 'deferred')

    def test_a_deferral_acs_refuses_is_not_called_deferred(self):
        from ctr import AcsError
        def refuse(method, path, params=None, body=None):
            if method == 'POST':
                self.sent = body
                raise AcsError('HTTP 400 invalid Timestamp')
            return {}
        self.gate()
        ctr.configure(acs_call=refuse)
        self.assertEqual(ctr.decide('prod', 'rejected')[0], 200)
        h = ctr.state()['hosts'][1]
        self.assertEqual(h['outcome'], 'rejected')
        self.assertIn('not filed', h['detail'])
        self.assertRegex(self.sent['exceptionExpiry']['expiresOn'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')

    def test_approve_waits_for_the_lab_of_the_same_image(self):
        self.gate(lab_outcome='running')
        self.assertEqual(ctr.decide('prod', 'approved')[0], 409)
        self.gate(lab_outcome='rolled_back')
        self.assertEqual(ctr.decide('prod', 'approved')[0], 409)
        self.assertEqual(ctr.decide('prod', 'rejected')[0], 200)      # reject stays possible

    def test_a_decided_gate_that_ao_still_shows_never_comes_back(self):
        ctr.configure(demo_mode=lambda: False, aap_call=None,
                      ao_call=lambda path, method='GET', body=None: {'resources': [
                          {'temporal_activity_id': 'approval_prod', 'status': 'waiting'}]} if path.endswith('/activities') else {'status': 'paused'})
        self.gate(decided='approved')
        self.assertFalse(ctr._read_execution('prod'))
        self.assertEqual(ctr.state()['hosts'][1]['outcome'], 'running')
        self.gate(decided='rejected')
        ctr._host('prod', outcome='deferred')
        self.assertTrue(ctr._read_execution('prod'))                   # settled: the follower stops
        self.assertEqual(ctr.state()['hosts'][1]['outcome'], 'deferred')

    def test_reset_refuses_an_open_run(self):
        self.gate()
        self.assertEqual(ctr.reset()[0], 409)
        ctr._set(status='assessing')
        self.assertEqual(ctr.reset()[0], 409)

    def test_no_assessment_while_the_demo_reset_runs(self):
        ctr._RESET.update(status='running')
        self.assertEqual(ctr.start_assess('lw-evt-spring-webmvc')[0], 409)

    def test_a_late_assessment_does_not_land_in_another_run(self):
        ctr.start_assess('lw-evt-spring-webmvc'); wait({'assessed'})
        fix = ctr.state()['fix']
        ctr.reset()
        ctr._assess(fix, 'gone')
        self.assertEqual(ctr.state()['status'], 'idle')

    def test_an_unexpected_error_ends_the_assessment(self):
        def boom(*a, **k):
            raise ValueError('not JSON')
        ctr.start_assess('lw-evt-spring-webmvc'); wait({'assessed'})
        fix, rid = ctr.state()['fix'], ctr.state()['run_id']
        ctr.configure(acs_call=boom)
        ctr._assess(fix, rid)
        self.assertEqual(ctr.state()['status'], 'failed')
        self.assertIn('not JSON', ctr.state()['error'])

    def test_dispatch_is_claimed_once(self):
        ctr.start_assess('lw-evt-spring-webmvc'); wait({'assessed'})
        ctr.start_generate()
        self.assertEqual(ctr.start_dispatch()[0], 200)
        self.assertEqual(ctr.start_dispatch()[0], 409)

    def test_a_policy_violation_is_not_prepared_as_a_rebuild(self):
        with ctr._LOCK:
            ctr._RUN.update(status='assessed', fix={'kind': 'policy', 'images': []}, impact={'targets': [{'key': 'k'}]})
        code, body = ctr.start_generate()
        self.assertEqual(code, 400)
        self.assertIn('policy', body['error'])

    def test_verify_gets_only_lightwell_builds(self):
        st = {'run_id': 'r', 'fix': {'kind': 'base', 'to': 'registry.access.redhat.com/ubi9@sha256:' + 'a' * 64, 'cves': ['CVE-1']},
              'siblings': [], 'change': []}
        h = {'app': 'x', 'name': 'x', 'namespace': 'n', 'cluster': 'c', 'env': 'lab'}
        inp = ctr._inputs(st, h)
        self.assertEqual((json.loads(inp['fixes_json']), inp['fix_kind'], inp['health_path']), ([], 'base', '/health'))

    def test_the_gitops_image_keeps_the_registry_port(self):
        t = {'image': 'image-registry.openshift-image-registry.svc:5000/agentic-patching/workflow-engine@sha256:' + 'a' * 64,
             'cluster': 'c', 'namespace': 'n', 'app': 'workflow-engine', 'name': 'workflow-engine'}
        e = ctr.build_change({'kind': 'lightwell', 'component': 'x', 'from': '1', 'to': '1.rhlw-00001'}, [t])[-1]
        self.assertEqual(e['to'], 'image-registry.openshift-image-registry.svc:5000/agentic-patching/workflow-engine@sha256:${BUILD_DIGEST}')
        t['image'] = 'quay.io/telco/app:2.4'
        self.assertEqual(ctr.build_change({'kind': 'lightwell', 'component': 'x', 'from': '1', 'to': '1.rhlw-00001'}, [t])[-1]['to'],
                         'quay.io/telco/app@sha256:${BUILD_DIGEST}')

    def test_deferral_scope_for_digest_and_tag_images(self):
        self.assertEqual(ctr._image_scope('image-registry.openshift-image-registry.svc:5000/agentic-patching/workflow-engine@sha256:' + 'a' * 64),
                         {'registry': 'image-registry.openshift-image-registry.svc:5000', 'remote': 'agentic-patching/workflow-engine', 'tag': '.*'})
        self.assertEqual(ctr._image_scope('quay.io/telco/inventory-service:2.4'),
                         {'registry': 'quay.io', 'remote': 'telco/inventory-service', 'tag': '2.4'})

    def test_restore_closes_what_cannot_be_followed(self):
        d = tempfile.mkdtemp(prefix='ctr-restore-')
        demo(APPV2_STATE_DIR=d)
        Path(d, 'ctr-run.json').write_text(json.dumps({'status': 'running', 'run_id': 'r9', 'fix': {}, 'stages': {}, 'hosts': [
            {'key': 'a', 'outcome': 'patched', 'steps': {}, 'execution_id': 'e1'},
            {'key': 'b', 'outcome': 'pending', 'steps': {}}]}))
        ctr.configure(demo_mode=lambda: False)
        ctr.restore()
        st = ctr.state()
        self.assertEqual(st['status'], 'complete')
        self.assertEqual(st['hosts'][1]['outcome'], 'failed')

    def test_patch_runs_lists_each_run_once_newest_first(self):
        ctr._HISTORY[:] = [{'run_id': 'a', 'summary': {'failed': 2}}, {'run_id': 'b'}, {'run_id': 'a', 'summary': {'patched': 2}}]
        self.assertEqual([(r['run_id'], r.get('summary')) for r in ctr.runs()], [('a', {'patched': 2}), ('b', None)])

    def test_the_run_file_is_replaced_whole(self):
        d = tempfile.mkdtemp(prefix='ctr-persist-')
        demo(APPV2_STATE_DIR=d)
        ctr.configure(demo_mode=lambda: False)
        ctr._set(status='running', run_id='r2')
        ctr._persist()
        self.assertEqual(json.loads(Path(d, 'ctr-run.json').read_text())['run_id'], 'r2')
        self.assertFalse(Path(d, 'ctr-run.json.tmp').exists())


if __name__ == '__main__':
    unittest.main()
