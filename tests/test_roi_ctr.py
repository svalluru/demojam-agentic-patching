"""ROI for Containers: the image rebuild priced against the manual baseline (agentic-patching.py roi_ctr)."""
import unittest

from test_roi_v2 import load_console


def run(outcomes, status='complete', siblings=2):
    hosts = [{'key': f'production/{ns}/workflow-engine', 'namespace': ns, 'env': 'prod' if 'prod' in ns else 'lab',
              'image': 'reg:5000/agentic-patching/workflow-engine@sha256:aa', 'outcome': o} for ns, o in outcomes]
    return {'status': status, 'run_id': 'r1', 'started_at': '2026-11-24T23:30:00Z', 'finished_at': '2026-11-24T23:35:00Z',
            'fix': {'kind': 'lightwell', 'component': 'spring-webmvc', 'cves': ['CVE-1', 'CVE-2'],
                    'images': [{'name': 'reg:5000/agentic-patching/workflow-engine@sha256:aa'}]},
            'siblings': [{'component': f'sib{i}', 'cves': [f'CVE-S{i}']} for i in range(siblings)],
            'hosts': hosts}


class RoiCtr(unittest.TestCase):
    def setUp(self):
        self.c = load_console()
        self.b = self.c.roi_baseline()

    def test_nothing_dispatched_is_no_section(self):
        self.assertIsNone(self.c.roi_ctr({}, self.b))
        self.assertIsNone(self.c.roi_ctr(run([('nfvo-lab', 'pending')]), self.b))

    def test_a_full_run_counts_images_builds_and_deployments(self):
        r = self.c.roi_ctr(run([('nfvo-lab', 'patched'), ('nfvo-prod', 'patched')]), self.b)
        m = r['measured']
        self.assertEqual((m['images'], m['components'], m['deployments'], m['gated'], m['patched'], m['cves']), (1, 3, 2, 1, 2, 4))
        self.assertEqual(m['image'], 'workflow-engine')
        self.assertGreater(r['saved']['minutes'], 0)
        self.assertEqual(r['left']['minutes'], 0)
        self.assertIsNotNone(r['saved']['effort_x'])

    def test_an_unpatched_deployment_is_charged_back(self):
        full = self.c.roi_ctr(run([('nfvo-lab', 'patched'), ('nfvo-prod', 'patched')]), self.b)
        part = self.c.roi_ctr(run([('nfvo-lab', 'patched'), ('nfvo-prod', 'deferred')]), self.b)
        self.assertEqual(part['left']['minutes'], self.b['ctr_rollout'] + self.b['ctr_verify'])
        self.assertLess(part['saved']['minutes'], full['saved']['minutes'])

    def test_a_run_that_patched_nothing_claims_nothing(self):
        r = self.c.roi_ctr(run([('oss-lab', 'failed'), ('oss-prod', 'failed')]), self.b)
        self.assertLessEqual(r['saved']['minutes'], 0)
        self.assertIsNone(r['saved']['effort_x'])

    def test_the_report_has_a_containers_side(self):
        rep = self.c.roi_report({}, None, [], None, {}, run([('nfvo-lab', 'patched'), ('nfvo-prod', 'patched')]))
        self.assertTrue(rep['sides']['ctr'])
        self.assertEqual(rep['combined']['minutes'], rep['ctr']['saved']['minutes'])
        self.assertTrue(any(a['side'] == 'ctr' for a in rep['assumptions']))

    def test_sliders_move_it(self):
        st = run([('nfvo-lab', 'patched'), ('nfvo-prod', 'patched')])
        lo = self.c.roi_ctr(st, self.c.roi_baseline({'ROI_CTR_BUILD_MIN': 0}))
        hi = self.c.roi_ctr(st, self.c.roi_baseline({'ROI_CTR_BUILD_MIN': 120}))
        self.assertLess(lo['manual']['minutes'], hi['manual']['minutes'])


class RoiCtrState(unittest.TestCase):
    def setUp(self):
        load_console()
        import ctr
        self.ctr = ctr
        from test_ctr import demo
        demo()

    def test_the_newest_finished_run_when_none_is_open(self):
        self.ctr._HISTORY[:] = [{'run_id': 'old', 'hosts': [{'outcome': 'patched'}]},
                                {'run_id': 'new', 'hosts': [{'outcome': 'patched'}]}]
        st = self.ctr.roi_state()
        self.assertEqual((st['run_id'], st['roi_from_history']), ('new', True))

    def test_the_open_run_once_it_reached_a_deployment(self):
        self.ctr._HISTORY[:] = [{'run_id': 'old', 'hosts': [{'outcome': 'patched'}]}]
        self.ctr._set(status='running', run_id='cur', hosts=[{'outcome': 'running'}])
        self.assertEqual(self.ctr.roi_state()['run_id'], 'cur')


if __name__ == '__main__':
    unittest.main()
