import sys
import unittest
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import preflight                                                           # noqa: E402

SCAN = {'id': 'abc', 'status': 'done', 'repos': [{'status': 'done', 'components': 13, 'summary': {
    'vulnerable_components': 4, 'lightwell': {'remediated': 2, 'predisclosure': 1, 'source': 'sample'}}}]}


def fake(mode='demo', repos=preflight.DEMO_REPOS, status=None, token=True, scan=SCAN, start=None, aap=None):
    def fetch(method, path, body=None):
        if path == '/healthz':
            return {'ok': True}
        if path == '/v1/mode':
            return {'ok': True, 'mode': mode, 'demo_repos': list(repos), 'github_token': token, 'pom_resolution': 'all', 'ranges': True}
        if path == '/v1/lightwell/status':
            return status or {'ok': True, 'detail': 'Authenticated. 4 repositories are visible to this service account.'}
        if path == '/v1/remediation/status':
            return aap or {'ok': True, 'detail': 'Controller reachable, token accepted, job template found.'}
        if path == '/v1/scans' and method == 'POST':
            return start or {'ok': True, 'id': 'abc'}
        if path == '/v1/scans/abc':
            return {'ok': True, 'scan': scan}
        raise AssertionError(path)
    return fetch


def levels(results):
    return [lv for lv, _ in results]


class PreflightTests(unittest.TestCase):
    def test_demo_all_good(self):
        r = preflight.check(fake())
        self.assertEqual(set(levels(r)), {preflight.OK})

    def test_demo_missing_recording_fails_and_names_it(self):
        r = preflight.check(fake(repos=['appsecco/dvja']))
        bad = [t for lv, t in r if lv == preflight.FAIL]
        self.assertEqual(len(bad), 1)
        self.assertIn('demojam/lightwell-coverage-demo', bad[0])
        self.assertNotIn('appsecco/dvja', bad[0])

    def test_server_down(self):
        def down(method, path, body=None):
            raise urllib.error.URLError('refused')
        r = preflight.check(down)
        self.assertEqual(levels(r), [preflight.FAIL])
        self.assertIn('start.sh', r[0][1])

    def test_live_bad_credentials_fail(self):
        r = preflight.check(fake(mode='live', status={'ok': False, 'detail': 'The service account was refused.'}))
        self.assertIn(preflight.FAIL, levels(r))
        self.assertTrue(any('refused' in t for _, t in r))

    def test_live_without_github_token_warns_only(self):
        r = preflight.check(fake(mode='live', token=False))
        self.assertIn(preflight.WARN, levels(r))
        self.assertNotIn(preflight.FAIL, levels(r))

    def test_live_aap_problem_warns_and_is_shown(self):
        r = preflight.check(fake(mode='live', aap={'ok': False, 'detail': 'the job template "T" does not exist'}))
        self.assertIn((preflight.WARN, 'Remediation (AAP): the job template "T" does not exist'), r)
        self.assertNotIn(preflight.FAIL, levels(r))

    def test_live_aap_ok(self):
        r = preflight.check(fake(mode='live'))
        self.assertIn((preflight.OK, 'Remediation (AAP): Controller reachable, token accepted, job template found.'), r)

    def test_scan_reports_counts(self):
        r = preflight.check(fake(), scan='appsecco/dvja')
        self.assertEqual(r[-1][0], preflight.OK)
        self.assertIn('13 components, 4 vulnerable, 3 with a Lightwell build', r[-1][1])

    def test_scan_failure_is_reported(self):
        bad = {'id': 'abc', 'status': 'done', 'repos': [{'status': 'error', 'error': 'not found'}]}
        r = preflight.check(fake(scan=bad), scan='x/y')
        self.assertEqual(r[-1][0], preflight.FAIL)
        self.assertIn('not found', r[-1][1])

    def test_scan_that_never_finishes_times_out(self):
        running = {'id': 'abc', 'status': 'running', 'repos': []}
        r = preflight.check(fake(scan=running), scan='x/y', wait=0.05, tick=lambda s: None)
        self.assertEqual(r[-1][0], preflight.FAIL)
        self.assertIn('did not finish', r[-1][1])

    def test_scan_not_started(self):
        r = preflight.check(fake(start={'ok': False, 'error': 'bad repo'}), scan='x')
        self.assertEqual(r[-1][0], preflight.FAIL)
        self.assertIn('bad repo', r[-1][1])


if __name__ == '__main__':
    unittest.main()
