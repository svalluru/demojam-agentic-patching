import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import github, repo, scan                                         # noqa: E402
from scanner.http import UpstreamError                                     # noqa: E402


class ParseRepoTests(unittest.TestCase):
    def test_accepted_forms(self):
        for spec in ('https://github.com/acme/app', 'github.com/acme/app', 'acme/app', 'https://github.com/acme/app.git',
                     'https://github.com/acme/app/', 'HTTP://www.github.com/acme/app?x=1'):
            r = repo.parse_repo(spec)
            self.assertEqual((r.owner, r.repo, r.ref, r.subpath), ('acme', 'app', '', ''), spec)

    def test_tree_url(self):
        r = repo.parse_repo('https://github.com/acme/app/tree/release/services/api')
        self.assertEqual((r.ref, r.subpath), ('release', 'services/api'))

    def test_rejected(self):
        for spec in ('', 'acme', 'https://bitbucket.org/acme/app', 'https://github.com/acme/app/issues', 'a/b/../c',
                     'https://github.com/ac me/app', 'https://github.com/acme/app/tree/../x', 'x' * 400):
            with self.assertRaises(ValueError, msg=spec):
                repo.parse_repo(spec)


class FakeGitHub:
    """Stands in for http.request, keyed by URL fragment."""

    def __init__(self, tree, files, meta=None, fail=None):
        self.tree, self.files, self.meta, self.fail, self.urls = tree, files, meta or {'default_branch': 'main', 'private': False}, fail, []

    def __call__(self, service, url, **kw):
        self.urls.append(url)
        if self.fail:
            raise self.fail
        if '/git/trees/' in url:
            return {'tree': self.tree, 'truncated': False}, {}
        if '/commits/' in url:
            return {'sha': 'c0ffee'}, {}
        if '/contents/' in url or 'raw.githubusercontent.com' in url:
            path = url.split('c0ffee/', 1)[-1] if 'raw.' in url else url.split('/contents/', 1)[1].split('?', 1)[0]
            return self.files[path].encode(), {}
        return self.meta, {}


class ClientTests(unittest.TestCase):
    TREE = [{'path': 'pom.xml', 'type': 'blob', 'size': 10}, {'path': 'src/Main.java', 'type': 'blob', 'size': 10},
            {'path': 'node_modules/x/package.json', 'type': 'blob', 'size': 10},
            {'path': 'svc/requirements.txt', 'type': 'blob', 'size': 10}, {'path': 'big/pom.xml', 'type': 'blob', 'size': 9_999_999}]
    FILES = {'pom.xml': '<project/>', 'svc/requirements.txt': 'django==2.2'}

    def run_snapshot(self, token='', ref='acme/app', **fake_kw):
        fake = FakeGitHub(self.TREE, self.FILES, **fake_kw)
        with mock.patch.object(github, 'request', fake):
            snap = github.GitHubClient(token).snapshot(repo.parse_repo(ref))
        return snap, fake

    def test_finds_only_manifests_and_skips_vendored_and_huge(self):
        snap, _ = self.run_snapshot()
        self.assertEqual(sorted(p for p, _ in snap.manifests), ['pom.xml', 'svc/requirements.txt'])
        self.assertEqual(snap.commit, 'c0ffee')
        self.assertTrue(any('big/pom.xml' in n for n in snap.notes))

    def test_subpath_limits_the_search(self):
        snap, _ = self.run_snapshot(ref='acme/app/tree/main/svc')
        self.assertEqual([p for p, _ in snap.manifests], ['svc/requirements.txt'])

    def test_tokenless_uses_raw_host_and_token_uses_contents_api(self):
        _, anon = self.run_snapshot()
        self.assertTrue(any('raw.githubusercontent.com' in u for u in anon.urls))
        self.assertFalse(any('/contents/' in u for u in anon.urls))
        _, authed = self.run_snapshot(token='t')
        self.assertTrue(any('/contents/' in u for u in authed.urls))

    def test_rate_limit_message(self):
        err = UpstreamError('GitHub', 'HTTP 403', 403, '1900000000')
        err.headers = {'x-ratelimit-remaining': '0'}
        with self.assertRaises(UpstreamError) as ctx:
            self.run_snapshot(fail=err)
        self.assertIn('GITHUB_TOKEN', ctx.exception.message)
        self.assertIn('resets', ctx.exception.message)

    def test_not_found_message(self):
        with self.assertRaises(UpstreamError) as ctx:
            self.run_snapshot(fail=UpstreamError('GitHub', 'HTTP 404', 404))
        self.assertIn('private', ctx.exception.message)


class FakeOsv:
    missing = []

    def lookup(self, comps):
        return {('PyPI', c.name, c.version): [{'id': 'GHSA-1', 'cve': 'CVE-1', 'severity': 'high', 'score': 7.5,
                                                'fixed_versions': ['3.0'], 'suggested_fix': '3.0', 'url': 'u', 'aliases': [],
                                                'summary': 's', 'vector': '', 'published': '', 'references': []}]
                for c in comps if c.name == 'django'} | {('PyPI', c.name, c.version): [] for c in comps if c.name != 'django'}


class FakeGh:
    def snapshot(self, ref):
        return repo.RepoSnapshot(ref.slug, 'main', 'abc', False,
                                   [('requirements.txt', 'django==2.2\nflask==1.0\nrequests>=2\n'),
                                    ('svc/requirements.txt', 'django==2.2\n')], ['note one'])


class ScanTests(unittest.TestCase):
    def test_result_shape(self):
        r = scan.scan_repository('acme/app', FakeGh(), FakeOsv())
        self.assertEqual(r['status'], 'done')
        self.assertEqual(r['components'], 2)                       # django and flask, once each
        self.assertEqual(r['unevaluated'], 1)                      # requests>=2
        self.assertEqual(r['summary']['vulnerable_components'], 1)
        self.assertEqual(r['summary']['high'], 1)
        f = r['findings'][0]
        self.assertEqual(f['component']['sources'], ['requirements.txt', 'svc/requirements.txt'])
        self.assertIn('note one', r['notes'])

    def test_fix_that_clears_every_advisory_is_the_highest_per_advisory_fix(self):
        class TwoVulns(FakeOsv):
            def lookup(self, comps):
                mk = lambda i, fix: {'id': i, 'cve': '', 'severity': 'high', 'score': 7.5, 'fixed_versions': [fix] if fix else [],
                                     'suggested_fix': fix, 'url': '', 'aliases': [], 'summary': '', 'vector': '', 'published': '',
                                     'references': []}
                return {('PyPI', 'django', '2.2'): [mk('A', '2.2.10'), mk('B', '2.2.28'), mk('C', None)]}
        f = scan.scan_repository('acme/app', FakeGh(), TwoVulns())['findings'][0]
        self.assertEqual((f['fix_all'], f['unfixed']), ('2.2.28', 1))

    def test_bad_input_and_upstream_failure_become_errors_not_exceptions(self):
        self.assertEqual(scan.scan_repository('nonsense', FakeGh(), FakeOsv())['status'], 'error')

        class Boom:
            def snapshot(self, ref):
                raise UpstreamError('GitHub', 'nope', 404)
        r = scan.scan_repository('acme/app', Boom(), FakeOsv())
        self.assertEqual((r['status'], r['error']), ('error', 'nope'))


class ProgressTests(unittest.TestCase):
    @staticmethod
    def collect():
        events = []
        return events, lambda step, state, detail='', done=None, total=None: events.append((step, state, detail, done, total))

    def test_steps_are_reported_in_order(self):
        events, cb = self.collect()
        scan.scan_repository('acme/app', FakeGh(), FakeOsv(), progress=cb)
        steps = [e[0] for e in events]
        self.assertEqual(steps, sorted(steps, key=['fetch', 'parse', 'osv', 'coverage'].index))
        for step in ('fetch', 'parse', 'osv', 'coverage'):
            self.assertEqual([e[1] for e in events if e[0] == step][-1], 'done', step)
        self.assertIn('2 manifest files', [e[2] for e in events if e[0] == 'fetch' and e[1] == 'done'][0])

    def test_coverage_counts_each_component(self):
        events, cb = self.collect()
        scan.scan_repository('acme/app', FakeGh(), FakeOsv(), progress=cb)
        counted = [e for e in events if e[0] == 'coverage' and e[3] is not None]
        self.assertEqual([(e[3], e[4]) for e in counted], [(0, 1), (0, 1)])
        self.assertIn('django 2.2', [e[2] for e in events if e[0] == 'coverage' and e[1] == 'running'])

    def test_failures_end_the_step_that_failed(self):
        events, cb = self.collect()
        scan.scan_repository('nonsense', FakeGh(), FakeOsv(), progress=cb)
        self.assertEqual(events[-1][:2], ('fetch', 'failed'))

        class Boom:
            def snapshot(self, ref):
                raise UpstreamError('GitHub', 'nope', 404)
        events, cb = self.collect()
        scan.scan_repository('acme/app', Boom(), FakeOsv(), progress=cb)
        self.assertEqual((events[-1][:2], events[-1][2]), (('fetch', 'failed'), 'nope'))

        class OsvDown(FakeOsv):
            def lookup(self, comps):
                raise UpstreamError('OSV', 'osv is down', 503)
        events, cb = self.collect()
        scan.scan_repository('acme/app', FakeGh(), OsvDown(), progress=cb)
        self.assertEqual((events[-1][:2], events[-1][2]), (('osv', 'failed'), 'osv is down'))

    def test_no_callback_changes_nothing(self):
        events, cb = self.collect()
        a = scan.scan_repository('acme/app', FakeGh(), FakeOsv())
        b = scan.scan_repository('acme/app', FakeGh(), FakeOsv(), progress=cb)
        for r in (a, b):
            r.pop('scanned_at')
        self.assertEqual(a, b)


if __name__ == '__main__':
    unittest.main()
