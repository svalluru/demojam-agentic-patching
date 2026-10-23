import sys
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import gitlab, repo                                           # noqa: E402
from scanner.http import UpstreamError                                     # noqa: E402

TREE = [{'path': 'pom.xml', 'type': 'blob'}, {'path': 'src', 'type': 'tree'}, {'path': 'src/Main.java', 'type': 'blob'},
        {'path': 'node_modules/x/package.json', 'type': 'blob'}, {'path': 'svc/requirements.txt', 'type': 'blob'}]
FILES = {'pom.xml': '<project/>', 'svc/requirements.txt': 'django==2.2'}


class FakeGitLab:
    """Stands in for http.request. Records every call, pages the tree like GitLab does."""

    def __init__(self, tree=TREE, files=FILES, visibility='public', per_page=100, fail=None):
        self.tree, self.files, self.visibility, self.per_page, self.fail, self.calls = tree, files, visibility, per_page, fail, []

    def __call__(self, service, url, **kw):
        self.calls.append((url, kw))
        if self.fail:
            raise self.fail
        parts = urllib.parse.urlparse(url)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(parts.query).items()}
        path = parts.path
        if '/repository/tree' in path:
            page = int(q.get('page', 1))
            rows = self.tree[(page - 1) * self.per_page: page * self.per_page]
            more = page * self.per_page < len(self.tree)
            return rows, {'x-next-page': str(page + 1) if more else ''}
        if '/repository/commits/' in path:
            return {'id': 'c0ffee'}, {}
        if '/repository/files/' in path:
            name = urllib.parse.unquote(path.split('/repository/files/', 1)[1].rsplit('/raw', 1)[0])
            return self.files[name].encode(), {}
        return {'default_branch': 'main', 'visibility': self.visibility}, {}


def snap(spec='gitlab.com/grp/sub/app', client=None, **fake_kw):
    fake = FakeGitLab(**fake_kw)
    with mock.patch.object(gitlab, 'request', fake):
        out = (client or gitlab.GitLabClient()).snapshot(repo.parse_repo(spec, ['git.example.com']))
    return out, fake


class SnapshotTests(unittest.TestCase):
    def test_finds_only_manifests_and_skips_vendored_folders_and_trees(self):
        s, _ = snap()
        self.assertEqual(sorted(p for p, _ in s.manifests), ['pom.xml', 'svc/requirements.txt'])
        self.assertEqual((s.slug, s.ref, s.commit, s.private), ('gitlab.com/grp/sub/app', 'main', 'c0ffee', False))

    def test_the_project_path_and_file_paths_are_url_encoded(self):
        _, fake = snap()
        urls = [c[0] for c in fake.calls]
        self.assertTrue(any('/projects/grp%2Fsub%2Fapp' in u for u in urls))
        self.assertTrue(any('/repository/files/svc%2Frequirements.txt/raw' in u for u in urls))
        self.assertTrue(all(u.startswith('https://gitlab.com/api/v4/') for u in urls))

    def test_files_are_fetched_at_the_commit_not_the_branch(self):
        _, fake = snap()
        raws = [c[0] for c in fake.calls if '/raw' in c[0]]
        self.assertTrue(raws and all('ref=c0ffee' in u for u in raws))

    def test_subpath_limits_the_search(self):
        s, _ = snap('https://gitlab.com/grp/sub/app/-/tree/main/svc')
        self.assertEqual([p for p, _ in s.manifests], ['svc/requirements.txt'])

    def test_a_private_project_is_flagged(self):
        s, _ = snap(visibility='private')
        self.assertTrue(s.private)

    def test_the_tree_is_paged_to_the_end(self):
        tree = [{'path': f'd{i}/pom.xml', 'type': 'blob'} for i in range(7)]
        files = {f'd{i}/pom.xml': '<project/>' for i in range(7)}
        s, fake = snap(tree=tree, files=files, per_page=3)
        self.assertEqual(len(s.manifests), 7)
        self.assertEqual(len([c for c in fake.calls if '/repository/tree' in c[0]]), 3)

    def test_a_tree_longer_than_the_page_limit_says_so(self):
        tree = [{'path': f'd{i}/pom.xml', 'type': 'blob'} for i in range(9)]
        files = {f'd{i}/pom.xml': '<project/>' for i in range(9)}
        with mock.patch.object(gitlab, 'MAX_PAGES', 2):
            s, _ = snap(tree=tree, files=files, per_page=3)
        self.assertTrue(any('more than' in n for n in s.notes))

    def test_manifest_count_is_capped(self):
        tree = [{'path': f'd{i}/pom.xml', 'type': 'blob'} for i in range(5)]
        files = {f'd{i}/pom.xml': '<project/>' for i in range(5)}
        s, _ = snap(tree=tree, files=files, client=gitlab.GitLabClient(max_manifests=2))
        self.assertEqual(len(s.manifests), 2)
        self.assertTrue(any('only the first 2' in n for n in s.notes))

    def test_no_manifests_is_reported_not_silent(self):
        s, _ = snap(tree=[{'path': 'README.md', 'type': 'blob'}])
        self.assertEqual(s.manifests, [])
        self.assertTrue(any('No supported dependency manifests' in n for n in s.notes))

    def test_downloads_are_capped(self):
        _, fake = snap(client=gitlab.GitLabClient(max_bytes=4321))
        self.assertEqual({c[1].get('max_bytes') for c in fake.calls if '/raw' in c[0]}, {4321})

    def test_self_hosted_host_is_used_for_the_api(self):
        s, fake = snap('https://git.example.com/grp/app', client=gitlab.GitLabClient('git.example.com'))
        self.assertTrue(all(c[0].startswith('https://git.example.com/api/v4/') for c in fake.calls))


class TokenTests(unittest.TestCase):
    def test_token_goes_in_private_token_header_only_when_set(self):
        _, anon = snap()
        self.assertTrue(all('PRIVATE-TOKEN' not in c[1].get('headers', {}) for c in anon.calls))
        _, authed = snap(client=gitlab.GitLabClient(token='glpat-SECRET'))
        self.assertTrue(all(c[1]['headers'].get('PRIVATE-TOKEN') == 'glpat-SECRET' for c in authed.calls))
        self.assertTrue(all('SECRET' not in c[0] for c in authed.calls))                 # never in a URL


class ErrorTests(unittest.TestCase):
    def fails(self, err, **kw):
        with self.assertRaises(UpstreamError) as ctx:
            snap(fail=err, **kw)
        return ctx.exception

    def test_not_found_mentions_the_token_and_the_host(self):
        e = self.fails(UpstreamError('GitLab', 'HTTP 404', 404))
        self.assertIn('private project', e.message)
        self.assertIn('gitlab.com', e.message)

    def test_rate_limit_says_when_to_retry(self):
        err = UpstreamError('GitLab', 'HTTP 429', 429)
        err.headers = {'retry-after': '37'}
        e = self.fails(err)
        self.assertIn('37 seconds', e.message)

    def test_refused_token(self):
        e = self.fails(UpstreamError('GitLab', 'HTTP 401', 401))
        self.assertIn('read_api', e.message)
        self.assertEqual(e.status, 401)

    def test_a_manifest_that_cannot_be_fetched_is_noted_and_the_rest_continue(self):
        class Flaky(FakeGitLab):
            def __call__(self, service, url, **kw):
                if 'pom.xml' in url and '/raw' in url:
                    raise UpstreamError('GitLab', 'larger than 1000 KB')
                return super().__call__(service, url, **kw)
        with mock.patch.object(gitlab, 'request', Flaky()):
            s = gitlab.GitLabClient().snapshot(repo.parse_repo('gitlab.com/grp/app'))
        self.assertEqual([p for p, _ in s.manifests], ['svc/requirements.txt'])
        self.assertTrue(any('pom.xml' in n and 'could not be fetched' in n for n in s.notes))


if __name__ == '__main__':
    unittest.main()
