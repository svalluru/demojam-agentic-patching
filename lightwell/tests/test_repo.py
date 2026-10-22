import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import repo                                                   # noqa: E402
from scanner.http import UpstreamError                                     # noqa: E402


class GitHubUrlTests(unittest.TestCase):
    def test_accepted_forms(self):
        for spec in ('https://github.com/acme/app', 'github.com/acme/app', 'acme/app', 'https://github.com/acme/app.git',
                     'https://github.com/acme/app/', 'HTTP://www.github.com/acme/app?x=1'):
            r = repo.parse_repo(spec)
            self.assertEqual((r.kind, r.host, r.path, r.ref, r.subpath, r.slug), ('github', 'github.com', 'acme/app', '', '', 'acme/app'), spec)

    def test_tree_url(self):
        r = repo.parse_repo('https://github.com/acme/app/tree/release/services/api')
        self.assertEqual((r.ref, r.subpath), ('release', 'services/api'))

    def test_owner_and_repo(self):
        r = repo.parse_repo('acme/app')
        self.assertEqual((r.owner, r.repo), ('acme', 'app'))


class GitLabUrlTests(unittest.TestCase):
    def test_project_and_nested_groups(self):
        r = repo.parse_repo('https://gitlab.com/acme/app')
        self.assertEqual((r.kind, r.host, r.path, r.slug), ('gitlab', 'gitlab.com', 'acme/app', 'gitlab.com/acme/app'))
        r = repo.parse_repo('gitlab.com/acme/platform/team/app.git')
        self.assertEqual((r.path, r.slug), ('acme/platform/team/app', 'gitlab.com/acme/platform/team/app'))

    def test_tree_url_uses_the_dash_separator(self):
        r = repo.parse_repo('https://gitlab.com/acme/platform/app/-/tree/release/services/api')
        self.assertEqual((r.path, r.ref, r.subpath), ('acme/platform/app', 'release', 'services/api'))
        self.assertEqual(repo.parse_repo('https://gitlab.com/acme/app/-/tree/main').subpath, '')

    def test_a_bare_owner_repo_is_github_never_gitlab(self):
        self.assertEqual(repo.parse_repo('acme/app').kind, 'github')

    def test_self_hosted_hosts_must_be_listed(self):
        with self.assertRaises(ValueError) as ctx:
            repo.parse_repo('https://git.example.com/acme/app')
        self.assertIn('not supported', str(ctx.exception))
        r = repo.parse_repo('https://git.example.com/acme/app', ['git.example.com'])
        self.assertEqual((r.kind, r.host, r.slug), ('gitlab', 'git.example.com', 'git.example.com/acme/app'))
        r = repo.parse_repo('https://GIT.example.com:8443/acme/app', ['git.example.com:8443'])
        self.assertEqual(r.host, 'git.example.com:8443')

    def test_the_host_list_is_normalised_and_always_has_gitlab_com(self):
        self.assertEqual(repo.allowed_gitlab_hosts(['A.example.com', ' ', 'bad host', 'a.example.com']), ['gitlab.com', 'a.example.com'])


class RejectedTests(unittest.TestCase):
    def test_rejected(self):
        for spec in ('', 'acme', 'https://bitbucket.org/acme/app', 'https://github.com/acme/app/issues', 'a/b/../c',
                     'https://github.com/ac me/app', 'https://github.com/acme/app/tree/../x', 'x' * 500,
                     'https://gitlab.com/acme', 'https://gitlab.com/acme/app/-/blob/main/x', 'https://gitlab.com/acme/../app',
                     'https://169.254.169.254/latest/meta-data', 'http://localhost:8080/a/b', 'file:///etc/passwd'):
            with self.assertRaises(ValueError, msg=spec):
                repo.parse_repo(spec)


class RouterAndDemoTests(unittest.TestCase):
    def test_router_sends_each_ref_to_its_host(self):
        calls = []

        class C:
            def __init__(self, name): self.name = name
            def snapshot(self, ref): calls.append((self.name, ref.slug)); return repo.RepoSnapshot(ref.slug, 'main', 'c')
        router = repo.RepoRouter(C('github'), {'gitlab.com': C('gitlab.com'), 'git.example.com': C('git.example.com')})
        for spec in ('acme/app', 'https://gitlab.com/g/p', 'https://git.example.com/g/p'):
            router.snapshot(repo.parse_repo(spec, ['git.example.com']))
        self.assertEqual(calls, [('github', 'acme/app'), ('gitlab.com', 'gitlab.com/g/p'), ('git.example.com', 'git.example.com/g/p')])
        with self.assertRaises(UpstreamError):
            router.snapshot(repo.parse_repo('https://other.test/g/p', ['other.test']))              # allowed to parse, but not configured

    def test_demo_repos_serve_both_hosts_from_files_named_after_the_slug(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ('acme__app', 'gitlab.com__grp__sub__proj'):
                (Path(d) / f'{name}.json').write_text(json.dumps({'ref': 'main', 'commit': 'abc', 'manifests': {'pom.xml': '<project/>'}}))
            demo = repo.DemoRepos(Path(d))
            self.assertEqual(demo.available(), ['acme/app', 'gitlab.com/grp/sub/proj'])
            self.assertEqual(demo.snapshot(repo.parse_repo('acme/app')).manifests, [('pom.xml', '<project/>')])
            self.assertEqual(demo.snapshot(repo.parse_repo('https://gitlab.com/grp/sub/proj')).commit, 'abc')
            with self.assertRaises(UpstreamError) as ctx:
                demo.snapshot(repo.parse_repo('acme/other'))
            self.assertIn('not recorded', ctx.exception.message)


if __name__ == '__main__':
    unittest.main()
