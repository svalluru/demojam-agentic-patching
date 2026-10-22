import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import parse, pom, scan                                       # noqa: E402
from scanner.http import UpstreamError                                     # noqa: E402


def project(group='com.acme', artifact='app', version='1.0', parent=None, props=None, managed=(), deps=(), relpath=None):
    """A pom.xml. parent is (group, artifact, version); managed and deps are (group, artifact, version-or-None[, scope])."""
    def dep(d):
        g, a, v = d[:3]
        scope = f'<scope>{d[3]}</scope>' if len(d) > 3 else ''
        typ = '<type>pom</type>' if len(d) > 3 and d[3] == 'import' else ''
        return f"<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId>{f'<version>{v}</version>' if v else ''}{scope}{typ}</dependency>"
    par = ''
    if parent:
        rel = '' if relpath is None else (f'<relativePath>{relpath}</relativePath>' if relpath else '<relativePath/>')
        par = f'<parent><groupId>{parent[0]}</groupId><artifactId>{parent[1]}</artifactId><version>{parent[2]}</version>{rel}</parent>'
    p = ''.join(f'<{k}>{v}</{k}>' for k, v in (props or {}).items())
    return (f'<project xmlns="http://maven.apache.org/POM/4.0.0">{par}<groupId>{group}</groupId><artifactId>{artifact}</artifactId>'
            f'{f"<version>{version}</version>" if version else ""}<properties>{p}</properties>'
            f'<dependencyManagement><dependencies>{"".join(dep(d) for d in managed)}</dependencies></dependencyManagement>'
            f'<dependencies>{"".join(dep(d) for d in deps)}</dependencies></project>')


class Fetch:
    """Stands in for the published-POM fetcher, keyed by (group, artifact, version)."""

    def __init__(self, poms=None, fail=None):
        self.poms, self.fail, self.calls = poms or {}, fail, []

    def __call__(self, g, a, v):
        self.calls.append((g, a, v))
        if self.fail:
            raise self.fail
        return self.poms.get((g, a, v))


def versions(files, path, fetch=None, **kw):
    resolver = pom.PomResolver(files, fetch, **kw)
    comps, notes = parse.parse_manifest(path, files[path], resolver)
    return {c.name: c.version for c in comps}, notes, resolver


class InRepositoryTests(unittest.TestCase):
    ROOT = project('com.acme', 'root', props={'jackson.version': '2.9.8'}, managed=[('com.fasterxml.jackson.core', 'jackson-databind', '${jackson.version}')])

    def test_a_module_takes_versions_and_properties_from_the_parent_in_the_same_repository(self):
        files = {'pom.xml': self.ROOT, 'api/pom.xml': project(artifact='api', parent=('com.acme', 'root', '1.0'), deps=[('com.fasterxml.jackson.core', 'jackson-databind', None)])}
        got, notes, _ = versions(files, 'api/pom.xml')
        self.assertEqual(got['com.fasterxml.jackson.core:jackson-databind'], '2.9.8')
        self.assertTrue(any('parent com.acme:root:1.0 (this repository)' in n for n in notes))

    def test_a_childs_property_overrides_the_parents_in_the_versions_the_parent_manages(self):
        files = {'pom.xml': self.ROOT, 'api/pom.xml': project(artifact='api', parent=('com.acme', 'root', '1.0'), props={'jackson.version': '2.15.0'},
                                                              deps=[('com.fasterxml.jackson.core', 'jackson-databind', None)])}
        self.assertEqual(versions(files, 'api/pom.xml')[0]['com.fasterxml.jackson.core:jackson-databind'], '2.15.0')

    def test_the_parent_is_found_by_coordinates_when_it_is_not_where_relativePath_says(self):
        files = {'build/parent/pom.xml': self.ROOT, 'api/pom.xml': project(artifact='api', parent=('com.acme', 'root', '1.0'), relpath='../nowhere/pom.xml',
                                                                          deps=[('com.fasterxml.jackson.core', 'jackson-databind', None)])}
        self.assertEqual(versions(files, 'api/pom.xml')[0]['com.fasterxml.jackson.core:jackson-databind'], '2.9.8')

    def test_a_parent_of_the_wrong_coordinates_at_the_relative_path_is_not_used(self):
        other = project('com.other', 'other', managed=[('x', 'y', '9')])
        files = {'pom.xml': other, 'api/pom.xml': project(artifact='api', parent=('com.acme', 'root', '1.0'), deps=[('x', 'y', None)])}
        got, notes, _ = versions(files, 'api/pom.xml')
        self.assertIsNone(got['x:y'])
        self.assertTrue(any('parent POM com.acme:root:1.0 could not be read' in n for n in notes))

    def test_the_project_version_property_and_inherited_versions_work(self):
        files = {'pom.xml': project(version='3.1'), 'm/pom.xml': project(artifact='m', version=None, parent=('com.acme', 'app', '3.1'), deps=[('com.acme', 'sibling', '${project.version}')])}
        self.assertEqual(versions(files, 'm/pom.xml')[0]['com.acme:sibling'], '3.1')

    def test_a_module_with_its_own_explicit_version_keeps_it(self):
        files = {'pom.xml': self.ROOT, 'api/pom.xml': project(artifact='api', parent=('com.acme', 'root', '1.0'), deps=[('com.fasterxml.jackson.core', 'jackson-databind', '2.0.0')])}
        self.assertEqual(versions(files, 'api/pom.xml')[0]['com.fasterxml.jackson.core:jackson-databind'], '2.0.0')


class PublishedPomTests(unittest.TestCase):
    PARENT = project('org.vendor', 'vendor-parent', '5', props={'log4j.version': '2.14.1'}, managed=[('org.apache.logging.log4j', 'log4j-core', '${log4j.version}')])

    def module(self, **kw):
        return project(artifact='app', parent=('org.vendor', 'vendor-parent', '5'), deps=[('org.apache.logging.log4j', 'log4j-core', None)], **kw)

    def test_a_published_parent_is_fetched_once_and_its_versions_apply(self):
        fetch = Fetch({('org.vendor', 'vendor-parent', '5'): self.PARENT})
        got, notes, resolver = versions({'pom.xml': self.module()}, 'pom.xml', fetch)
        self.assertEqual(got['org.apache.logging.log4j:log4j-core'], '2.14.1')
        self.assertEqual((fetch.calls, resolver.fetches), ([('org.vendor', 'vendor-parent', '5')], 1))
        self.assertTrue(any('(Maven Central)' in n for n in notes))

    def test_two_modules_share_one_fetch(self):
        fetch = Fetch({('org.vendor', 'vendor-parent', '5'): self.PARENT})
        files = {'a/pom.xml': self.module(), 'b/pom.xml': self.module()}
        resolver = pom.PomResolver(files, fetch)
        for path in files:
            parse.parse_manifest(path, files[path], resolver)
        self.assertEqual(len(fetch.calls), 1)

    def test_without_a_fetcher_nothing_outside_the_repository_is_looked_at(self):
        got, notes, _ = versions({'pom.xml': self.module()}, 'pom.xml')
        self.assertIsNone(got['org.apache.logging.log4j:log4j-core'])
        self.assertTrue(any('not fetched in this mode' in n for n in notes))

    def test_a_missing_or_failing_fetch_leaves_the_dependency_unresolved_and_says_why(self):
        got, notes, _ = versions({'pom.xml': self.module()}, 'pom.xml', Fetch())
        self.assertIsNone(got['org.apache.logging.log4j:log4j-core'])
        self.assertTrue(any('it was not found' in n for n in notes))
        got, notes, _ = versions({'pom.xml': self.module()}, 'pom.xml', Fetch(fail=UpstreamError('Maven Central', 'HTTP 503', 503)))
        self.assertIsNone(got['org.apache.logging.log4j:log4j-core'])
        self.assertTrue(any('HTTP 503' in n for n in notes))

    def test_a_published_pom_that_declares_a_doctype_or_is_not_xml_is_ignored(self):
        for text, why in (('<!DOCTYPE x [<!ENTITY a "b">]><project/>', 'DOCTYPE'), ('<project>', 'not valid XML')):
            got, notes, _ = versions({'pom.xml': self.module()}, 'pom.xml', Fetch({('org.vendor', 'vendor-parent', '5'): text}))
            self.assertIsNone(got['org.apache.logging.log4j:log4j-core'])
            self.assertTrue(any(why in n for n in notes), why)

    def test_coordinates_that_are_not_plain_text_are_never_fetched(self):
        fetch = Fetch()
        files = {'pom.xml': project(artifact='app', parent=('org.vendor/../x', 'p', '1'), deps=[('g', 'a', None)]),
                 'b/pom.xml': project(artifact='b', parent=('org.vendor', 'p', '${unknown}'), deps=[('g', 'a', None)])}
        for path in files:
            versions(files, path, fetch)
        self.assertEqual(fetch.calls, [])

    def test_the_number_of_fetches_is_capped(self):
        poms = {('org.vendor', f'p{i}', '1'): self.PARENT for i in range(5)}
        files = {f'm{i}/pom.xml': project(artifact=f'm{i}', parent=('org.vendor', f'p{i}', '1'), deps=[('org.apache.logging.log4j', 'log4j-core', None)]) for i in range(5)}
        fetch = Fetch(poms)
        resolver = pom.PomResolver(files, fetch, max_fetches=2)
        out = [parse.parse_manifest(p, t, resolver)[0][0].version for p, t in files.items()]
        self.assertEqual((len(fetch.calls), out.count(None)), (2, 3))

    def test_a_chain_that_loops_ends(self):
        a = project(artifact='a', parent=('g', 'b', '1'), deps=[('x', 'y', None)])
        b = project('g', 'b', '1', parent=('com.acme', 'a', '1.0'))
        got, notes, _ = versions({'pom.xml': a.replace('<groupId>com.acme</groupId><artifactId>a</artifactId>', '<groupId>com.acme</groupId><artifactId>a</artifactId>', 1)},
                                 'pom.xml', Fetch({('g', 'b', '1'): b, ('com.acme', 'a', '1.0'): a}))
        self.assertIsNone(got['x:y'])
        self.assertTrue(any('circular' in n or 'deep' in n for n in notes))


class BomTests(unittest.TestCase):
    BOM = project('io.stack', 'stack-bom', '4.5', props={'jackson.version': '2.15.2'}, managed=[
        ('com.fasterxml.jackson.core', 'jackson-databind', '${jackson.version}'), ('io.netty', 'netty-codec', '4.1.100'), ('shared', 'lib', '1')])

    def module(self, managed=(), deps=None, extra_import=None):
        imports = [('io.stack', 'stack-bom', '${stack.version}', 'import')] + ([extra_import] if extra_import else [])
        return project(artifact='app', props={'stack.version': '4.5'}, managed=imports + list(managed),
                       deps=deps or [('com.fasterxml.jackson.core', 'jackson-databind', None), ('io.netty', 'netty-codec', None)])

    def test_an_imported_bom_is_fetched_and_its_properties_are_resolved_in_its_own_context(self):
        fetch = Fetch({('io.stack', 'stack-bom', '4.5'): self.BOM})
        got, notes, _ = versions({'pom.xml': self.module()}, 'pom.xml', fetch)
        self.assertEqual((got['com.fasterxml.jackson.core:jackson-databind'], got['io.netty:netty-codec']), ('2.15.2', '4.1.100'))
        self.assertEqual(fetch.calls, [('io.stack', 'stack-bom', '4.5')])
        self.assertTrue(any('BOM io.stack:stack-bom:4.5 (Maven Central)' in n for n in notes))

    def test_a_bom_that_imports_another_bom_is_followed(self):
        outer = project('io.stack', 'outer', '1', managed=[('io.stack', 'stack-bom', '4.5', 'import'), ('only', 'outer', '7')])
        fetch = Fetch({('io.stack', 'outer', '1'): outer, ('io.stack', 'stack-bom', '4.5'): self.BOM})
        files = {'pom.xml': project(artifact='app', managed=[('io.stack', 'outer', '1', 'import')], deps=[('io.netty', 'netty-codec', None), ('only', 'outer', None)])}
        got, _, _ = versions(files, 'pom.xml', fetch)
        self.assertEqual((got['io.netty:netty-codec'], got['only:outer']), ('4.1.100', '7'))

    def test_the_pom_wins_over_its_boms_and_the_first_import_wins_among_boms(self):
        other = project('io.other', 'other-bom', '1', managed=[('shared', 'lib', '2'), ('io.netty', 'netty-codec', '9.9')])
        fetch = Fetch({('io.stack', 'stack-bom', '4.5'): self.BOM, ('io.other', 'other-bom', '1'): other})
        files = {'pom.xml': self.module(managed=[('io.netty', 'netty-codec', '4.1.200')], extra_import=('io.other', 'other-bom', '1', 'import'),
                                        deps=[('io.netty', 'netty-codec', None), ('shared', 'lib', None)])}
        got, _, _ = versions(files, 'pom.xml', fetch)
        self.assertEqual((got['io.netty:netty-codec'], got['shared:lib']), ('4.1.200', '1'))

    def test_a_bom_in_the_same_repository_needs_no_fetch(self):
        files = {'bom/pom.xml': self.BOM, 'pom.xml': self.module()}
        fetch = Fetch()
        got, notes, _ = versions(files, 'pom.xml', fetch)
        self.assertEqual((got['io.netty:netty-codec'], fetch.calls), ('4.1.100', []))
        self.assertTrue(any('(this repository)' in n for n in notes))

    def test_a_bom_that_cannot_be_read_says_so_and_changes_nothing_else(self):
        got, notes, _ = versions({'pom.xml': self.module(deps=[('io.netty', 'netty-codec', None), ('junit', 'junit', '4.12')])}, 'pom.xml', Fetch())
        self.assertEqual((got['io.netty:netty-codec'], got['junit:junit']), (None, '4.12'))
        self.assertTrue(any('BOM io.stack:stack-bom:4.5 could not be read' in n for n in notes))

    def test_a_bom_with_an_unresolvable_version_is_not_fetched(self):
        fetch = Fetch()
        files = {'pom.xml': project(artifact='app', managed=[('io.stack', 'stack-bom', '${nope}', 'import')], deps=[('io.netty', 'netty-codec', None)])}
        got, notes, _ = versions(files, 'pom.xml', fetch)
        self.assertEqual(fetch.calls, [])
        self.assertTrue(any('not plain text' in n for n in notes))

    def test_type_and_classifier_are_part_of_what_is_managed(self):
        bom = project('io.stack', 'stack-bom', '4.5', managed=[('g', 'a', '1')])
        files = {'pom.xml': project(artifact='app', managed=[('io.stack', 'stack-bom', '4.5', 'import')],
                                    deps=[('g', 'a', None)]).replace('</dependencies></project>', '<dependency><groupId>g</groupId><artifactId>a</artifactId><classifier>tests</classifier></dependency></dependencies></project>')}
        comps, _ = parse.parse_manifest('pom.xml', files['pom.xml'], pom.PomResolver(files, Fetch({('io.stack', 'stack-bom', '4.5'): bom})))
        self.assertEqual([c.version for c in comps if c.name == 'g:a'], ['1', None])      # the jar is managed, the tests classifier is not


class ScanIntegrationTests(unittest.TestCase):
    class Repos:
        def __init__(self, files):
            self.files = files

        def snapshot(self, ref):
            from scanner.repo import RepoSnapshot
            return RepoSnapshot(ref.slug, 'main', 'abc', False, sorted(self.files.items()), [])

    class Osv:
        def lookup(self, comps):
            return {('Maven', c.name, c.version): [] for c in comps}

    def scan_with(self, mode, files, fetch=None):
        return scan.scan_repository('acme/app', self.Repos(files), self.Osv(), pom_resolution=mode, pom_fetch=fetch)

    def files(self):
        return {'pom.xml': project('com.acme', 'root', managed=[('g', 'managed', '3')]),
                'api/pom.xml': project(artifact='api', parent=('com.acme', 'root', '1.0'), deps=[('g', 'managed', None), ('g', 'direct', '1')])}

    def test_off_reads_each_pom_alone_repo_follows_the_parent_and_all_also_fetches(self):
        self.assertEqual(self.scan_with('off', self.files())['unevaluated'], 1)
        repo = self.scan_with('repo', self.files())
        self.assertEqual((repo['unevaluated'], [f for f in repo['notes'] if 'parent com.acme:root:1.0 (this repository)' in f] != []), (0, True))

    def test_all_fetches_what_the_repository_does_not_have(self):
        files = {'pom.xml': project(artifact='app', parent=('org.vendor', 'vendor-parent', '5'), deps=[('org.apache.logging.log4j', 'log4j-core', None)])}
        fetch = Fetch({('org.vendor', 'vendor-parent', '5'): PublishedPomTests.PARENT})
        self.assertEqual(self.scan_with('repo', files, fetch)['unevaluated'], 1)
        self.assertEqual(fetch.calls, [])                                                          # repo mode never goes out
        r = self.scan_with('all', files, fetch)
        self.assertEqual((r['unevaluated'], len(fetch.calls)), (0, 1))                          # the parent itself is a component too

    def test_progress_says_how_many_poms_were_fetched(self):
        events = []
        files = {'pom.xml': project(artifact='app', parent=('org.vendor', 'vendor-parent', '5'), deps=[('org.apache.logging.log4j', 'log4j-core', None)])}
        scan.scan_repository('acme/app', self.Repos(files), self.Osv(), progress=lambda s, st, d='', **k: events.append((s, st, d)),
                             pom_resolution='all', pom_fetch=Fetch({('org.vendor', 'vendor-parent', '5'): PublishedPomTests.PARENT}))
        self.assertIn('1 parent or BOM POMs fetched', [d for s, st, d in events if s == 'parse' and st == 'done'][0])


class CentralFetcherTests(unittest.TestCase):
    def test_the_url_is_built_from_plain_coordinates_and_the_answer_is_cached(self):
        with mock.patch.object(pom, 'request', return_value=(b'<project/>', {})) as req:
            f = pom.CentralFetcher('https://example.test/maven2/')
            self.assertEqual(f('org.vendor', 'vendor-parent', '5'), '<project/>')
            self.assertEqual(f('org.vendor', 'vendor-parent', '5'), '<project/>')
        self.assertEqual(req.call_count, 1)
        self.assertEqual(req.call_args.args[1], 'https://example.test/maven2/org/vendor/vendor-parent/5/vendor-parent-5.pom')
        self.assertEqual(req.call_args.kwargs['max_bytes'], pom.MAX_POM_BYTES)

    def test_a_404_is_none_and_cached_and_other_errors_are_raised(self):
        f = pom.CentralFetcher()
        with mock.patch.object(pom, 'request', side_effect=UpstreamError('Maven Central', 'HTTP 404', 404)) as req:
            self.assertIsNone(f('a', 'b', '1'))
            self.assertIsNone(f('a', 'b', '1'))
        self.assertEqual(req.call_count, 1)
        with mock.patch.object(pom, 'request', side_effect=UpstreamError('Maven Central', 'HTTP 503', 503)):
            with self.assertRaises(UpstreamError):
                f('a', 'b', '2')

    def test_coordinates_that_are_not_plain_never_reach_the_network(self):
        with mock.patch.object(pom, 'request') as req:
            for bad in (('a/../b', 'x', '1'), ('a', 'x y', '1'), ('a', 'x', '1/../../etc'), ('a', 'x', '${v}'), ('', 'x', '1')):
                self.assertIsNone(pom.CentralFetcher()(*bad), bad)
        req.assert_not_called()


if __name__ == '__main__':
    unittest.main()
