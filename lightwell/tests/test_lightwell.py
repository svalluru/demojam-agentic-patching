import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import lightwell, scan                                        # noqa: E402
from scanner.repo import DemoRepos                                          # noqa: E402
from scanner.osv import FixtureOsv                                         # noqa: E402

DEMO = Path(__file__).resolve().parents[1] / 'demo'


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = Path(self.tmp.name) / 'c.json'
        path.write_text(json.dumps({'note': 'n', 'entries': [
            {'ecosystem': 'maven', 'name': 'a:b', 'version': '1.0', 'status': 'remediated', 'build': '1.0.rhlw-00001', 'cves': ['CVE-1']},
            {'ecosystem': 'pypi', 'name': 'Flask_Login', 'version': '0.4.1', 'status': 'predisclosure', 'build': '0.4.1.rhlw-00001',
             'embargo_days': 3, 'cves': []}]}))
        self.cat = lightwell.FixtureCatalog(path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_exact_version_only(self):
        self.assertEqual(self.cat.check('maven', 'a:b', '1.0')['status'], 'remediated')
        self.assertEqual(self.cat.check('maven', 'a:b', '1.0.1')['status'], 'not_covered')
        self.assertEqual(self.cat.check('maven', 'a:c', '1.0')['status'], 'not_covered')

    def test_pypi_names_are_normalised(self):
        r = self.cat.check('pypi', 'flask-login', '0.4.1')
        self.assertEqual((r['status'], r['embargo_days']), ('predisclosure', 3))

    def test_package_view_comes_from_the_snapshot_when_the_package_was_looked_up(self):
        path = Path(self.tmp.name) / 'c2.json'
        path.write_text(json.dumps({'entries': [], 'repositories': [{'name': 'r'}], 'packages': {
            'maven|a:b': {'remediated': [{'version': '2.0', 'build': '2.0.rhlw-00001', 'repository': 'x'}], 'validated': ['1.0']},
            'pypi|flask-login': {'remediated': [], 'validated': []}}}))
        cat = lightwell.FixtureCatalog(path)
        v = cat.check('maven', 'a:b', '1.0')['versions']
        self.assertEqual((v['nearest']['version'], v['exact_validated'], v['carried']), ('2.0', True, True))
        self.assertFalse(cat.check('pypi', 'Flask_Login', '0.4.1')['versions']['carried'])
        self.assertNotIn('versions', cat.check('maven', 'not:looked-up', '1.0'))      # absent from the snapshot: say nothing
        self.assertEqual(cat.facts(), {'repositories': [{'name': 'r'}]})
        self.assertIsNone(self.cat.facts())

    def test_it_says_it_is_a_sample(self):
        self.assertTrue(self.cat.sample)
        self.assertEqual(self.cat.describe()['source'], 'sample')

    def test_live_mode_does_not_pretend(self):
        cat = lightwell.make_catalog('live', DEMO)
        self.assertEqual(cat.check('maven', 'a:b', '1.0')['status'], 'not_checked')
        self.assertFalse(cat.sample)
        self.assertEqual(cat.describe()['source'], 'none')
        self.assertIsInstance(lightwell.make_catalog('demo', DEMO), lightwell.FixtureCatalog)


def vuln(vid, cve, aliases=()):
    return {'id': vid, 'cve': cve, 'aliases': list(aliases), 'severity': 'high', 'score': 7.5, 'fixed_versions': ['2'],
            'suggested_fix': '2', 'url': '', 'summary': '', 'vector': '', 'published': '', 'references': []}


class ApplyCoverageTests(unittest.TestCase):
    def test_issue_matching_uses_id_cve_or_alias(self):
        cat = lightwell.FixtureCatalog(Path('/nonexistent'))
        cat._index = {('maven', 'a:b', '1.0'): {'status': 'remediated', 'build': '1.0.rhlw-00001', 'cves': ['CVE-1', 'GHSA-x']}}
        findings = [{'component': {'ecosystem': 'maven', 'name': 'a:b', 'version': '1.0'},
                     'vulns': [vuln('GHSA-1', 'CVE-1'), vuln('GHSA-x', ''), vuln('PYSEC-9', 'CVE-9', ['CVE-1']), vuln('GHSA-2', 'CVE-2')]},
                    {'component': {'ecosystem': 'maven', 'name': 'c:d', 'version': '1.0'}, 'vulns': [vuln('GHSA-3', 'CVE-3')]}]
        out = scan.apply_coverage(findings, cat)
        self.assertEqual([v['lightwell_fixed'] for v in findings[0]['vulns']], [True, True, True, False])
        self.assertEqual((findings[0]['lightwell']['resolves'], findings[0]['lightwell']['of']), (3, 4))
        self.assertEqual(findings[1]['lightwell']['status'], 'not_covered')
        self.assertEqual((out['remediated'], out['not_covered'], out['issues_resolved'], out['issues_total']), (1, 1, 3, 5))
        self.assertTrue(out['sample'])

    def test_not_covered_with_a_remediated_build_of_another_version_is_other_version(self):
        cat = lightwell.FixtureCatalog(Path('/nonexistent'))
        cat._packages = {'maven|a:b': {'remediated': [{'version': '1.5', 'build': '1.5.rhlw-00001', 'repository': 'r'}], 'validated': []}}
        findings = [{'component': {'ecosystem': 'maven', 'name': 'a:b', 'version': '1.0'}, 'vulns': [vuln('G', 'CVE-1')]},
                    {'component': {'ecosystem': 'maven', 'name': 'c:d', 'version': '1.0'}, 'vulns': [vuln('H', 'CVE-2')]}]
        out = scan.apply_coverage(findings, cat)
        self.assertEqual(findings[0]['lightwell']['status'], 'other_version')
        self.assertEqual(findings[0]['lightwell']['versions']['nearest']['version'], '1.5')
        self.assertIsNone(findings[0]['lightwell']['resolves'])
        self.assertFalse(findings[0]['vulns'][0]['lightwell_fixed'])
        self.assertEqual(findings[1]['lightwell']['status'], 'not_covered')
        self.assertEqual((out['other_version'], out['not_covered'], out['remediated']), (1, 1, 0))

    def test_a_build_that_does_not_list_its_cves_is_not_credited_with_fixing_any(self):
        cat = lightwell.FixtureCatalog(Path('/nonexistent'))
        cat._index = {('maven', 'a:b', '1.0'): {'status': 'predisclosure', 'build': 'b', 'cves': []}}
        findings = [{'component': {'ecosystem': 'maven', 'name': 'a:b', 'version': '1.0'}, 'vulns': [vuln('G', 'CVE-1')]}]
        out = scan.apply_coverage(findings, cat)
        self.assertIsNone(findings[0]['lightwell']['resolves'])
        self.assertFalse(findings[0]['vulns'][0]['lightwell_fixed'])
        self.assertEqual(out['issues_resolved'], 0)

    def test_not_checked_when_nothing_is_configured(self):
        findings = [{'component': {'ecosystem': 'maven', 'name': 'a:b', 'version': '1.0'}, 'vulns': [vuln('G', 'CVE-1')]}]
        out = scan.apply_coverage(findings, lightwell.make_catalog('live', DEMO))
        self.assertEqual((out['not_checked'], out['source'], out['sample']), (1, 'none', False))


def demo_scan(repo):
    return scan.scan_repository(repo, DemoRepos(DEMO / 'repos'), FixtureOsv(DEMO / 'osv.json'), lightwell.make_catalog('demo', DEMO))


class RecordedDataTests(unittest.TestCase):
    """The shipped sample catalog against the shipped recorded scans. Fails if either is edited out of step."""

    def test_the_example_vulnerable_apps_have_no_coverage_which_matches_the_live_catalog(self):
        for repo, issues, comps in (('appsecco/dvja', 33, 5), ('adeyosemanputra/pygoat', 348, 21)):
            lw = demo_scan(repo)['summary']['lightwell']
            self.assertEqual((lw['remediated'], lw['predisclosure'], lw['not_covered'] + lw['other_version'], lw['issues_resolved'], lw['issues_total']),
                             (0, 0, comps, 0, issues), repo)
            self.assertTrue(lw['sample'])


class RealRepoCoverageTests(unittest.TestCase):
    """Real public repositories whose pinned versions Lightwell does patch. Every number here was seen from the live
    API on the day the entries were added (2026-10-19), and the repositories were scanned live with the same result."""

    def covered(self, repo):
        r = demo_scan(repo)
        return r, {f['component']['name']: f['lightwell'] for f in r['findings'] if f['lightwell']['status'] == 'remediated'}

    def test_java_sec_code_has_partial_coverage(self):
        r, got = self.covered('JoyChou93/java-sec-code')
        lw = r['summary']['lightwell']
        self.assertEqual((lw['remediated'], lw['other_version'], lw['not_covered'], lw['issues_resolved'], lw['issues_total']), (4, 10, 17, 3, 158))
        self.assertEqual({k: v['build'] for k, v in got.items()},
                         {'com.thoughtworks.xstream:xstream': '1.4.20.rhlw-00001', 'commons-beanutils:commons-beanutils': '1.9.4.rhlw-00001',
                          'commons-net:commons-net': '3.6.0.rhlw-00001', 'org.apache.httpcomponents:httpclient': '4.5.12.rhlw-00001'})
        self.assertIsNone(got['commons-net:commons-net']['resolves'])         # a build exists, its CVEs are not itemised

    def test_junit_is_covered_in_both_the_github_and_the_gitlab_repository(self):
        for repo in ('snyk-labs/java-goof', 'gitlab.com/pdftk-java/pdftk'):
            r, got = self.covered(repo)
            self.assertEqual(list(got), ['junit:junit'], repo)
            self.assertEqual(got['junit:junit']['build'], '4.12.0.rhlw-00002', repo)
            self.assertEqual(r['summary']['lightwell']['issues_resolved'], 1, repo)
        self.assertEqual(demo_scan('gitlab.com/pdftk-java/pdftk')['summary']['lightwell']['issues_total'], 20)
        self.assertEqual(demo_scan('snyk-labs/java-goof')['summary']['lightwell']['issues_total'], 107)

    def test_the_gitlab_security_test_projects_have_no_coverage(self):
        for repo in ('gitlab.com/gitlab-org/security-products/tests/java-maven', 'gitlab.com/gitlab-org/security-products/tests/python-poetry'):
            lw = demo_scan(repo)['summary']['lightwell']
            self.assertEqual((lw['remediated'], lw['issues_resolved']), (0, 0), repo)


class SampleDetailTests(unittest.TestCase):
    """The sample catalog carries a snapshot of what the live detail endpoints returned, so demo mode shows the same view."""

    def finding(self, repo, name):
        r = demo_scan(repo)
        return next(f for f in r['findings'] if f['component']['name'].endswith(name))['lightwell']

    def test_every_sample_entry_has_detail(self):
        data = json.loads((DEMO / 'lightwell_catalog.json').read_text())
        for e in data['entries']:
            self.assertTrue(e['detail']['build']['version'], e['name'])
            self.assertEqual(e['detail']['repository']['security_level'], 'remediated', e['name'])

    def test_a_scan_gets_the_detail_matched_to_its_own_findings(self):
        lw = self.finding('JoyChou93/java-sec-code', 'xstream')
        adv = lw['detail']['advisories'][0]
        self.assertEqual((adv['cve'], adv['credited']), ('CVE-2024-47072', True))
        self.assertEqual(adv['osv']['id'].split('-')[0], 'GHSA')                       # matched to the OSV finding
        self.assertEqual(lw['detail']['build']['version'], '1.4.20.rhlw-00001')

    def test_lightwell_advisories_osv_did_not_flag_are_marked(self):
        det = self.finding('demojam/lightwell-coverage-demo', 'sqlparse')['detail']
        self.assertTrue(any(a['osv'] for a in det['advisories']))
        self.assertEqual([d['type'] for d in det['distributions']], ['sdist', 'bdist_wheel'])

    def test_a_newer_listed_build_is_visible_for_spring_core(self):
        det = self.finding('demojam/lightwell-coverage-demo', 'spring-core')['detail']
        self.assertEqual(det['build']['version'], '5.3.18.rhlw-00006')
        self.assertEqual(det['builds'][0]['build'], '5.3.18.rhlw-00010')                # the detail endpoint lists a newer build

    def test_scans_do_not_share_or_mutate_the_sample_detail(self):
        a = self.finding('JoyChou93/java-sec-code', 'xstream')['detail']
        b = self.finding('JoyChou93/java-sec-code', 'xstream')['detail']
        a['advisories'][0]['osv'] = 'changed'
        self.assertNotEqual(b['advisories'][0]['osv'], 'changed')
        data = json.loads((DEMO / 'lightwell_catalog.json').read_text())
        self.assertNotIn('osv', next(e for e in data['entries'] if e['name'].endswith('xstream') and e['version'] == '1.4.20')['detail']['advisories'][0])


class CoverageDemoRepoTests(unittest.TestCase):
    """demojam/lightwell-coverage-demo is built to show every coverage outcome."""

    def setUp(self):
        self.r = demo_scan('demojam/lightwell-coverage-demo')
        self.by = {f['component']['name'].split(':')[-1]: f['lightwell'] for f in self.r['findings']}

    def test_every_outcome_appears(self):
        s = {k: v['status'] for k, v in self.by.items()}
        self.assertEqual(s['postgresql'], 'remediated')
        self.assertEqual(s['struts2-core'], 'not_covered')
        self.assertEqual(s['django'], 'not_covered')
        lw = self.r['summary']['lightwell']
        self.assertEqual((lw['remediated'], lw['not_covered'], lw['issues_resolved'], lw['issues_total']), (11, 2, 33, 104))

    def test_full_partial_and_not_itemised_coverage(self):
        full = {k: (v['resolves'], v['of']) for k, v in self.by.items() if v['resolves'] == v['of']}
        self.assertEqual(full['postgresql'], (4, 4))
        self.assertEqual(full['log4j-core'], (4, 4))
        self.assertEqual(self.by['jackson-databind']['resolves'], 5)
        self.assertEqual(self.by['jackson-databind']['of'], 12)
        self.assertEqual((self.by['xstream']['resolves'], self.by['xstream']['of']), (3, 4))
        for name in ('snakeyaml', 'commons-compress', 'spring-core'):
            self.assertIsNone(self.by[name]['resolves'], name)           # a build exists, which CVEs it fixes is not known

    def test_the_build_names_follow_the_live_formats(self):
        self.assertEqual(self.by['jackson-databind']['build'], '2.13.4.rhlw-00027')
        self.assertEqual(self.by['sqlparse']['build'], '0.5.5+rhlw.1')
        self.assertEqual(self.by['snakeyaml']['build'], '1.30.0.rhlw-00013')       # Lightwell says 1.30.0, the manifest says 1.30

    def test_the_scan_says_it_is_constructed(self):
        self.assertTrue(any('Constructed demo application' in n for n in self.r['notes']))

    def test_the_sample_files_and_the_recording_agree(self):
        folder = DEMO.parent / 'samples' / 'lightwell-coverage-demo'
        recorded = json.loads((DEMO / 'repos' / 'demojam__lightwell-coverage-demo.json').read_text())['manifests']
        for name, text in recorded.items():
            self.assertEqual((folder / name).read_text(), text, f'{name} drifted from samples/')


class ImageProcessorDemoTests(unittest.TestCase):
    """sunil-samuel/Image-Processor has no manifest, so its demo data is reconstructed from the README.
    These pin down that it stays honest about that."""

    def setUp(self):
        self.r = scan.scan_repository('sunil-samuel/Image-Processor', DemoRepos(DEMO / 'repos'), FixtureOsv(DEMO / 'osv.json'),
                                      lightwell.make_catalog('demo', DEMO))

    def test_only_the_pinned_package_is_checked(self):
        self.assertEqual((self.r['status'], self.r['components'], self.r['unevaluated']), ('done', 1, 11))
        self.assertEqual([f['component']['name'] for f in self.r['findings']], ['transformers'])
        self.assertGreater(self.r['summary']['issues'], 0)

    def test_the_page_is_told_the_manifest_was_reconstructed(self):
        self.assertTrue(any('no dependency manifest' in n and 'README' in n for n in self.r['notes']))
        self.assertTrue(any('not pinned' in n for n in self.r['notes']))

    def test_no_coverage_is_claimed_for_it(self):
        self.assertEqual(self.r['findings'][0]['lightwell']['status'], 'not_covered')


if __name__ == '__main__':
    unittest.main()
