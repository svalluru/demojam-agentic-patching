import json
import sys
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import lightwell, scan                                        # noqa: E402
from scanner.http import UpstreamError                                     # noqa: E402

SECRET = 'S3CRET-VALUE-DO-NOT-LEAK'
CLIENT = 'client-id-123'

LIVE = 'lightwell/java/remediated'
ROWS = [   # the shape the live API returns: Java has `release`, Python carries +rhlw.N in `version`
    {'group': 'org.apache.logging.log4j', 'name': 'log4j-core', 'version': '2.3', 'release': 'rhlw-00001', 'repository': LIVE},
    {'group': 'org.apache.logging.log4j', 'name': 'log4j-core', 'version': '2.3', 'release': 'rhlw-00003', 'repository': LIVE},
    {'group': 'org.apache.logging.log4j', 'name': 'log4j-core', 'version': '2.4', 'release': 'rhlw-00001', 'repository': LIVE},
    {'group': 'org.apache.logging.log4j', 'name': 'log4j-core', 'version': '2.23.0', 'release': None, 'repository': 'lightwell/java/validated'},
    {'group': 'org.someoneelse', 'name': 'log4j-core', 'version': '2.3', 'release': 'rhlw-00009', 'repository': LIVE},
    {'group': 'com.google.code.gson', 'name': 'gson', 'version': '2.8.1', 'release': 'rhlw-00001', 'repository': LIVE},
    {'group': 'com.google.code.gson', 'name': 'gson', 'version': '2.8.1', 'release': 'rhlw-00001-n0001', 'repository': 'lightwell/java/predisclosure'},
    {'group': 'com.google.code.gson', 'name': 'gson', 'version': '2.8.1', 'release': 'rhlw-00001-n0002', 'repository': 'lightwell/java/predisclosure'},
    {'group': None, 'name': 'pyyaml', 'version': '5.1+rhlw.2', 'release': None, 'repository': 'lightwell/python/remediated'},
    {'group': None, 'name': 'pyyaml', 'version': '6.0', 'release': None, 'repository': 'lightwell/python/validated'},
    {'group': 'x', 'name': 'docform', 'version': '1.0.rhlw-00001', 'release': None, 'repository': LIVE},
    {'group': None, 'name': 'sqlparse', 'version': '0.5.5+rhlw.1', 'release': None, 'repository': 'lightwell/python/remediated'},
    {'group': 'org.apache.commons', 'name': 'commons-compress', 'version': '1.9.0', 'release': 'rhlw-00005', 'repository': LIVE},   # Lightwell says 1.9.0
    {'group': 'com.fasterxml.jackson.core', 'name': 'jackson-databind', 'version': '2.13.4.1-rhlw-00015', 'release': None, 'repository': LIVE},
]
L4J = 'org.apache.logging.log4j:log4j-core'
ADVISORIES = [   # the live shape: package_name is the Maven coordinates (or the Python name), package_version is the upstream version
    {'advisory_id': 'x_RHLW-CVE-2021-44228-2.3', 'aliases': ['GHSA-jfh8-c2jp-5v3q', 'CVE-2021-44228'], 'fixed_versions': ['2.3.rhlw-00001'],
     'package_name': L4J, 'package_version': '2.3'},
    {'advisory_id': 'x_RHLW-CVE-2020-9488-2.3', 'aliases': ['CVE-2020-9488'], 'fixed_versions': ['2.3.rhlw-00003'],
     'package_name': L4J, 'package_version': '2.3'},
    {'advisory_id': 'x_RHLW-CVE-2099-0001-2.3', 'aliases': ['CVE-2099-0001'], 'fixed_versions': ['2.3.rhlw-00007'],        # newer than the newest listed (00003)
     'package_name': L4J, 'package_version': '2.3'},
    {'advisory_id': 'x_RHLW-CVE-2088-0001-2.8.1', 'aliases': ['CVE-2088-0001'], 'fixed_versions': ['2.8.1.rhlw-00009'],      # only a newer build
     'package_name': 'com.google.code.gson:gson', 'package_version': '2.8.1'},
    {'advisory_id': 'x_RHLW-CVE-2026-71491-0.5.5', 'aliases': ['GHSA-f2ff-p2ww-7p4p', 'PYSEC-2026-3697', 'CVE-2026-71491'],
     'fixed_versions': ['0.5.5+rhlw.1'], 'package_name': 'sqlparse', 'package_version': '0.5.5'},
]


class FakeService:
    """Stands in for scanner.lightwell.request and records what was asked."""

    def __init__(self, rows=ROWS, fail_token=None, fail_api=None):
        self.rows, self.fail_token, self.fail_api, self.calls = rows, fail_token, fail_api, []

    def __call__(self, service, url, **kw):
        self.calls.append((service, url, kw))
        if service == 'Red Hat SSO':
            if self.fail_token:
                raise self.fail_token
            return {'access_token': 'TOKEN-ABC', 'expires_in': 900}, {}
        if self.fail_api:
            raise self.fail_api
        parts = urllib.parse.urlparse(url)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(parts.query).items()}
        if parts.path.endswith('/repositories'):
            return {'data': [{}], 'meta': {'count': 7}}, {}
        # Confirmed against the live service (October 2026): the name filter is a case-insensitive substring match.
        if parts.path.endswith('/advisories'):
            rows = [a for a in ADVISORIES if a['package_name'] == q.get('package_name') and a['package_version'] == q.get('package_version')]
            off, lim = int(q.get('offset', 0)), int(q.get('limit', 100))
            return {'data': rows[off:off + lim], 'meta': {'count': len(rows), 'limit': lim, 'offset': off}}, {}
        rows = [r for r in self.rows if q.get('name', '').lower() in r['name'].lower()]
        off, lim = int(q.get('offset', 0)), int(q.get('limit', 100))
        return {'data': rows[off:off + lim], 'meta': {'count': len(rows), 'limit': lim, 'offset': off}}, {}

    def api_calls(self):
        return [c for c in self.calls if c[0] == 'Lightwell API']


def catalog(**kw):
    return lightwell.LightwellApiCatalog(CLIENT, SECRET, **kw)


def run(cat, svc, *args, **kw):
    with mock.patch.object(lightwell, 'request', svc):
        return cat.check(*args, **kw)


class CheckTests(unittest.TestCase):
    def test_remediated_and_the_cves_it_resolves(self):
        svc = FakeService()
        r = run(catalog(), svc, 'maven', L4J, '2.3')
        self.assertEqual((r['status'], r['build']), ('remediated', '2.3.rhlw-00003'))        # the newest of two builds of 2.3
        self.assertIn('CVE-2021-44228', r['cves'])
        self.assertIn('GHSA-jfh8-c2jp-5v3q', r['cves'])
        self.assertIn('CVE-2020-9488', r['cves'])
        self.assertNotIn('CVE-2099-0001', r['cves'])           # its fix is in rhlw-00007, newer than anything published

    def test_only_the_right_group_and_exact_version_count(self):
        r = run(catalog(), FakeService(), 'maven', 'org.apache.logging.log4j:log4j-core', '2.5')
        self.assertEqual(r['status'], 'not_covered')
        r = run(catalog(), FakeService(), 'maven', 'org.nobody:log4j-core', '2.3')            # same name, other group
        self.assertEqual(r['status'], 'not_covered')
        r = run(catalog(), FakeService(), 'maven', 'org.someoneelse:log4j-core', '2.3')
        self.assertEqual(r['build'], '2.3.rhlw-00009')
        self.assertEqual(run(catalog(), FakeService(), 'maven', 'org.apache.logging.log4j:log4j-core', '2.23.0')['status'],
                         'not_covered')                                              # a validated build is not a remediation

    def test_predisclosure_is_recognised_and_the_newest_build_wins(self):
        r = run(catalog(), FakeService(), 'maven', 'com.google.code.gson:gson', '2.8.1')
        self.assertEqual((r['status'], r['build']), ('predisclosure', '2.8.1.rhlw-00001-n0002'))

    def test_the_documented_suffix_form_inside_version_is_accepted_too(self):
        r = run(catalog(), FakeService(), 'maven', 'x:docform', '1.0')
        self.assertEqual((r['status'], r['build']), ('remediated', '1.0.rhlw-00001'))

    def test_python_names_are_normalised_and_use_the_python_ecosystem(self):
        svc = FakeService()
        r = run(catalog(), svc, 'pypi', 'pyyaml', '5.1')
        self.assertEqual((r['status'], r['build']), ('remediated', '5.1+rhlw.2'))            # Python's local-version form
        self.assertIn('ecosystem=python', svc.api_calls()[0][1])
        self.assertEqual(run(catalog(), FakeService(), 'pypi', 'pyyaml', '6.0')['status'], 'not_covered')   # validated only

    def test_unsupported_ecosystem(self):
        self.assertEqual(run(catalog(), FakeService(), 'cargo', 'x', '1')['status'], 'not_checked')

    def test_an_advisory_that_names_only_a_newer_build_is_not_credited(self):
        r = run(catalog(), FakeService(), 'maven', 'com.google.code.gson:gson', '2.8.1')
        self.assertEqual(r['cves'], [])
        self.assertIn('newer build (2.8.1.rhlw-00009)', r['note'])

    def test_no_advisory_means_not_itemised_not_that_it_fixes_nothing(self):
        r = run(catalog(), FakeService(), 'maven', 'x:docform', '1.0')
        self.assertEqual((r['status'], r['cves']), ('remediated', []))
        self.assertIn('not itemised', r['note'])

    def test_python_advisories_are_matched_by_name(self):
        r = run(catalog(), FakeService(), 'pypi', 'SQLParse', '0.5.5')
        self.assertEqual((r['status'], r['build']), ('remediated', '0.5.5+rhlw.1'))
        self.assertIn('CVE-2026-71491', r['cves'])
        self.assertIn('PYSEC-2026-3697', r['cves'])

    def test_lightwell_writing_1_9_0_matches_maven_central_saying_1_9(self):
        r = run(catalog(), FakeService(), 'maven', 'org.apache.commons:commons-compress', '1.9')
        self.assertEqual((r['status'], r['build']), ('remediated', '1.9.0.rhlw-00005'))
        self.assertEqual(run(catalog(), FakeService(), 'maven', 'org.apache.commons:commons-compress', '1.90')['status'], 'not_covered')

    def test_the_hyphen_suffix_form_is_recognised(self):
        r = run(catalog(), FakeService(), 'maven', 'com.fasterxml.jackson.core:jackson-databind', '2.13.4.1')
        self.assertEqual((r['status'], r['build']), ('remediated', '2.13.4.1-rhlw-00015'))

    def test_a_package_is_listed_once_however_many_versions_are_asked_about(self):
        svc = FakeService()
        cat = catalog()
        for v in ('2.3', '2.4', '2.5'):
            run(cat, svc, 'maven', 'org.apache.logging.log4j:log4j-core', v)
        # one package listing, plus one advisory lookup for each of the two versions that have a build
        self.assertEqual(len([c for c in svc.api_calls() if '/package_versions' in c[1]]), 1)

    def test_pagination(self):
        svc = FakeService()
        with mock.patch.object(lightwell, 'PAGE', 2):
            r = run(catalog(), svc, 'maven', 'com.google.code.gson:gson', '2.8.1')
        self.assertEqual(r['status'], 'predisclosure')
        self.assertEqual(len([c for c in svc.api_calls() if '/package_versions' in c[1]]), 2)      # three gson rows at two a page

    def test_a_build_whose_advisories_cannot_be_itemised_is_not_credited(self):
        class Flaky(FakeService):
            def __call__(self, service, url, **kw):
                if '/advisories' in url:
                    raise UpstreamError('Lightwell API', 'HTTP 503', 503)
                return super().__call__(service, url, **kw)
        cat = catalog()
        r = run(cat, Flaky(), 'maven', L4J, '2.3')
        self.assertEqual((r['status'], r['cves']), ('remediated', []))
        self.assertIn('itemised', r['note'])


class TokenTests(unittest.TestCase):
    def test_token_is_requested_with_the_service_account_and_reused(self):
        svc = FakeService()
        cat = catalog()
        run(cat, svc, 'maven', 'org.apache.logging.log4j:log4j-core', '2.3')
        run(cat, svc, 'pypi', 'pyyaml', '5.1')
        sso = [c for c in svc.calls if c[0] == 'Red Hat SSO']
        self.assertEqual(len(sso), 1)
        self.assertEqual(sso[0][2]['form'], {'grant_type': 'client_credentials', 'client_id': CLIENT, 'client_secret': SECRET,
                                             'scope': 'api.console'})
        self.assertEqual(svc.api_calls()[0][2]['headers'], {'Authorization': 'Bearer TOKEN-ABC'})

    def test_an_expiring_token_is_replaced(self):
        svc = FakeService()
        cat = catalog()
        with mock.patch.object(lightwell.time, 'time', return_value=1000.0):
            run(cat, svc, 'pypi', 'pyyaml', '5.1')
        with mock.patch.object(lightwell.time, 'time', return_value=1000.0 + 900 - 30):       # inside the safety margin
            run(cat, svc, 'maven', 'com.google.code.gson:gson', '2.8.1')
        self.assertEqual(len([c for c in svc.calls if c[0] == 'Red Hat SSO']), 2)


class FailureTests(unittest.TestCase):
    def test_a_refused_token_stops_further_calls_and_says_what_to_check(self):
        svc = FakeService(fail_api=UpstreamError('Lightwell API', 'HTTP 401 for x', 401))
        cat = catalog()
        first = run(cat, svc, 'pypi', 'pyyaml', '5.1')
        n = len(svc.calls)
        second = run(cat, svc, 'maven', 'com.google.code.gson:gson', '2.8.1')
        self.assertEqual((first['status'], second['status']), ('not_checked', 'not_checked'))
        self.assertIn('Repositories viewer', first['note'])
        self.assertEqual(len(svc.calls), n)                                # it did not keep asking

    def test_forbidden(self):
        r = run(catalog(), FakeService(fail_api=UpstreamError('Lightwell API', 'HTTP 403', 403)), 'pypi', 'pyyaml', '5.1')
        self.assertEqual(r['status'], 'not_checked')
        self.assertIn('membership', r['note'])

    def test_rejected_credentials_never_leak_the_secret_anywhere(self):
        svc = FakeService(fail_token=UpstreamError('Red Hat SSO', 'HTTP 401 for https://sso.example/token', 401))
        cat = catalog()
        r = run(cat, svc, 'pypi', 'pyyaml', '5.1')
        with mock.patch.object(lightwell, 'request', svc):
            st = cat.status()
        everything = json.dumps([r, cat.describe(), st, cat.error])
        self.assertNotIn(SECRET, everything)
        self.assertNotIn(CLIENT, everything)
        self.assertIn('rejected', r['note'])
        self.assertFalse(st['ok'])

    def test_status_reports_how_many_repositories_are_visible(self):
        cat = catalog()
        with mock.patch.object(lightwell, 'request', FakeService()):
            st = cat.status()
        self.assertTrue(st['ok'])
        self.assertIn('7 repositories', st['detail'])
        self.assertNotIn(SECRET, json.dumps(st))

    def test_network_failure_is_not_checked_not_a_crash(self):
        r = run(catalog(), FakeService(fail_api=UpstreamError('Lightwell API', 'could not reach x')), 'pypi', 'pyyaml', '5.1')
        self.assertEqual(r['status'], 'not_checked')


class DemoFlagAndFactoryTests(unittest.TestCase):
    def test_demo_flag_goes_on_package_queries_only(self):
        svc = FakeService()
        cat = catalog(demo=True)
        run(cat, svc, 'pypi', 'pyyaml', '5.1')
        with mock.patch.object(lightwell, 'request', svc):
            cat.status()
        urls = [c[1] for c in svc.api_calls()]
        self.assertIn('demo=true', urls[0])
        self.assertNotIn('demo=', urls[-1])                                # /repositories

    def test_factory(self):
        d = Path(__file__).resolve().parents[1] / 'demo'
        none = lambda k, default='': default
        have = {'LIGHTWELL_CLIENT_ID': CLIENT, 'LIGHTWELL_CLIENT_SECRET': SECRET, 'LIGHTWELL_API_DEMO': 'true',
                'LIGHTWELL_API_BASE': 'https://example.test/api/'}.get
        self.assertIsInstance(lightwell.make_catalog('demo', d, have), lightwell.FixtureCatalog)
        self.assertIsInstance(lightwell.make_catalog('live', d, none), lightwell.UnconfiguredCatalog)
        half = {'LIGHTWELL_CLIENT_ID': CLIENT}.get
        self.assertIsInstance(lightwell.make_catalog('live', d, lambda k, default='': half(k, default)), lightwell.UnconfiguredCatalog)
        cat = lightwell.make_catalog('live', d, lambda k, default='': have(k, default))
        self.assertIsInstance(cat, lightwell.LightwellApiCatalog)
        self.assertTrue(cat.demo)
        self.assertEqual(cat.base, 'https://example.test/api')
        self.assertEqual(cat.describe()['source'], 'api')


class ScanIntegrationTests(unittest.TestCase):
    def test_apply_coverage_uses_the_api_answer(self):
        vuln = lambda vid, cve: {'id': vid, 'cve': cve, 'aliases': [], 'severity': 'high', 'score': 7.5, 'fixed_versions': [],
                                 'suggested_fix': None, 'url': '', 'summary': '', 'vector': '', 'published': '', 'references': []}
        findings = [{'component': {'ecosystem': 'maven', 'name': L4J, 'version': '2.3'},
                     'vulns': [vuln('GHSA-1', 'CVE-2021-44228'), vuln('GHSA-2', 'CVE-2021-45046'), vuln('GHSA-3', 'CVE-2020-9488')]}]
        with mock.patch.object(lightwell, 'request', FakeService()):
            out = scan.apply_coverage(findings, catalog())
        self.assertEqual([v['lightwell_fixed'] for v in findings[0]['vulns']], [True, False, True])
        self.assertEqual((out['remediated'], out['issues_resolved'], out['issues_total'], out['source'], out['sample']),
                         (1, 2, 3, 'api', False))


UUID = 'aaaaaaaa-0000-0000-0000-000000000001'
DETAIL_ROWS = [dict(r, repository_uuid=UUID, created_at='2026-10-12T00:00:00Z') for r in ROWS]    # when the row was listed
REPO_FACTS = {'name': LIVE, 'uuid': UUID, 'security_level': 'remediated', 'content_type': 'maven', 'build_count': 2749,
              'advisory_count': 272, 'package_count': 964, 'feature_name': 'lightwell-network,lightwell-clearinghouse',
              'published_distribution_url': 'https://packages.example.test/java/remediated/'}
L4J_BUILDS = {'group': 'org.apache.logging.log4j', 'name': 'log4j-core', 'version': '2.3.rhlw-00003', 'author': 'The Apache Software Foundation',
              'license': '', 'project_url': '', 'builds': [{'version': '2.3', 'release': 'rhlw-00001', 'created_at': '2026-08-01T10:00:00Z'},
                                                           {'version': '2.3', 'release': 'rhlw-00003', 'created_at': '2026-08-04T10:00:00Z'},
                                                           {'version': '2.3', 'release': 'rhlw-00007', 'created_at': '2026-09-01T10:00:00Z'}]}
SQLPARSE = {'name': 'sqlparse', 'version': '0.5.5+rhlw.1', 'author': {'name': 'Andi Albrecht', 'email': 'private@example.test'},
            'distributions': [{'filename': 'sqlparse-0.5.5+rhlw.1.tar.gz', 'packagetype': 'sdist', 'size': 124657, 'sha256': 'ab' * 32,
                               'created_at': '2026-10-13T20:36:11Z'}]}


class DetailService(FakeService):
    """FakeService plus the three endpoints the detail view uses. `detail_fail` makes only those raise."""

    def __init__(self, detail_fail=None, **kw):
        super().__init__(rows=DETAIL_ROWS, **kw)
        self.detail_fail = detail_fail

    def __call__(self, service, url, **kw):
        path = urllib.parse.urlparse(url).path
        if service == 'Lightwell API' and ('/maven_packages/' in path or '/python_packages/' in path or path.endswith('/repositories')):
            self.calls.append((service, url, kw))
            if self.detail_fail:
                raise self.detail_fail
            if path.endswith('/repositories'):
                return {'data': [{'name': 'someone/else'}, REPO_FACTS], 'meta': {'count': 2}}, {}
            if '/maven_packages/' in path:
                return L4J_BUILDS, {}
            return SQLPARSE, {}
        return super().__call__(service, url, **kw)


class DetailTests(unittest.TestCase):
    def test_the_detail_carries_what_the_extra_endpoints_say(self):
        r = run(catalog(), DetailService(), 'maven', L4J, '2.3')
        d = r['detail']
        self.assertEqual((r['status'], r['build']), ('remediated', '2.3.rhlw-00003'))
        self.assertEqual(d['repository']['build_count'], 2749)
        self.assertEqual(d['repository']['features'], ['lightwell-network', 'lightwell-clearinghouse'])
        self.assertEqual([b['build'] for b in d['builds']], ['2.3.rhlw-00007', '2.3.rhlw-00003', '2.3.rhlw-00001'])    # newest first
        self.assertEqual(d['build']['created_at'], '2026-08-04T10:00:00Z')            # the build's own date, not when the row was listed
        self.assertEqual(d['build']['listed_at'], '2026-10-12T00:00:00Z')
        self.assertEqual(d['author'], 'The Apache Software Foundation')
        self.assertNotIn('license', d)                                                  # empty values are left out, not shown blank
        self.assertNotIn('project_url', d)

    def test_each_advisory_says_whether_this_build_is_credited(self):
        by_id = {a['id']: a for a in run(catalog(), DetailService(), 'maven', L4J, '2.3')['detail']['advisories']}
        self.assertTrue(by_id['x_RHLW-CVE-2021-44228-2.3']['credited'])
        self.assertEqual(by_id['x_RHLW-CVE-2021-44228-2.3']['fixed_in'], '2.3.rhlw-00001')
        self.assertFalse(by_id['x_RHLW-CVE-2099-0001-2.3']['credited'])                 # fixed only in 00007, newer than the build matched
        self.assertEqual(by_id['x_RHLW-CVE-2099-0001-2.3']['fixed_in'], '2.3.rhlw-00007')

    def test_python_detail_lists_the_distribution_files_and_drops_the_email(self):
        d = run(catalog(), DetailService(), 'pypi', 'sqlparse', '0.5.5')['detail']
        self.assertEqual(d['author'], 'Andi Albrecht')
        self.assertNotIn('private@example.test', json.dumps(d))
        self.assertEqual(d['distributions'], [{'filename': 'sqlparse-0.5.5+rhlw.1.tar.gz', 'type': 'sdist', 'size': 124657,
                                               'sha256': 'ab' * 32, 'created_at': '2026-10-13T20:36:11Z'}])

    def test_the_python_build_is_asked_for_by_its_full_version_with_the_plus_encoded(self):
        svc = DetailService()
        run(catalog(), svc, 'pypi', 'sqlparse', '0.5.5')
        urls = [c[1] for c in svc.api_calls() if '/python_packages/' in c[1]]
        self.assertEqual(len(urls), 1)
        self.assertTrue(urls[0].endswith('/python_packages/sqlparse/0.5.5%2Brhlw.1'), urls[0])
        self.assertIn(UUID, urls[0])

    def test_a_failing_detail_call_never_changes_the_coverage_answer_or_the_credentials(self):
        for err in (UpstreamError('Lightwell API', 'HTTP 500', 500), UpstreamError('Lightwell API', 'access refused (HTTP 403)', 403),
                    UpstreamError('Lightwell API', 'bad request', 400)):
            cat = catalog()
            r = run(cat, DetailService(detail_fail=err), 'maven', L4J, '2.3')
            self.assertEqual((r['status'], r['build']), ('remediated', '2.3.rhlw-00003'), err.status)
            self.assertIn('CVE-2021-44228', r['cves'])
            self.assertEqual((cat._refused, cat.error), ('', ''), err.status)             # nothing marked as refused
            self.assertEqual(r['detail']['build']['version'], '2.3.rhlw-00003')
            self.assertNotIn('builds', r['detail'])
            self.assertEqual(run(cat, DetailService(), 'maven', 'com.google.code.gson:gson', '2.8.1')['status'], 'predisclosure')

    def test_repository_facts_are_fetched_once_per_repository(self):
        svc, cat = DetailService(), catalog()
        run(cat, svc, 'maven', L4J, '2.3')
        run(cat, svc, 'maven', 'org.apache.logging.log4j:log4j-core', '2.4')
        self.assertEqual(len([c for c in svc.api_calls() if c[1].split('?')[0].endswith('/repositories')]), 1)

    def test_not_covered_makes_no_detail_calls(self):
        svc = DetailService()
        r = run(catalog(), svc, 'maven', 'org.nobody:thing', '1.0')
        self.assertEqual(r['status'], 'not_covered')
        self.assertNotIn('detail', r)
        self.assertFalse([c for c in svc.api_calls() if '/maven_packages/' in c[1] or c[1].split('?')[0].endswith('/repositories')])

    def test_the_number_of_extra_lookups_is_capped_and_the_answer_survives(self):
        with mock.patch.object(lightwell, 'MAX_DETAIL_CALLS', 0):
            r = run(catalog(), DetailService(), 'maven', L4J, '2.3')
        self.assertEqual((r['status'], r['build']), ('remediated', '2.3.rhlw-00003'))
        self.assertIn('limit', r['detail']['note'])


class MatchDetailTests(unittest.TestCase):
    VULN = {'id': 'GHSA-jfh8-c2jp-5v3q', 'cve': 'CVE-2021-44228', 'aliases': ['CVE-2021-44228'], 'severity': 'critical', 'score': 10.0}

    def detail(self):
        return {'advisories': [{'id': 'x_RHLW-CVE-2021-44228-2.3', 'cve': 'CVE-2021-44228', 'aliases': ['GHSA-jfh8-c2jp-5v3q', 'CVE-2021-44228'], 'score': 9.9},
                               {'id': 'x_RHLW-CVE-2000-1-2.3', 'cve': 'CVE-2000-1', 'aliases': [], 'score': 5.0}]}

    def test_lightwell_advisories_are_matched_to_osv_findings_or_marked_unflagged(self):
        vuln = dict(self.VULN)
        out = scan._match_detail(self.detail(), [vuln])
        self.assertEqual(out['advisories'][0]['osv'], {'id': 'GHSA-jfh8-c2jp-5v3q', 'severity': 'critical', 'score': 10.0})
        self.assertIsNone(out['advisories'][1]['osv'])
        self.assertEqual(vuln['lightwell_severity'], 9.9)

    def test_it_works_on_a_copy_because_the_sample_catalog_shares_one_dict(self):
        shared = self.detail()
        scan._match_detail(shared, [dict(self.VULN)])
        self.assertNotIn('osv', shared['advisories'][0])

    def advisory_detail(self, **adv):
        base = {'id': 'x_RHLW-CVE-2021-44228-2.3', 'cve': 'CVE-2021-44228', 'aliases': [], 'published': '2021-12-10T00:00:00Z',
                'fixed_in': '2.3.rhlw-00003', 'credited': True}
        return {'build': {'version': '2.3.rhlw-00003', 'created_at': '2021-12-25T10:00:00Z'},
                'builds': [{'build': '2.3.rhlw-00001', 'created_at': '2021-12-12T10:00:00Z'}, {'build': '2.3.rhlw-00003', 'created_at': '2021-12-25T10:00:00Z'}],
                'advisories': [{**base, **adv}]}

    def test_lead_time_is_days_from_publication_to_the_fixing_build(self):
        a = scan._match_detail(self.advisory_detail(), [])['advisories'][0]
        self.assertEqual((a['lead_days'], a['fix_built']), (15, '2021-12-25'))
        a = scan._match_detail(self.advisory_detail(fixed_in='2.3.rhlw-00001'), [])['advisories'][0]
        self.assertEqual(a['lead_days'], 2)                      # the advisory's own fixing build, not the newest one matched

    def test_a_build_dated_before_the_advisory_gives_a_negative_lead_time(self):
        a = scan._match_detail(self.advisory_detail(published='2022-01-05T00:00:00Z'), [])['advisories'][0]
        self.assertEqual(a['lead_days'], -11)

    def test_no_lead_time_when_not_credited_or_a_date_is_missing(self):
        for adv in ({'credited': False}, {'published': ''}, {'fixed_in': ''}):
            self.assertNotIn('lead_days', scan._match_detail(self.advisory_detail(**adv), [])['advisories'][0], adv)


class CatalogViewTests(unittest.TestCase):
    def check(self, name, version, rows=ROWS):
        svc = FakeService(rows)
        with mock.patch.object(lightwell, 'request', svc):
            return catalog().check('maven', name, version), svc

    def test_package_facts_split_remediated_from_validated_and_never_count_validated(self):
        facts = lightwell.package_facts([r for r in ROWS if r['name'] == 'log4j-core' and r['group'] == 'org.apache.logging.log4j'])
        self.assertEqual([(x['version'], x['build']) for x in facts['remediated']], [('2.3', '2.3.rhlw-00003'), ('2.4', '2.4.rhlw-00001')])
        self.assertEqual(facts['validated'], ['2.23.0'])

    def test_view_names_the_nearest_remediated_version_above_the_installed_one(self):
        facts = lightwell.package_facts([r for r in ROWS if r['name'] == 'log4j-core' and r['group'] == 'org.apache.logging.log4j'])
        self.assertEqual(lightwell.package_view(facts, '2.3')['nearest'], {'version': '2.4', 'build': '2.4.rhlw-00001'})
        self.assertIsNone(lightwell.package_view(facts, '2.4')['nearest'])
        self.assertEqual(lightwell.package_view(facts, '2.0')['nearest']['version'], '2.3')
        self.assertTrue(lightwell.package_view(facts, '2.23.0')['exact_validated'])
        self.assertFalse(lightwell.package_view(facts, '2.3')['exact_validated'])

    def test_a_long_list_is_capped_but_keeps_the_nearest_version_and_the_totals(self):
        rows = [{'group': 'g', 'name': 'n', 'version': f'1.{i}', 'release': 'rhlw-00001', 'repository': LIVE} for i in range(40)]
        v = lightwell.package_view(lightwell.package_facts(rows), '1.20')
        self.assertEqual((len(v['remediated']), v['remediated_total']), (lightwell.MAX_VERSIONS, 40))
        self.assertEqual(v['nearest']['version'], '1.21')
        self.assertIn('1.21', [x['version'] for x in v['remediated']])
        self.assertIn('1.20', [x['version'] for x in v['remediated']])

    def test_check_attaches_the_package_view_for_covered_and_uncovered_versions_with_no_extra_calls(self):
        r, svc = self.check(L4J, '2.3')
        self.assertEqual((r['status'], r['versions']['nearest']['version']), ('remediated', '2.4'))
        r, svc = self.check(L4J, '9.9')
        self.assertEqual((r['status'], r['versions']['remediated_total'], r['versions']['nearest']), ('not_covered', 2, None))
        self.assertEqual(len(svc.api_calls()), 1)                # the one package_versions list that was already being made

    def test_a_package_lightwell_does_not_carry_says_so(self):
        r, _ = self.check('org.nobody:nothing', '1.0')
        self.assertEqual((r['status'], r['versions']['carried']), ('not_covered', False))

    def test_a_validated_version_is_not_coverage(self):
        r, _ = self.check(L4J, '2.23.0')
        self.assertEqual(r['status'], 'not_covered')
        self.assertTrue(r['versions']['exact_validated'])

    def test_apply_coverage_carries_the_view_and_the_worst_lead_time(self):
        class Cat:
            source, sample = 'api', False

            def check(self, eco, name, version, cves=None):
                return {'status': 'remediated', 'build': '2.3.rhlw-00003', 'cves': ['CVE-2021-44228'], 'embargo_days': None, 'note': '',
                        'versions': {'carried': True}, 'detail': MatchDetailTests().advisory_detail()}

            def facts(self):
                return {'repositories': [{'name': 'r'}]}
        f = {'component': {'ecosystem': 'maven', 'name': L4J, 'version': '2.3'}, 'vulns': [{'id': 'GHSA-x', 'cve': 'CVE-2021-44228', 'aliases': [], 'severity': 'critical', 'score': 10.0}]}
        out = scan.apply_coverage([f], Cat())
        self.assertEqual((f['lightwell']['versions'], f['lightwell']['lead_days']), ({'carried': True}, 15))
        self.assertEqual(out['catalog'], {'repositories': [{'name': 'r'}]})


class CatalogFactsTests(unittest.TestCase):
    class Repos(FakeService):
        def __call__(self, service, url, **kw):
            if service == 'Lightwell API' and urllib.parse.urlparse(url).path.endswith('/repositories'):
                self.calls.append((service, url, kw))
                return {'data': [{'name': 'lightwell/java/remediated', 'security_level': 'remediated', 'build_count': 5, 'secret_field': 'x'},
                                 {'name': 'lightwell/java/validated-demo', 'security_level': 'validated'}], 'meta': {'count': 2}}, {}
            return super().__call__(service, url, **kw)

    def test_facts_list_repositories_without_the_demo_ones_and_ask_once(self):
        svc, cat = self.Repos(), catalog()
        with mock.patch.object(lightwell, 'request', svc):
            first, second = cat.facts(), cat.facts()
        self.assertEqual(first, {'repositories': [{'name': 'lightwell/java/remediated', 'security_level': 'remediated', 'build_count': 5}]})
        self.assertIs(first, second)
        self.assertEqual(len(svc.api_calls()), 1)

    def test_a_failure_leaves_the_panel_out_and_does_not_mark_the_credentials_refused(self):
        svc, cat = FakeService(fail_api=UpstreamError('Lightwell API', 'HTTP 403', 403)), catalog()
        with mock.patch.object(lightwell, 'request', svc):
            self.assertIsNone(cat.facts())
        self.assertEqual(cat._refused, '')


if __name__ == '__main__':
    unittest.main()
