import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import osv                                                    # noqa: E402
from scanner.parse import Component                                        # noqa: E402


class CvssTests(unittest.TestCase):
    def test_known_scores(self):
        cases = {
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H': 9.8,
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H': 10.0,     # Log4Shell
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N': 5.3,
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H': 7.5,
            'CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N': 5.5,
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N': 0.0,
        }
        for vector, expected in cases.items():
            self.assertEqual(osv.cvss3_score(vector), expected, vector)

    def test_other_versions_are_not_scored(self):
        self.assertIsNone(osv.cvss3_score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'))
        self.assertIsNone(osv.cvss3_score('garbage'))

    def test_labels(self):
        self.assertEqual([osv.severity_label(x) for x in (9.8, 7.0, 4.0, 0.1, None)],
                         ['critical', 'high', 'moderate', 'low', 'unknown'])

    def test_vector_beats_database_label_and_label_is_the_fallback(self):
        v = {'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}],
             'database_specific': {'severity': 'LOW'}}
        self.assertEqual(osv.severity_of(v)[:2], ('critical', 9.8))
        self.assertEqual(osv.severity_of({'database_specific': {'severity': 'MODERATE'}})[:2], ('moderate', None))
        self.assertEqual(osv.severity_of({})[0], 'unknown')


class VersionTests(unittest.TestCase):
    def test_ordering(self):
        self.assertGreater(osv.vcmp('2.9.10', '2.9.9'), 0)
        self.assertLess(osv.vcmp('5.3.20', '5.3.21'), 0)
        self.assertLess(osv.vcmp('1.0.0-rc1', '1.0.0'), 0)
        self.assertEqual(osv.vcmp('1.0', '1.0.0'), 0)
        self.assertLess(osv.vcmp('1.0.0-beta', '1.0.0-rc1'), 0)

    VULN = {'affected': [{'package': {'ecosystem': 'Maven', 'name': 'a:b'}, 'ranges': [
        {'type': 'ECOSYSTEM', 'events': [{'introduced': '2.0.0'}, {'fixed': '2.12.7.1'}, {'introduced': '2.13.0'}, {'fixed': '2.13.4.2'}]}]},
        {'package': {'ecosystem': 'Maven', 'name': 'other:pkg'}, 'ranges': [{'type': 'ECOSYSTEM', 'events': [{'fixed': '9'}]}]}]}

    def test_fix_is_taken_from_the_branch_the_install_is_on(self):
        self.assertEqual(osv.fixed_versions(self.VULN, 'Maven', 'a:b', '2.13.1')[1], '2.13.4.2')
        self.assertEqual(osv.fixed_versions(self.VULN, 'Maven', 'a:b', '2.9.8')[1], '2.12.7.1')
        fixes, _ = osv.fixed_versions(self.VULN, 'Maven', 'a:b', '2.9.8')
        self.assertEqual(fixes, ['2.12.7.1', '2.13.4.2'])
        self.assertEqual(osv.fixed_versions(self.VULN, 'Maven', 'a:b', '3.0.0')[1], None)

    def test_pypi_names_are_normalised(self):
        v = {'affected': [{'package': {'ecosystem': 'PyPI', 'name': 'Flask_Login'}, 'ranges': [
            {'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '0.6.0'}]}]}]}
        self.assertEqual(osv.fixed_versions(v, 'PyPI', 'flask-login', '0.4.1')[1], '0.6.0')


class ClientTests(unittest.TestCase):
    def test_lookup_batches_then_fetches_details_once_per_id(self):
        calls = []

        def fake(service, url, **kw):
            calls.append((kw.get('method', 'GET'), url))
            if url.endswith('/v1/querybatch'):
                qs = kw['body']['queries']
                return {'results': [{'vulns': [{'id': 'GHSA-1'}]} if q['package']['name'] == 'a:b' else {} for q in qs]}, {}
            return {'id': 'GHSA-1', 'aliases': ['CVE-2020-1'], 'summary': 's', 'database_specific': {'severity': 'HIGH'},
                    'affected': []}, {}

        comps = [Component('maven', 'a:b', '1.0', 'pom.xml'), Component('maven', 'a:b', '1.0', 'other/pom.xml'),
                 Component('maven', 'c:d', '1.0', 'pom.xml'), Component('maven', 'e:f', None, 'pom.xml')]
        with mock.patch.object(osv, 'request', fake):
            out = osv.OsvClient().lookup(comps)
        self.assertEqual(len([c for c in calls if c[1].endswith('querybatch')]), 1)
        self.assertEqual(len([c for c in calls if '/v1/vulns/' in c[1]]), 1)
        self.assertEqual(out[('Maven', 'a:b', '1.0')][0]['cve'], 'CVE-2020-1')
        self.assertEqual(out[('Maven', 'c:d', '1.0')], [])
        self.assertNotIn(('Maven', 'e:f', None), out)

    def test_severity_is_borrowed_from_an_alias_and_slimming_keeps_the_answer(self):
        docs = {'PYSEC-1': {'id': 'PYSEC-1', 'aliases': ['CVE-2020-9', 'GHSA-aaaa'], 'summary': 's', 'details': 'first line\nsecond',
                            'affected': [{'package': {'ecosystem': 'PyPI', 'name': 'django', 'purl': 'x'}, 'versions': ['1'] * 500,
                                          'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '2.2.1'}]}]}]},
                'GHSA-aaaa': {'id': 'GHSA-aaaa', 'database_specific': {'severity': 'HIGH'},
                              'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}]}}
        asked = []

        def fake(service, url, **kw):
            asked.append(url.rsplit('/', 1)[-1])
            return docs[url.rsplit('/', 1)[-1]], {}

        with mock.patch.object(osv, 'request', fake):
            client = osv.RecordingOsv()
            doc = client._get_vuln('PYSEC-1')
        self.assertEqual(asked, ['PYSEC-1', 'GHSA-aaaa'])            # the CVE alias is not fetched
        self.assertEqual(osv.severity_of(doc)[:2], ('critical', 9.8))
        self.assertEqual(doc['_severity_from'], 'GHSA-aaaa')
        small = osv.slim(doc)
        self.assertNotIn('versions', small['affected'][0])
        self.assertEqual(osv._summarize(small, 'PyPI', 'django', '2.2.0'), osv._summarize(doc, 'PyPI', 'django', '2.2.0'))

    def test_pagination(self):
        pages = iter([{'vulns': [{'id': 'B'}], 'next_page_token': 't2'}, {'vulns': [{'id': 'C'}]}])

        def fake(service, url, **kw):
            if url.endswith('querybatch'):
                return {'results': [{'vulns': [{'id': 'A'}], 'next_page_token': 't1'}]}, {}
            return next(pages), {}

        with mock.patch.object(osv, 'request', fake):
            ids = osv.OsvClient().ids_for([('PyPI', 'x', '1')])
        self.assertEqual(ids[('PyPI', 'x', '1')], ['A', 'B', 'C'])


if __name__ == '__main__':
    unittest.main()
