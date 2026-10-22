import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import parse, ranges, scan                                    # noqa: E402
from scanner.repo import RepoSnapshot                                      # noqa: E402


class LowerBoundTests(unittest.TestCase):
    CASES = {
        'maven': {
            '[1.0,2.0)': ('1.0', False), '(1.0,2.0)': ('1.0', True), '[1.0]': ('1.0', False), '[1.0,)': ('1.0', False),
            '[1.0,2.0),[3.0,)': ('1.0', False), '1.+': ('1', False), '1.2.+': ('1.2', False),
            '(,2.0)': None, '(,1.0],[1.2,)': None, '+': None, 'latest.release': None, '1.0': None, '': None},
        'pep440': {
            '>=2.0': ('2.0', False), '>2.0': ('2.0', True), '~=2.0': ('2.0', False), '==2.*': ('2', False), '==2.0.*': ('2.0', False),
            '>=1.0,<2.0': ('1.0', False), '>=1.0,>=1.5': ('1.5', False), '>=1.0, !=1.2': ('1.0', False),
            '<2.0': None, '!=1.5': None, '*': None, '': None},
        'poetry': {
            '^1.2.3': ('1.2.3', False), '~1.2': ('1.2', False), '1.*': ('1', False), '>=1.0,<2.0': ('1.0', False),
            '^1.0 || ^2.0': ('1.0', False), '*': None, '<2': None},
        'npm': {
            '^1.2.3': ('1.2.3', False), '~1.2': ('1.2.0', False), '>=1.0.0 <2.0.0': ('1.0.0', False), '>= 1.0.0': ('1.0.0', False),
            '1.x': ('1.0.0', False), '1.2.x': ('1.2.0', False), '>1.0.0': ('1.0.0', True), '1.2.3 - 2.3.4': ('1.2.3', False),
            '^1.0.0 || ^2.0.0': ('1.0.0', False), 'v1.2.3': ('1.2.3', False),
            '*': None, 'x': None, 'latest': None, 'next': None, '<2.0.0': None, 'git+https://example.test/a/b.git': None, 'github:a/b': None,
            'file:../x': None}}

    def test_every_syntax(self):
        for syntax, cases in self.CASES.items():
            for spec, want in cases.items():
                self.assertEqual(ranges.lower_bound(syntax, spec), want, f'{syntax} {spec!r}')

    def test_an_unknown_syntax_gives_nothing(self):
        self.assertIsNone(ranges.lower_bound('cobol', '>=1.0'))


class ParserTests(unittest.TestCase):
    def comps(self, path, text, on):
        c, n = parse.parse_manifest(path, text, ranges=on)
        return {x.name: x for x in c}, ' '.join(n)

    def test_requirements(self):
        text = 'requests>=2.0\nflask==1.0\nnumpy\nurllib3<2\ndjango>2.0\n'
        off, notes = self.comps('requirements.txt', text, False)
        self.assertEqual((off['requests'].version, off['requests'].declared, off['flask'].version), (None, '>=2.0', '1.0'))      # declared is kept, the version is not looked up
        self.assertIn('not pinned with ==', notes)
        on, notes = self.comps('requirements.txt', text, True)
        self.assertEqual((on['requests'].version, on['requests'].declared, on['flask'].version, on['flask'].declared), ('2.0', '>=2.0', '1.0', ''))
        self.assertEqual((on['numpy'].version, on['urllib3'].version), (None, None))
        self.assertEqual((on['django'].version, on['django'].exclusive, on['requests'].exclusive), ('2.0', True, False))
        self.assertIn('lowest version each range allows', notes)
        self.assertIn('1 ranges have no lower bound', notes)
        self.assertIn('1 requirements are not pinned with ==', notes)                    # numpy has no range at all
        self.assertIn('just above', on['django'].note)

    def test_pyproject_both_styles(self):
        text = ('[project]\ndependencies = ["django>=3.2", "pillow==9.0.0"]\n[project.optional-dependencies]\ndev = ["pytest~=7.0"]\n'
                '[tool.poetry.dependencies]\npython = "^3.9"\nrequests = "^2.20"\nflask = {version = ">=1.0,<2"}\nrich = "13.0.0"\nanything = "*"\n')
        on, notes = self.comps('pyproject.toml', text, True)
        self.assertEqual({k: v.version for k, v in on.items()}, {'django': '3.2', 'pillow': '9.0.0', 'pytest': '7.0', 'requests': '2.20', 'flask': '1.0', 'rich': '13.0.0', 'anything': None})
        self.assertEqual(on['pytest'].scope, 'dev')
        self.assertIn('1 ranges have no lower bound', notes)
        off, _ = self.comps('pyproject.toml', text, False)
        self.assertIsNone(off['django'].version)
        self.assertIsNone(off['requests'].version)

    def test_a_dependency_with_no_version_at_all_still_gets_its_own_note(self):
        on, notes = self.comps('pyproject.toml', '[project]\ndependencies = ["flask", "django>=3.2"]\n', True)
        self.assertEqual((on['flask'].version, on['django'].version), (None, '3.2'))
        self.assertIn('1 dependencies with no version at all are not evaluated', notes)
        self.assertNotIn('given as ranges are not evaluated', notes)

    def test_package_json(self):
        text = json.dumps({'dependencies': {'lodash': '^4.17.0', 'left-pad': '1.3.0', 'any': '*'}, 'devDependencies': {'jest': '~29.1'}})
        on, notes = self.comps('package.json', text, True)
        self.assertEqual({k: v.version for k, v in on.items()}, {'lodash': '4.17.0', 'left-pad': '1.3.0', 'any': None, 'jest': '29.1.0'})
        self.assertEqual(on['jest'].declared, '~29.1')
        off, _ = self.comps('package.json', text, False)
        self.assertIsNone(off['lodash'].version)

    def test_gradle_including_the_old_behaviour(self):
        text = "dependencies {\n  implementation 'g:a:1.+'\n  implementation \"g:b:[1.0,2.0)\"\n  implementation 'g:c:2.0'\n  testImplementation 'g:d:(,3.0)'\n}"
        on, notes = self.comps('build.gradle', text, True)
        self.assertEqual({k: v.version for k, v in on.items()}, {'g:a': '1', 'g:b': '1.0', 'g:c': '2.0', 'g:d': None})
        self.assertIn('group:artifact:version', notes)
        off, _ = self.comps('build.gradle', text, False)
        self.assertEqual({k: v.version for k, v in off.items()}, {'g:a': '1.+', 'g:c': '2.0'})            # as before: the bracket forms are not read

    def test_pom_version_ranges(self):
        text = ('<project xmlns="http://maven.apache.org/POM/4.0.0"><groupId>x</groupId><artifactId>y</artifactId><version>1</version><dependencies>'
                '<dependency><groupId>g</groupId><artifactId>a</artifactId><version>[1.0,2.0)</version></dependency>'
                '<dependency><groupId>g</groupId><artifactId>b</artifactId><version>(,2.0)</version></dependency></dependencies></project>')
        on, notes = self.comps('pom.xml', text, True)
        self.assertEqual((on['g:a'].version, on['g:a'].declared, on['g:b'].version), ('1.0', '[1.0,2.0)', None))
        self.assertIn('1 ranges have no lower bound', notes)
        self.assertIsNone(self.comps('pom.xml', text, False)[0]['g:a'].version)

    def test_lock_files_are_untouched(self):
        lock = '[[package]]\nname = "idna"\nversion = "3.4"\n'
        comps, _ = parse.parse_manifest('poetry.lock', lock, ranges=True)
        self.assertEqual([(c.version, c.declared) for c in comps], [('3.4', '')])


class ScanTests(unittest.TestCase):
    class Repos:
        def __init__(self, files):
            self.files = files

        def snapshot(self, ref):
            return RepoSnapshot(ref.slug, 'main', 'abc', False, sorted(self.files.items()), [])

    class Osv:
        def __init__(self):
            self.asked = []

        def lookup(self, comps):
            self.asked += [(c.name, c.version) for c in comps]
            return {('PyPI', c.name, c.version): [] for c in comps}

    def run_scan(self, files, on):
        osv = self.Osv()
        return scan.scan_repository('acme/app', self.Repos(files), osv, ranges=on), osv

    def test_the_lowest_version_is_what_gets_looked_up_and_the_result_says_so(self):
        files = {'requirements.txt': 'requests>=2.0\nflask==1.0\n'}
        r, osv = self.run_scan(files, True)
        self.assertEqual(sorted(osv.asked), [('flask', '1.0'), ('requests', '2.0')])
        self.assertEqual(r['from_ranges'], 1)
        r, osv = self.run_scan(files, False)
        self.assertEqual((sorted(osv.asked), r['from_ranges'], r['unevaluated']), ([('flask', '1.0')], 0, 1))

    def test_an_exact_pin_elsewhere_means_it_is_not_just_a_lower_bound(self):
        files = {'requirements.txt': 'requests>=2.0\n', 'svc/requirements.txt': 'requests==2.0\n'}
        r, _ = self.run_scan(files, True)
        self.assertEqual((r['components'], r['from_ranges']), (1, 0))

    def test_the_component_carries_the_declared_range_and_exclusivity(self):
        class Vulnerable(self.Osv):
            def lookup(self, comps):
                return {('PyPI', c.name, c.version): [{'id': 'GHSA-1', 'cve': '', 'severity': 'high', 'score': 7.0, 'fixed_versions': ['3.0'], 'suggested_fix': '3.0',
                                                       'url': '', 'aliases': [], 'summary': '', 'vector': '', 'published': '', 'references': []}] for c in comps}
        r = scan.scan_repository('acme/app', self.Repos({'requirements.txt': 'django>2.0\nflask>=1.0\n', 'other/requirements.txt': 'flask>=1.5\n'}), Vulnerable(), ranges=True)
        by = {f['component']['name']: f['component'] for f in r['findings']}
        self.assertEqual((by['django']['ranges'], by['django']['range_exclusive'], by['django']['version']), (['>2.0'], True, '2.0'))
        self.assertEqual((by['flask']['ranges'], by['flask']['range_exclusive']), (['>=1.0'], False))
        self.assertEqual(r['from_ranges'], 3)                                           # django 2.0, flask 1.0 and flask 1.5 are three versions looked up


if __name__ == '__main__':
    unittest.main()
