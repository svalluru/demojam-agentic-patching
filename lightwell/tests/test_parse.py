import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import parse                                                  # noqa: E402

POM = '''<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>2.3.1.RELEASE</version></parent>
  <groupId>com.acme</groupId><artifactId>app</artifactId>
  <properties><log4j.version>2.14.1</log4j.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.9.8</version></dependency>
    <dependency><groupId>org.bom</groupId><artifactId>bom</artifactId><version>1</version><scope>import</scope><type>pom</type></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId></dependency>
    <dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>test</scope></dependency>
    <dependency><groupId>x</groupId><artifactId>ranged</artifactId><version>[1.0,2.0)</version></dependency>
  </dependencies>
</project>'''


class PomTests(unittest.TestCase):
    def setUp(self):
        self.comps, self.notes = parse.parse_pom(POM, 'pom.xml')
        self.by = {c.name: c for c in self.comps}

    def test_property_and_managed_versions_resolve(self):
        self.assertEqual(self.by['org.apache.logging.log4j:log4j-core'].version, '2.14.1')
        self.assertEqual(self.by['com.fasterxml.jackson.core:jackson-databind'].version, '2.9.8')

    def test_unmanaged_version_is_left_unresolved_and_says_why(self):
        c = self.by['org.springframework:spring-core']
        self.assertIsNone(c.version)
        self.assertIn('parent', c.note)

    def test_test_scope_and_ranges_and_parent(self):
        self.assertEqual(self.by['junit:junit'].scope, 'dev')
        self.assertIsNone(self.by['x:ranged'].version)
        self.assertEqual(self.by['org.springframework.boot:spring-boot-starter-parent'].version, '2.3.1.RELEASE')

    def test_notes_admit_the_limits(self):
        text = ' '.join(self.notes)
        self.assertIn('BOM', text)
        self.assertIn('transitive', text)

    def test_doctype_is_refused(self):
        comps, notes = parse.parse_pom('<!DOCTYPE x [<!ENTITY a "b">]><project/>', 'pom.xml')
        self.assertEqual(comps, [])
        self.assertIn('DOCTYPE', notes[0])

    def test_invalid_xml(self):
        self.assertEqual(parse.parse_pom('<a>', 'pom.xml')[0], [])


class PythonTests(unittest.TestCase):
    def test_requirements(self):
        text = '# c\nDjango==2.2.0\nrequests>=2.0\nPyYAML[extra]==5.3 ; python_version>"3"\n-r other.txt\n' \
               'git+https://x/y.git\nFlask_Login===0.4.1 \\\n  --hash=sha256:abc\n'
        comps, notes = parse.parse_requirements(text, 'requirements.txt')
        by = {c.name: c for c in comps}
        self.assertEqual(by['django'].version, '2.2.0')
        self.assertEqual(by['pyyaml'].version, '5.3')
        self.assertEqual(by['flask-login'].version, '0.4.1')
        self.assertFalse(by['requests'].pinned)
        self.assertIn('not pinned', ' '.join(notes))

    @unittest.skipIf(parse.tomllib is None, 'needs tomllib')
    def test_pyproject_and_poetry_lock(self):
        comps, _ = parse.parse_pyproject(
            '[project]\ndependencies=["jinja2==2.10","click>=7"]\n[tool.poetry.dependencies]\npython="^3.8"\nflask="1.0.2"\nrich="^13"\n',
            'pyproject.toml')
        by = {c.name: c for c in comps}
        self.assertEqual(by['jinja2'].version, '2.10')
        self.assertEqual(by['flask'].version, '1.0.2')
        self.assertIsNone(by['rich'].version)
        self.assertNotIn('python', by)
        locked, _ = parse.parse_poetry_lock('[[package]]\nname="Pillow"\nversion="8.0.0"\n', 'poetry.lock')
        self.assertEqual((locked[0].name, locked[0].version, locked[0].scope), ('pillow', '8.0.0', 'transitive'))

    def test_pipfile_lock(self):
        comps, _ = parse.parse_pipfile_lock('{"default":{"urllib3":{"version":"==1.25.8"}},"develop":{"pytest":{"version":"==6.0.0"}}}',
                                            'Pipfile.lock')
        self.assertEqual({(c.name, c.scope) for c in comps}, {('urllib3', 'transitive'), ('pytest', 'dev')})


class NpmAndGradleTests(unittest.TestCase):
    def test_package_json(self):
        comps, notes = parse.parse_package_json('{"dependencies":{"lodash":"4.17.4","express":"^4.0.0"},"devDependencies":{"jest":"29.0.0"}}',
                                                'package.json')
        by = {c.name: c for c in comps}
        self.assertEqual(by['lodash'].version, '4.17.4')
        self.assertIsNone(by['express'].version)
        self.assertEqual(by['jest'].scope, 'dev')
        self.assertTrue(notes)

    def test_package_lock_v3_and_v1(self):
        v3 = '{"packages":{"":{"name":"x"},"node_modules/a":{"version":"1.0.0"},"node_modules/a/node_modules/@s/b":{"version":"2.0.0","dev":true}}}'
        comps, _ = parse.parse_package_lock(v3, 'package-lock.json')
        self.assertEqual({(c.name, c.version) for c in comps}, {('a', '1.0.0'), ('@s/b', '2.0.0')})
        v1 = '{"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"3.0.0"}}}}}'
        self.assertEqual(len(parse.parse_package_lock(v1, 'package-lock.json')[0]), 2)

    def test_gradle(self):
        comps, _ = parse.parse_gradle("dependencies {\n  implementation 'org.a:b:1.2.3'\n  testImplementation(\"x.y:z:4.5\")\n  implementation project(':lib')\n}",
                                      'build.gradle')
        self.assertEqual([(c.name, c.version, c.scope) for c in comps],
                         [('org.a:b', '1.2.3', 'direct'), ('x.y:z', '4.5', 'dev')])


class MiscTests(unittest.TestCase):
    def test_manifest_kind_skips_vendored_directories(self):
        self.assertEqual(parse.manifest_kind('services/api/pom.xml'), 'pom')
        self.assertEqual(parse.manifest_kind('requirements-dev.txt'), 'requirements')
        self.assertEqual(parse.manifest_kind('requirements/base.txt'), 'requirements')
        self.assertIsNone(parse.manifest_kind('node_modules/x/package.json'))
        self.assertIsNone(parse.manifest_kind('README.md'))

    def test_purls(self):
        self.assertEqual(parse.make_purl('maven', 'org.a:b', '1.0'), 'pkg:maven/org.a/b@1.0')
        self.assertEqual(parse.make_purl('npm', '@scope/pkg', '2.0.0'), 'pkg:npm/%40scope/pkg@2.0.0')
        self.assertEqual(parse.make_purl('pypi', 'django', '2.2'), 'pkg:pypi/django@2.2')


if __name__ == '__main__':
    unittest.main()
