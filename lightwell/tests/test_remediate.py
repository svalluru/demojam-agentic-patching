import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import remediation                                                         # noqa: E402
from scanner import aap                                                    # noqa: E402
from scanner.http import UpstreamError                                     # noqa: E402
from scanner.remediate import resolve                                      # noqa: E402
from scanner.repo import RepoRef                                           # noqa: E402


def finding(name, version, *, status='not_covered', build=None, nearest=None, fix=None, sources=('pom.xml',), eco='maven'):
    lw = {'status': status, 'build': build}
    if nearest:
        lw['versions'] = {'nearest': nearest}
    return {'component': {'name': name, 'version': version, 'ecosystem': eco, 'sources': list(sources)}, 'lightwell': lw, 'fix_all': fix, 'vulns': []}


FINDINGS = [
    finding('a:exact', '1.0', status='remediated', build='1.0.rhlw-1', fix='1.5'),
    finding('b:pre', '2.0', status='predisclosure', build='2.0.rhlw-2'),
    finding('c:near', '3.0', status='other_version', nearest={'version': '3.1', 'build': '3.1.rhlw-3'}, fix='3.4'),
    finding('d:osv', '4.0', fix='4.2'),
    finding('e:none', '5.0'),
    finding('f:gradle', '6.0', fix='6.1', sources=('build.gradle',)),
    finding('django', '2.2', fix='2.2.28', sources=('requirements.txt',), eco='pypi'),
]


def by_name(plan):
    return {c['name']: c for c in plan['changes']}


class ResolveTests(unittest.TestCase):
    def test_lightwell_only_changes_just_the_exact_builds(self):
        plan = resolve(FINDINGS, ['lightwell'])
        got = by_name(plan)
        self.assertEqual(set(got), {'a:exact', 'b:pre'})
        self.assertEqual((got['a:exact']['to'], got['a:exact']['source'], got['a:exact']['tier']), ('1.0.rhlw-1', 'lightwell', 'remediated'))
        self.assertEqual(got['b:pre']['tier'], 'predisclosure')
        self.assertEqual(plan['registry'], [{'ecosystem': 'maven', 'tier': 'predisclosure'}, {'ecosystem': 'maven', 'tier': 'remediated'}])
        why = {s['name']: s['reason'] for s in plan['skipped']}
        self.assertIn('Lightwell with Another Build', why['c:near'])
        self.assertIn('OSV', why['c:near'])
        self.assertIn('not selected', why['d:osv'])
        self.assertIn('No fixed version', why['e:none'])

    def test_another_build_is_used_before_osv_when_both_are_ticked(self):
        got = by_name(resolve(FINDINGS, ['another', 'osv']))
        self.assertEqual((got['c:near']['to'], got['c:near']['source']), ('3.1.rhlw-3', 'another'))
        self.assertEqual((got['d:osv']['to'], got['d:osv']['source']), ('4.2', 'osv'))
        self.assertEqual((got['a:exact']['to'], got['a:exact']['source']), ('1.5', 'osv'))        # Lightwell not ticked, so OSV is used

    def test_lightwell_wins_over_osv_for_the_same_component(self):
        got = by_name(resolve(FINDINGS, ['lightwell', 'osv']))
        self.assertEqual(got['a:exact']['source'], 'lightwell')

    def test_osv_changes_carry_no_registry(self):
        plan = resolve(FINDINGS, ['osv'])
        self.assertEqual(plan['registry'], [])
        self.assertNotIn('tier', by_name(plan)['d:osv'])

    def test_a_file_type_that_is_not_edited_is_listed_for_hand_editing(self):
        plan = resolve(FINDINGS, ['osv'])
        self.assertNotIn('f:gradle', by_name(plan))
        self.assertIn('by hand', next(s['reason'] for s in plan['skipped'] if s['name'] == 'f:gradle'))

    def test_offered_counts_ignore_the_choice(self):
        self.assertEqual(resolve(FINDINGS, [])['offered'], {'lightwell': 2, 'another': 1, 'osv': 5})
        self.assertEqual(resolve(FINDINGS, [])['changes'], [])

    def test_unknown_sources_are_dropped(self):
        self.assertEqual(resolve(FINDINGS, ['everything'])['sources'], [])

    def test_a_version_with_unsafe_characters_is_not_edited(self):
        bad = [finding('a:b', '1.0', fix='1.0;rm -rf /')]
        plan = resolve(bad, ['osv'])
        self.assertEqual(plan['changes'], [])
        self.assertIn('not allowed', plan['skipped'][0]['reason'])


POM = """<project>
  <properties><gson.version>2.8.6</gson.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>g</groupId><artifactId>managed</artifactId><version>1.0</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <!-- keep this comment -->
    <dependency>
      <groupId>org.postgresql</groupId>
      <artifactId>postgresql</artifactId>
      <version>42.3.3</version>
    </dependency>
    <dependency><groupId>com.google.code.gson</groupId><artifactId>gson</artifactId><version>${gson.version}</version></dependency>
    <dependency><groupId>g</groupId><artifactId>noversion</artifactId></dependency>
    <dependency><groupId>g</groupId><artifactId>ranged</artifactId><version>[1.0,2.0)</version></dependency>
  </dependencies>
</project>
"""


def apply(pom=POM, changes=(), req=None):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / 'pom.xml').write_text(pom)
        if req is not None:
            (root / 'requirements.txt').write_text(req)
        report = remediation.edit_script().run(root, list(changes))
        return report, (root / 'pom.xml').read_text(), (root / 'requirements.txt').read_text() if req is not None else ''


def ch(name, old, new, *files):
    return {'name': name, 'from': old, 'to': new, 'manifests': list(files or ['pom.xml'])}


class EditScriptTests(unittest.TestCase):
    def test_a_pinned_version_changes_and_the_rest_of_the_file_is_untouched(self):
        report, pom, _ = apply(changes=[ch('org.postgresql:postgresql', '42.3.3', '42.3.3.rhlw-00006')])
        self.assertEqual(report[0]['applied'], ['pom.xml (version)'])
        self.assertEqual(pom, POM.replace('<version>42.3.3</version>', '<version>42.3.3.rhlw-00006</version>'))
        self.assertIn('<!-- keep this comment -->', pom)

    def test_a_version_held_in_a_property_changes_the_property(self):
        report, pom, _ = apply(changes=[ch('com.google.code.gson:gson', '2.8.6', '2.10.1')])
        self.assertEqual(report[0]['applied'], ['pom.xml (property gson.version)'])
        self.assertIn('<gson.version>2.10.1</gson.version>', pom)
        self.assertIn('${gson.version}', pom)

    def test_what_cannot_be_changed_says_why_and_leaves_the_file_alone(self):
        report, pom, _ = apply(changes=[ch('g:noversion', '1.0', '1.1'), ch('g:ranged', '1.0', '1.1'), ch('g:absent', '1.0', '1.1'),
                                         ch('org.postgresql:postgresql', '9.9', '10.0')])
        self.assertEqual(pom, POM)
        problems = [e['problems'][0] for e in report]
        self.assertIn('parent or BOM', problems[0])
        self.assertIn('is [1.0,2.0), not 1.0', problems[1])
        self.assertIn('no dependency g:absent', problems[2])
        self.assertIn('is 42.3.3, not 9.9', problems[3])
        self.assertTrue(all(not e['applied'] for e in report))

    def test_requirements_pins_are_matched_by_normalised_name(self):
        req = 'Django==2.2  # web\nrequests[security]==2.0 ; python_version>"3"\nother==1.0\n'
        report, _, text = apply(req=req, changes=[ch('django', '2.2', '2.2.28', 'requirements.txt'), ch('requests', '2.0', '2.31.0', 'requirements.txt')])
        self.assertTrue(all(e['applied'] for e in report))
        self.assertEqual(text, 'Django==2.2.28  # web\nrequests[security]==2.31.0 ; python_version>"3"\nother==1.0\n')

    def test_a_path_outside_the_checkout_is_refused(self):
        report, _, _ = apply(changes=[ch('x:y', '1', '2', '../outside/pom.xml')])
        self.assertIn('not found', report[0]['problems'][0])

    def test_exit_status_reports_whether_anything_changed(self):
        script = str(remediation.SCRIPTS / 'apply_dependency_changes.py')
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'pom.xml').write_text(POM)
            (Path(tmp) / 'c.json').write_text(json.dumps([ch('g:absent', '1', '2')]))
            run = subprocess.run([sys.executable, script, '--root', tmp, '--changes', str(Path(tmp) / 'c.json')], capture_output=True, text=True)
        self.assertEqual(run.returncode, 1)
        self.assertEqual(json.loads(run.stdout)[0]['name'], 'g:absent')


def ev(kind, task='', uuid='', parent='', **more):
    return {'event': kind, 'task': task, 'uuid': uuid, 'parent_uuid': parent, **more}


def started(stage, text, uuid):
    return ev('playbook_on_task_start', f'STAGE {stage}: {text}', uuid)


class JobViewTests(unittest.TestCase):
    def test_stages_follow_the_last_stage_task_in_the_events(self):
        events = [started('clone', 'Clone', 'a'), ev('runner_on_ok', parent='a'), started('edit', 'Apply', 'b'), ev('runner_on_ok', parent='b', changed=True),
                  ev('playbook_on_task_start', 'Not a stage task', 'x'), started('build', 'Build with Maven', 'c')]
        v = aap.view({'status': 'running'}, events, push=False)
        self.assertEqual([(s['id'], s['state']) for s in v['stages']], [('clone', 'done'), ('edit', 'done'), ('build', 'running')])
        self.assertEqual(v['state'], 'running')

    def test_each_step_shows_how_it_ended_and_skipped_ones_are_only_counted(self):
        events = [started('build', 'Look for an installed JDK', 'a'), ev('runner_on_ok', parent='a'),
                  started('build', 'Download the JDK', 'b'), ev('runner_on_skipped', parent='b'),
                  started('build', 'Build with Maven', 'c')]
        build = aap.view({'status': 'running'}, events, push=False)['stages'][2]
        self.assertEqual([(x['label'], x['state']) for x in build['actions']], [('Look for an installed JDK', 'ok'), ('Build with Maven', 'running')])
        self.assertEqual(build['skipped'], 1)

    def test_a_failed_step_fails_its_stage_and_says_why(self):
        events = [started('clone', 'Clone', 'a'), ev('runner_on_ok', parent='a'), started('clone', 'Stop if the clone failed', 'b'),
                  ev('runner_on_failed', parent='b', event_data={'res': {'msg': 'git clone failed (rc 128): repository not found'}}), ev('playbook_on_stats')]
        v = aap.view({'status': 'failed'}, events, push=False)
        clone = v['stages'][0]
        self.assertEqual(clone['state'], 'failed')
        self.assertEqual(clone['actions'][1], {'label': 'Stop if the clone failed', 'state': 'failed', 'detail': 'git clone failed (rc 128): repository not found'})

    def test_steps_skipped_after_the_build_do_not_hide_where_the_job_got_to(self):
        events = [started('clone', 'Clone', 'a'), ev('runner_on_ok', parent='a'), started('edit', 'Apply', 'b'), ev('runner_on_ok', parent='b'),
                  started('build', 'Build with Maven', 'c'), ev('runner_on_ok', parent='c'), started('push', 'Commit the change', 'd'), ev('runner_on_skipped', parent='d'),
                  ev('playbook_on_task_start', 'Fail the job if the build or the push failed', 'e'),
                  ev('runner_on_failed', 'Fail the job if the build or the push failed', parent='e', event_data={'res': {'msg': 'The build failed (rc 1).'}})]
        v = aap.view({'status': 'failed'}, events, push=False)
        self.assertEqual([(s['id'], s['state']) for s in v['stages']], [('clone', 'done'), ('edit', 'done'), ('build', 'failed')])
        self.assertEqual(v['failure'], 'The build failed (rc 1).')
        self.assertEqual(aap.view({'status': 'running'}, events[:8], push=False)['failure'], '')

    def test_a_hidden_failure_message_is_not_shown(self):
        events = [started('build', 'Build', 'a'), ev('runner_on_failed', parent='a', event_data={'res': {'msg': "the output has been hidden due to the fact that 'no_log: true' was specified"}})]
        self.assertEqual(aap.view({'status': 'failed'}, events, push=False)['stages'][2]['actions'][0]['detail'], '')

    def test_the_log_is_the_events_output_without_colour_codes(self):
        events = [ev('playbook_on_start', stdout='\x1b[0;32mPLAY [x]\x1b[0m'), ev('runner_on_ok', stdout='ok: [localhost]')]
        self.assertEqual(aap.view({'status': 'running'}, events, push=False)['log'], 'PLAY [x]\nok: [localhost]')

    def test_a_failed_job_marks_the_stage_it_stopped_in(self):
        events = [started('clone', 'Clone', 'a'), started('edit', 'Apply', 'b')]
        v = aap.view({'status': 'failed'}, events, push=True)
        self.assertEqual([(s['id'], s['state']) for s in v['stages']], [('clone', 'done'), ('edit', 'failed'), ('build', 'pending'), ('push', 'pending')])
        self.assertEqual(v['state'], 'failed')

    def test_a_successful_job_shows_everything_done_and_the_artifact(self):
        v = aap.view({'status': 'successful', 'artifacts': {'app_patch': {'build_rc': 0, 'diff': 'x'}}}, [started('build', 'B', 'a')], push=False)
        self.assertEqual({s['state'] for s in v['stages']}, {'done'})
        self.assertEqual(v['result'], {'build_rc': 0, 'diff': 'x'})
        self.assertEqual([s['id'] for s in v['stages']], ['clone', 'edit', 'build'])


class ClientTests(unittest.TestCase):
    def test_launch_finds_the_template_and_passes_the_variables_and_limit(self):
        calls = []

        def fake(service, url, **kw):
            calls.append((kw.get('method', 'GET'), url, kw.get('body'), kw['headers'], kw.get('cafile')))
            if '/job_templates/?' in url:
                return {'results': [{'id': 7, 'name': 'T'}, {'id': 8, 'name': 'T2'}]}, {}
            return {'job': 42}, {}
        with mock.patch('scanner.aap.request', fake):
            job = aap.AapClient('https://c.example/api/controller/v2/', 'tok', 'T', 'buildhost', '/ca.pem').launch({'a': 1})
        self.assertEqual(job, 42)
        self.assertEqual(calls[1][:3], ('POST', 'https://c.example/api/controller/v2/job_templates/7/launch/', {'extra_vars': {'a': 1}, 'limit': 'buildhost'}))
        self.assertEqual(calls[0][3], {'Authorization': 'Bearer tok'})
        self.assertEqual(calls[0][4], '/ca.pem')

    def test_a_missing_template_is_explained(self):
        with mock.patch('scanner.aap.request', lambda *a, **k: ({'results': []}, {})):
            with self.assertRaises(UpstreamError) as cm:
                aap.AapClient('https://c/api', 'tok', 'Nope').launch({})
        self.assertIn('"Nope" does not exist', cm.exception.message)
        self.assertNotIn('tok', cm.exception.message)

    def test_events_are_read_page_by_page_without_asking_for_text(self):
        urls = []

        def fake(service, url, **kw):
            urls.append((url, kw.get('raw', False)))
            page = int(url.rsplit('page=', 1)[1])
            return {'results': [{'counter': page}], 'next': 'more' if page < 2 else None}, {}
        with mock.patch('scanner.aap.request', fake):
            got = aap.AapClient('https://c', 't').events(5)
        self.assertEqual([e['counter'] for e in got], [1, 2])
        self.assertEqual([u for u, _ in urls], ['https://c/jobs/5/job_events/?order_by=counter&page_size=200&page=1', 'https://c/jobs/5/job_events/?order_by=counter&page_size=200&page=2'])
        self.assertFalse(any(raw for _, raw in urls))


class JavaTests(unittest.TestCase):
    def detect(self, files):
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in files.items():
                path = Path(tmp, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            return remediation._script('detect_java').detect(tmp)

    def test_old_source_level_is_java_8(self):
        got = self.detect({'pom.xml': '<project><properties><maven.compiler.source>1.7</maven.compiler.source></properties></project>'})
        self.assertEqual((got['version'], got['declared']), (8, 7))

    def test_property_indirection_and_highest_requirement_win(self):
        got = self.detect({'pom.xml': '<project><properties><java.version>${v}</java.version><v>11</v></properties></project>',
                           'web/pom.xml': '<project><properties><maven.compiler.release>17</maven.compiler.release></properties></project>'})
        self.assertEqual((got['version'], got['reason']), (17, 'web/pom.xml: maven.compiler.release 17'))

    def test_spring_boot_parent_sets_the_floor(self):
        boot3 = '<project><parent><artifactId>spring-boot-starter-parent</artifactId><version>3.2.1</version></parent><properties><java.version>11</java.version></properties></project>'
        boot2 = boot3.replace('3.2.1', '2.7.18').replace('11', '1.8')
        self.assertEqual(self.detect({'pom.xml': boot3})['version'], 17)
        self.assertEqual(self.detect({'pom.xml': boot2})['version'], 8)

    def test_rounds_up_to_a_supported_release(self):
        self.assertEqual(self.detect({'.java-version': '15\n'})['version'], 17)
        got = self.detect({'pom.xml': '<project><properties><maven.compiler.release>25</maven.compiler.release></properties></project>'})
        self.assertEqual(got['version'], 21)
        self.assertIn('may not compile', got['reason'])

    def test_hints_only_count_when_nothing_else_says(self):
        flow = {'.github/workflows/ci.yml': 'with:\n  java-version: 11\n'}
        got = self.detect(flow)
        self.assertEqual(got['version'], 11)
        self.assertIn('a hint', got['reason'])
        self.assertEqual(self.detect({**flow, '.java-version': '21'})['version'], 21)

    def test_nothing_found_is_the_default(self):
        got = self.detect({'pom.xml': '<project/>'})
        self.assertEqual((got['version'], got['declared']), (17, None))

    def test_directories_that_are_not_source_are_ignored(self):
        got = self.detect({'target/pom.xml': '<project><properties><java.version>21</java.version></properties></project>'})
        self.assertIsNone(got['declared'])

    def test_choice_from_the_request(self):
        self.assertIsNone(remediation.parse_java(None))
        self.assertIsNone(remediation.parse_java(''))
        self.assertEqual((remediation.parse_java(11), remediation.parse_java('21')), (11, 21))
        for bad in (12, '9', 'x', True, [8], 1.5):
            with self.assertRaises(ValueError):
                remediation.parse_java(bad)

    def test_choice_goes_to_the_job(self):
        client = mock.Mock()
        client.launch.return_value = 1
        ref = RepoRef('github', 'github.com', 'acme/app', 'main', '')
        repo = {'url': 'acme/app', 'commit': 'abc'}
        plan = {'changes': [{'name': 'a', 'from': '1', 'to': '2', 'manifests': ['pom.xml'], 'source': 'osv'}], 'registry': []}
        remediation.Runs().start_live(client, repo, ref, plan, False)
        self.assertNotIn('java_version', client.launch.call_args[0][0])
        remediation.Runs().start_live(client, repo, ref, plan, False, 8)
        self.assertEqual(client.launch.call_args[0][0]['java_version'], 8)
        self.assertEqual(client.launch.call_args[0][0]['registry_base'], 'https://packages.redhat.com/api/pulp-content/lightwell')


class StatusTests(unittest.TestCase):
    def run_status(self, limit='', hosts=None, fail=None):
        def fake(service, url, **kw):
            if fail and fail in url:
                raise UpstreamError('AAP', 'the controller refused the token')
            if '/job_templates/' in url:
                return {'results': [{'name': 'T', 'id': 7}]}, {}
            if '/hosts/' in url:
                return {'results': hosts or []}, {}
            return {'username': 'svc'}, {}
        with mock.patch('scanner.aap.request', fake):
            return aap.AapClient('https://c', 'tok', 'T', limit).status()

    def test_ok(self):
        self.assertTrue(self.run_status()['ok'])

    def test_unknown_build_host(self):
        got = self.run_status(limit='build1')
        self.assertFalse(got['ok'])
        self.assertIn('build1', got['detail'])

    def test_known_build_host(self):
        self.assertTrue(self.run_status(limit='build1', hosts=[{'name': 'build1'}])['ok'])

    def test_refused_token(self):
        got = self.run_status(fail='/me/')
        self.assertEqual((got['ok'], got['detail']), (False, 'the controller refused the token'))


class RunTests(unittest.TestCase):
    PLAN = {'changes': [ch('django', '2.2', '2.2.28', 'requirements.txt') | {'source': 'osv'}], 'registry': [], 'skipped': [], 'offered': {}, 'sources': ['osv']}
    REPO = {'url': 'acme/app', 'commit': 'abc123'}

    def test_demo_run_makes_a_real_diff_and_advances_with_the_clock(self):
        runs = remediation.Runs()
        run_id = runs.start_demo(self.REPO, self.PLAN, False, {'requirements.txt': 'django==2.2\nflask==1.0\n'})
        first = runs.view(run_id)
        self.assertEqual(first['state'], 'running')
        self.assertIn('-django==2.2\n+django==2.2.28', first['result']['diff'])
        run = runs._runs[run_id]['demo']
        later = run.view(run.started + 60)
        self.assertEqual((later['state'], {s['state'] for s in later['stages']}), ('done', {'done'}))
        self.assertTrue(all(a['state'] == 'ok' for s in later['stages'] for a in s['actions']))
        self.assertEqual([a['state'] for a in first['stages'][0]['actions']], ['running'])
        self.assertEqual(later['result']['build_rc'], 0)

    def test_demo_run_follows_the_playbook_and_ends_a_push_like_a_real_one(self):
        runs = remediation.Runs()
        run_id = runs.start_demo(self.REPO, self.PLAN, True, {'pom.xml': '<project/>'})
        run = runs._runs[run_id]['demo']
        mid = run.view(run.started + 22)
        self.assertEqual([s['state'] for s in mid['stages']], ['done', 'done', 'running', 'pending'])
        self.assertIn('Download the JDK', [a['label'] for a in mid['stages'][2]['actions']])
        self.assertFalse(mid['result']['pushed'])
        later = run.view(run.started + 120)
        self.assertEqual([s['id'] for s in later['stages']], ['clone', 'edit', 'build', 'push'])
        self.assertEqual((later['state'], later['result']['pushed'], later['result']['branch']), ('done', True, remediation.BRANCH))
        self.assertEqual(later['stages'][3]['skipped'], 0)

    def test_demo_run_builds_python_with_pip_and_not_pushing_stays_unpushed(self):
        runs = remediation.Runs()
        run_id = runs.start_demo(self.REPO, self.PLAN, False, {'requirements.txt': 'django==2.2\n'})
        run = runs._runs[run_id]['demo']
        later = run.view(run.started + 120)
        self.assertEqual([s['id'] for s in later['stages']], ['clone', 'edit', 'build'])
        self.assertEqual([a['label'] for a in later['stages'][2]['actions']][1], 'Build with pip')
        self.assertFalse(later['result']['pushed'])

    def test_live_run_launches_with_the_approved_changes_and_follows_the_job(self):
        client = mock.Mock()
        client.launch.return_value = 99
        client.job.return_value = {'status': 'successful', 'artifacts': {'app_patch': {'build_rc': 0}}}
        client.events.return_value = []
        runs = remediation.Runs()
        ref = RepoRef('github', 'github.com', 'acme/app', 'main', 'svc')
        run_id = runs.start_live(client, self.REPO, ref, self.PLAN, True)
        extra = client.launch.call_args[0][0]
        self.assertEqual((extra['repo_url'], extra['commit'], extra['subdir'], extra['push'], extra['patch_run_id']), ('https://github.com/acme/app.git', 'abc123', 'svc', True, run_id))
        self.assertEqual(extra['changes'], [{'name': 'django', 'from': '2.2', 'to': '2.2.28', 'manifests': ['requirements.txt']}])
        v = runs.view(run_id)
        self.assertEqual((v['state'], v['result']), ('done', {'build_rc': 0}))
        runs.view(run_id)
        self.assertEqual(client.job.call_count, 1)                           # a finished run is not asked about again

    def test_a_scan_without_a_commit_cannot_launch(self):
        with self.assertRaises(UpstreamError):
            remediation.Runs().start_live(mock.Mock(), {'url': 'x'}, RepoRef('github', 'github.com', 'a/b'), self.PLAN, False)

    def test_an_unreachable_controller_while_following_is_reported_not_raised(self):
        client = mock.Mock()
        client.launch.return_value = 1
        client.job.side_effect = UpstreamError('AAP', 'could not reach https://c/jobs/1/')
        runs = remediation.Runs()
        run_id = runs.start_live(client, self.REPO, RepoRef('github', 'github.com', 'a/b'), self.PLAN, False)
        v = runs.view(run_id)
        self.assertEqual(v['state'], 'unknown')
        self.assertIn('could not reach', v['error'])

    def test_commit_message_is_one_line(self):
        self.assertEqual(remediation.commit_message(self.PLAN), 'Clear known vulnerabilities in 1 dependency')
        plan = {'changes': [{'source': 'lightwell'}, {'source': 'osv'}]}
        self.assertEqual(remediation.commit_message(plan), 'Clear known vulnerabilities in 2 dependencies (1 with Lightwell builds)')


if __name__ == '__main__':
    unittest.main()
