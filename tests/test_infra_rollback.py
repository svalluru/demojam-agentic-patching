"""Infra patching's rollback route: checkpoint, post-patch health check, and dnf history rollback.

    python3 -m unittest discover -s tests
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_roi_v2 import load_console  # noqa: E402

import fallbacks  # noqa: E402


def step(name, artifacts=None, status='completed', **extra):
    out = {'name': name, 'status': status, 'error': None}
    if artifacts is not None:
        out['output'] = {'artifacts': artifacts, 'job_id': 7, 'job_url': 'https://aap/jobs/7', **extra}
    return out


class Verdicts(unittest.TestCase):
    def setUp(self):
        self.c = load_console()

    def test_health_reads_the_nested_artifacts(self):
        v = self.c.health_verdict([step('health_check_prod', {
            'health': 'failed', 'failed_services': 'httpd.service,sshd.service', 'new_failed_units': '',
            'reboot_needed': 'True', 'health_forced': 'False', 'health_notes': ' Not running: httpd. '})])
        self.assertFalse(v['healthy'])
        self.assertEqual(v['failed_services'], ['httpd.service', 'sshd.service'])
        self.assertTrue(v['reboot_needed'])
        self.assertFalse(v['forced'])           # 'False' as a string must not read as true
        self.assertEqual(v['notes'], 'Not running: httpd.')

    def test_health_absent_or_unreadable_is_none(self):
        self.assertIsNone(self.c.health_verdict([]))
        self.assertIsNone(self.c.health_verdict([step('health_check', {'health': ''})]))
        self.assertIsNone(self.c.health_verdict([step('verify_patch', {'patched': True})]))

    def test_rollback_reported(self):
        v = self.c.rollback_verdict([step('rollback', {'rolled_back': True, 'restored': 'Downgrade openssl',
                                                       'rollback_txn': 41, 'rollback_reboot': False})])
        self.assertTrue(v['rolled_back'])
        self.assertEqual(v['txn'], '41')
        self.assertEqual(v['job_url'], 'https://aap/jobs/7')

    def test_rollback_failed_without_artifacts_counts_as_not_rolled_back(self):
        v = self.c.rollback_verdict([step('rollback_prod', {}, status='failed')])
        self.assertFalse(v['rolled_back'])

    def test_rollback_not_reached_is_none(self):
        self.assertIsNone(self.c.rollback_verdict([step('rollback', {}, status='running')]))
        self.assertIsNone(self.c.rollback_verdict([step('health_check', {'health': 'ok'})]))

    def test_checkpoint_text_or_mapping(self):
        self.assertEqual(self.c.checkpoint_of([step('checkpoint', {'checkpoint_json': '{"dnf_txn": 41}'})]),
                         '{"dnf_txn": 41}')
        self.assertIn('41', self.c.checkpoint_of([step('checkpoint_prod', {'checkpoint_json': {'dnf_txn': 41}})]))
        self.assertEqual(self.c.checkpoint_of([]), '')


class Outcome(unittest.TestCase):
    def setUp(self):
        self.c = load_console()
        self.sick = {'healthy': False}
        self.well = {'healthy': True}

    def test_healthy_or_unchecked_changes_nothing(self):
        for o in ('patched', 'not_verified', 'failed', 'running'):
            self.assertEqual(self.c.infra_outcome(o, None, None), o)
            self.assertEqual(self.c.infra_outcome(o, self.well, None), o)

    def test_rolled_back_outranks_not_verified(self):
        self.assertEqual(self.c.infra_outcome('not_verified', self.sick, {'rolled_back': True}), 'rolled_back')
        self.assertEqual(self.c.infra_outcome('patched', self.sick, {'rolled_back': True}), 'rolled_back')

    def test_rollback_that_did_not_restore(self):
        self.assertEqual(self.c.infra_outcome('failed', self.sick, {'rolled_back': False}), 'rollback_failed')

    def test_unhealthy_while_rollback_still_running_keeps_the_outcome(self):
        self.assertEqual(self.c.infra_outcome('running', self.sick, None), 'running')

    def test_failed_remediation_is_never_talked_up(self):
        # The workflow stops at a failed remediation: no health check, no rollback, so it stays failed.
        self.assertEqual(self.c.infra_outcome('failed', None, None), 'failed')


class ForcedHost(unittest.TestCase):
    def setUp(self):
        self.c = load_console()

    def test_first_gated_host_but_not_the_staged_not_verified_one(self):
        hosts = [{'host': 'dev-01', 'decision': 'ok'},
                 {'host': 'pay-app-07.example.com', 'decision': 'review'},
                 {'host': 'pay-app-09.example.com', 'decision': 'review'}]
        self.assertEqual(self.c.forced_host(hosts), 'pay-app-09.example.com')

    def test_falls_back_to_the_first_host(self):
        self.assertEqual(self.c.forced_host([{'host': 'dev-01', 'decision': 'ok'}]), 'dev-01')
        self.assertEqual(self.c.forced_host([]), '')


class Simulator(unittest.TestCase):
    def setUp(self):
        self.c = load_console()

    def test_steps_have_checkpoint_and_health(self):
        names = [n for n, _ in fallbacks.SIM_STEPS_PROD]
        self.assertLess(names.index('checkpoint_prod'), names.index('run_cve_remediation_prod'))
        self.assertGreater(names.index('health_check_prod'), names.index('verify_patch_prod'))

    def test_unforced_auto_patch_is_healthy(self):
        run = self.c.with_verdicts(fallbacks.patch_simulated('CVE-1', 'dev-01', 'auto_patch', 'down', 'sim-1'))
        self.assertEqual(run['outcome'], 'patched')
        self.assertTrue(run['health']['healthy'])
        self.assertIsNone(run['rollback'])
        self.assertNotIn('rollback', [s['name'] for s in run['steps']])

    def test_forced_auto_patch_rolls_back(self):
        run = self.c.with_verdicts(fallbacks.patch_simulated('CVE-1', 'dev-01', 'auto_patch', 'down', 'sim-2',
                                                             force_fail=True))
        self.assertEqual(run['outcome'], 'rolled_back')
        self.assertFalse(run['health']['healthy'])
        self.assertTrue(run['health']['forced'])
        self.assertTrue(run['rollback']['rolled_back'])
        self.assertIn('openssl', run['rollback']['restored'])
        self.assertEqual(run['steps'][-1]['name'], 'rollback')

    def test_gated_run_waits_and_keeps_the_force_flag(self):
        run = fallbacks.patch_simulated('CVE-1', 'pay-app-09', 'approved_patch', 'down', 'sim-3', force_fail=True)
        self.assertEqual(run['outcome'], 'awaiting_approval')
        self.assertTrue(run['force_fail'])

    def test_summary_counts_both_rollback_outcomes(self):
        s = self.c._summarise([{'outcome': 'rolled_back'}, {'outcome': 'rollback_failed'}, {'outcome': 'patched'}])
        self.assertEqual((s['rolled_back'], s['rollback_failed'], s['patched'], s['failed']), (1, 1, 1, 0))

    def test_next_step_names_the_broken_host_first(self):
        self.assertIn('rollback did not', self.c.next_step({'rollback_failed': 1, 'not_verified': 2}))
        self.assertIn('rolled-back', self.c.next_step({'rolled_back': 1}))


class ManualRollback(unittest.TestCase):
    def setUp(self):
        self.c = load_console()
        self.saved = (dict(self.c._RUN), self.c.demo_pause, self.c._run_trace)
        self.c.demo_pause = lambda *a, **k: None
        self.c._run_trace = lambda *a, **k: None

    def tearDown(self):
        run, self.c.demo_pause, self.c._run_trace = self.saved
        self.c._RUN.clear(); self.c._RUN.update(run)

    def rows(self, *rows):
        self.c._RUN.clear()
        self.c._RUN['patch'] = {'results': [dict(r) for r in rows], 'summary': {}}

    def test_simulated_failed_row_is_rolled_back(self):
        import time
        self.rows({'execution_id': 'e1', 'host': 'pay-app-03', 'outcome': 'failed', 'simulated': True})
        self.c.manual_rollback('e1')
        deadline = time.time() + 5
        while time.time() < deadline:
            row = self.c._RUN['patch']['results'][0]
            if row['outcome'] != 'running':
                break
            time.sleep(0.05)
        self.assertEqual(row['outcome'], 'rolled_back')
        self.assertTrue(row['rollback']['rolled_back'])
        self.assertEqual(self.c._RUN['patch']['summary']['rolled_back'], 1)

    def test_refuses_rows_that_did_not_fail_or_have_no_checkpoint(self):
        self.rows({'execution_id': 'e1', 'host': 'a', 'outcome': 'patched', 'simulated': True},
                  {'execution_id': 'e2', 'host': 'b', 'outcome': 'failed', 'checkpoint': ''})
        for exec_id in ('e1', 'e2', 'nope'):
            with self.assertRaises(self.c.BackendUnavailable):
                self.c.manual_rollback(exec_id)


class Workflow(unittest.TestCase):
    def test_both_branches_route_unhealthy_hosts_to_rollback(self):
        import json
        from pathlib import Path
        wf = json.loads((Path(__file__).resolve().parents[1] / 'ao-setup' / 'demojam_lab_workflow.json').read_text())
        edges = {(e['from'], e['to'], e.get('from_port', '')) for e in wf['edges']}
        for sfx in ('', '_prod'):
            self.assertIn((f'deploy_script{sfx}', f'checkpoint{sfx}', ''), edges)
            self.assertIn((f'checkpoint{sfx}', f'run_cve_remediation{sfx}', ''), edges)
            self.assertIn((f'verify_patch{sfx}', f'health_check{sfx}', ''), edges)
            self.assertIn((f'health_switch{sfx}', f'rollback{sfx}', 'case_1'), edges)
            self.assertIn((f'health_switch{sfx}', f'notify_remediated{sfx}', 'case_0'), edges)
            self.assertNotIn((f'deploy_script{sfx}', f'run_cve_remediation{sfx}', ''), edges)
        self.assertIn('force_fail', wf['triggers'][0]['parameters']['input_schema']['properties'])


if __name__ == '__main__':
    unittest.main()
