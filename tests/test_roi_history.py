"""Calculate ROI for Applications: the run on screen, or the newest finished run when that one dispatched nothing.

    python3 -m unittest discover -s tests
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import appv2  # noqa: E402


def run(run_id, *outcomes, status='complete'):
    return {'run_id': run_id, 'status': status, 'hosts': [{'app': 'workflow-engine', 'outcome': o} for o in outcomes]}


class RoiState(unittest.TestCase):
    def setUp(self):
        self.saved = (appv2.state, appv2._history)

    def tearDown(self):
        appv2.state, appv2._history = self.saved

    def use(self, current, history):
        appv2.state = lambda: current
        appv2._history = lambda: [{'run_id': r['run_id'], 'finished_at': f'2026-11-1{i}T10:00:00Z', 'snapshot': r}
                                  for i, r in enumerate(history)]

    def test_a_dispatched_run_on_screen_is_priced(self):
        self.use(run('now', 'patched', 'skipped', status='awaiting_approval'), [run('old', 'patched')])
        got = appv2.roi_state()
        self.assertEqual(got['run_id'], 'now')
        self.assertFalse(got.get('roi_from_history'))

    def test_an_assessed_or_idle_run_falls_back_to_the_newest_dispatched_one(self):
        self.use({'status': 'idle'}, [run('older', 'patched'), run('newest', 'patched', 'rejected'),
                                      run('skipped-only', 'skipped', 'skipped')])
        got = appv2.roi_state()
        self.assertEqual(got['run_id'], 'newest')          # skipped-only dispatched nothing, so it is passed over
        self.assertTrue(got['roi_from_history'])
        self.assertEqual(got['finished_at'], '2026-11-11T10:00:00Z')

    def test_nothing_anywhere_returns_the_run_on_screen(self):
        self.use({'status': 'idle'}, [run('skipped-only', 'skipped')])
        self.assertEqual(appv2.roi_state(), {'status': 'idle'})



class AssessGuard(unittest.TestCase):
    """A new Assess must not replace a run that is waiting at an approval gate."""

    def setUp(self):
        self.saved = dict(appv2._RUN)

    def tearDown(self):
        appv2._RUN.clear(); appv2._RUN.update(self.saved)

    def put(self, **run):
        appv2._RUN.clear(); appv2._RUN.update(run)

    def test_a_site_at_the_gate_blocks_a_new_assess(self):
        self.put(status='complete', hosts=[{'site': 'lab', 'outcome': 'patched'},
                                           {'site': 'edge-site-1', 'outcome': 'awaiting_approval'}])
        self.assertTrue(appv2.busy())
        code, body = appv2.start_assess('evt-anything')
        self.assertEqual(code, 409)
        self.assertIn('edge-site-1', body['error'])

    def test_a_site_left_dispatching_without_an_execution_does_not_block(self):
        # After a restart mid-dispatch: the run failed, a site never reached AO. Assess must not be locked out.
        self.put(status='failed', hosts=[{'site': 'lab', 'outcome': 'dispatching', 'execution_id': ''}])
        self.assertFalse(appv2.busy())
        self.put(status='failed', hosts=[{'site': 'lab', 'outcome': 'running', 'execution_id': 'abc'}])
        self.assertTrue(appv2.busy())

    def test_a_finished_or_assessed_run_can_be_replaced(self):
        for st in ({'status': 'complete', 'hosts': [{'outcome': 'patched'}, {'outcome': 'rejected'}]},
                   {'status': 'assessed', 'hosts': []}, {'status': 'idle'}):
            self.put(**st)
            self.assertFalse(appv2.busy(), st)


class DiscardBeforeDispatch(unittest.TestCase):
    """Cancel on the run page before anything is dispatched: the run is forgotten, nothing is undone."""

    def setUp(self):
        self.saved = (dict(appv2._RUN), appv2._persist)
        appv2._persist = lambda: None           # never write the real run file from a test

    def tearDown(self):
        run, appv2._persist = self.saved
        appv2._RUN.clear(); appv2._RUN.update(run)

    def put(self, **run):
        appv2._RUN.clear(); appv2._RUN.update(run)

    def test_an_assessed_or_prepared_run_is_dropped_at_once(self):
        for status in ('assessed', 'generated', 'failed'):
            self.put(status=status, run_id='r1', hosts=[{'site': 'lab', 'outcome': 'queued'}])
            code, body = appv2.discard_run()
            self.assertEqual((code, body['pending']), (200, False), status)
            self.assertEqual(appv2.state().get('status'), 'idle')

    def test_cancelled_while_assessing_it_is_dropped_when_the_step_finishes(self):
        self.put(status='assessing', run_id='r1')
        self.assertEqual(appv2.discard_run(), (200, {'ok': True, 'pending': True}))
        self.assertTrue(appv2.busy())                        # the step is still running
        self.assertIn('still stopping', appv2.start_assess('evt-x')[1]['error'])
        appv2._set(status='assessed', impact={'targets': []})    # the step finishes
        self.assertEqual(appv2.state().get('status'), 'idle')
        self.assertNotIn('impact', appv2.state())

    def test_a_dispatched_run_needs_cancel_run(self):
        self.put(status='awaiting_approval', hosts=[{'site': 'edge', 'outcome': 'awaiting_approval'}])
        code, body = appv2.discard_run()
        self.assertEqual(code, 409)
        self.assertIn('Cancel run', body['error'])


if __name__ == '__main__':
    unittest.main()
