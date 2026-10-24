import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.aap import DemoRun, view                                      # noqa: E402

CLONE = ['Start from an empty working directory', 'Clone the repository', 'Cut the branch from the scanned commit']
EDIT = ['Write the change list and the edit script', 'Copy the edit script', 'Apply the dependency changes', 'Read the report']
PUSH = ['Check the tree is the one that was built', 'Commit the change', 'Push the branch']


def events(*done, skipped=()):
    """A job's events, as the controller reports them: (stage, label, result) in the order the playbook runs them."""
    out, n = [], 0
    for stage, label, result in done:
        n += 1
        out.append({'event': 'playbook_on_task_start', 'task': f'STAGE {stage}: {label}', 'uuid': f'u{n}'})
        out.append({'event': result, 'parent_uuid': f'u{n}', 'event_data': {'res': {}}})
    return out


def run(stage, labels, result='runner_on_ok'):
    return [(stage, x, result) for x in labels]


class PushOnlyRuns(unittest.TestCase):
    """A push-only run pushes what an earlier one built. It has no build stage, and the diff the playbook still
    collects under a build step must not read as a stage that is in progress."""

    def test_the_build_stage_is_gone_and_the_rest_are_in_order(self):
        ev = events(*run('clone', CLONE), *run('edit', EDIT),
                    ('build', 'Collect what changed', 'runner_on_ok'), *run('push', PUSH))
        got = view({'status': 'successful'}, ev, push=True, push_only=True)
        self.assertEqual([s['id'] for s in got['stages']], ['clone', 'edit', 'push'])
        self.assertEqual([s['state'] for s in got['stages']], ['done', 'done', 'done'])
        self.assertEqual([a['label'] for a in got['stages'][2]['actions']], PUSH)

    def test_the_collected_diff_does_not_push_the_finished_stages_back_to_pending(self):
        # The moment between the edits and the push: the last step that ran belongs to a stage this run does not have.
        ev = events(*run('clone', CLONE), *run('edit', EDIT), ('build', 'Collect what changed', 'runner_on_ok'))
        # Without that step being dropped, the stage in progress is one this run does not have, and every stage
        # reads as pending -- clone and edit go backwards on the page after they have already finished.
        got = view({'status': 'running'}, ev, push=True, push_only=True)
        self.assertEqual([s['state'] for s in got['stages']], ['done', 'running', 'pending'])

    def test_a_tree_that_does_not_match_the_build_fails_the_push_stage(self):
        ev = events(*run('clone', CLONE), *run('edit', EDIT), ('build', 'Collect what changed', 'runner_on_ok'),
                    ('push', 'Check the tree is the one that was built', 'runner_on_failed'))
        got = view({'status': 'failed'}, ev, push=True, push_only=True)
        self.assertEqual([s['state'] for s in got['stages']], ['done', 'done', 'failed'])

    def test_an_ordinary_run_still_has_all_four_stages(self):
        ev = events(*run('clone', CLONE), *run('edit', EDIT), ('build', 'Build with Maven', 'runner_on_ok'),
                    ('build', 'Collect what changed', 'runner_on_ok'), *run('push', PUSH[1:]))
        got = view({'status': 'successful'}, ev, push=True)
        self.assertEqual([s['id'] for s in got['stages']], ['clone', 'edit', 'build', 'push'])

    def test_a_staged_push_only_run_has_the_same_shape(self):
        d = DemoRun(False, '', [], started=0.0, branch='fix/x', push_only=True)
        got = d.view(now=0.5)
        self.assertEqual([s['id'] for s in got['stages']], ['clone', 'edit', 'push'])
        self.assertEqual(got['result'], {})
        got = d.view(now=10_000)
        self.assertEqual([a['label'] for a in got['stages'][2]['actions']], PUSH)
        # It reports the push and nothing else: the build it pushed belongs to the run before it.
        self.assertEqual(got['result'], {'pushed': True, 'push_error': '', 'branch': 'fix/x'})


if __name__ == '__main__':
    unittest.main()
