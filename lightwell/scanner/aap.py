"""
Launch and follow the remediation job on an Ansible Automation Platform controller.

The job template clones the repository onto a build host, applies the approved dependency changes, builds, and
optionally pushes a branch (see aap-setup/playbooks/app_clone_update_build.yml). This module only talks to the
controller's API: it launches the template with the change list as extra variables and turns the job's status
and events into the stages, and the steps within each, that the page shows. A staged run uses DemoRun instead and never imports a client.

The token is sent only to the controller's own address and never appears in an error message.
"""
from __future__ import annotations

import re
import time
import urllib.parse

from .http import UpstreamError, request

STAGES = ('clone', 'edit', 'build', 'push')
MAX_PAGES = 10
MAX_LOG = 20_000
_ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
_RESULTS = {'runner_on_ok': 'ok', 'runner_on_failed': 'failed', 'runner_on_unreachable': 'failed', 'runner_on_skipped': 'skipped'}
STAGE_LABELS = {'clone': 'Clone the repository', 'edit': 'Update the dependency versions', 'build': 'Build', 'push': 'Push the branch'}
_STAGE_TASK = re.compile(r'^STAGE (\w+): (.*)$')
TEMPLATE = 'App Patch - Clone, Update, Build'


class AapClient:
    def __init__(self, base: str, token: str, template: str = TEMPLATE, limit: str = '', cafile: str | None = None):
        self.base = base.rstrip('/')
        self.token = token
        self.template = template
        self.limit = limit
        self.cafile = cafile

    def _call(self, method: str, path: str, body=None):
        payload, _ = request('AAP', self.base + path, method=method, body=body, retries=1, timeout=30,
                             headers={'Authorization': 'Bearer ' + self.token}, cafile=self.cafile)
        return payload

    def _template_id(self) -> int:
        found = self._call('GET', '/job_templates/?name=' + urllib.parse.quote(self.template))
        for row in found.get('results', []):                                   # type: ignore[union-attr]
            if row.get('name') == self.template:
                return row['id']
        raise UpstreamError('AAP', f'the job template "{self.template}" does not exist. Create it with aap-setup/create-app-patch-objects.py')

    def status(self) -> dict:
        """Whether the token is accepted, the job template exists and, when a build host is set, the controller knows it.
        Launches nothing."""
        try:
            self._call('GET', '/me/')
            tid = self._template_id()
            if self.limit:
                hosts = self._call('GET', '/hosts/?name=' + urllib.parse.quote(self.limit))
                if not any(h.get('name') == self.limit for h in hosts.get('results', [])):    # type: ignore[union-attr]
                    return {'ok': False, 'detail': f'The controller has no host named "{self.limit}" (AAP_BUILD_HOST).'}
        except UpstreamError as exc:
            return {'ok': False, 'detail': exc.message}
        where = f' on {self.limit}' if self.limit else ''
        return {'ok': True, 'detail': f'Controller reachable, token accepted, job template "{self.template}" (id {tid}) found{where}.'}

    def launch(self, extra_vars: dict) -> int:
        body: dict = {'extra_vars': extra_vars}
        if self.limit:
            body['limit'] = self.limit
        out = self._call('POST', f'/job_templates/{self._template_id()}/launch/', body)
        job = out.get('job') or out.get('id')                                 # type: ignore[union-attr]
        if not job:
            raise UpstreamError('AAP', 'the controller did not return a job id')
        return int(job)

    def job(self, job_id: int) -> dict:
        return self._call('GET', f'/jobs/{int(job_id)}/')                     # type: ignore[return-value]

    def events(self, job_id: int) -> list[dict]:
        """The job's events in order. Used instead of the stdout endpoint, which refuses a JSON client with HTTP 406."""
        out: list[dict] = []
        for page in range(1, MAX_PAGES + 1):
            got = self._call('GET', f'/jobs/{int(job_id)}/job_events/?order_by=counter&page_size=200&page={page}')
            out += got.get('results', [])                                      # type: ignore[union-attr]
            if not got.get('next'):                                            # type: ignore[union-attr]
                break
        return out


def steps(events: list[dict]) -> list[dict]:
    """Each "STAGE ..." task in the order it started, with how it ended: running, ok, skipped or failed."""
    out: list[dict] = []
    by_id: dict = {}
    for e in events:
        kind = e.get('event')
        if kind == 'playbook_on_task_start':
            m = _STAGE_TASK.match(e.get('task') or '')
            if m:
                out.append({'stage': m.group(1), 'label': m.group(2), 'state': 'running', 'detail': ''})
                by_id[e.get('uuid')] = out[-1]
        elif kind in _RESULTS and by_id.get(e.get('parent_uuid')) is not None:
            step = by_id[e['parent_uuid']]
            step['state'] = _RESULTS[kind]
            msg = str(((e.get('event_data') or {}).get('res') or {}).get('msg') or '')
            if kind != 'runner_on_ok' and msg and 'no_log' not in msg:
                step['detail'] = msg.strip()[:300]
    return out


def failure(events: list[dict]) -> str:
    """The message of the first failed task that is not a stage step: the playbook's own "the build failed" stop."""
    for e in events:
        if e.get('event') == 'runner_on_failed' and not _STAGE_TASK.match(e.get('task') or ''):
            msg = str(((e.get('event_data') or {}).get('res') or {}).get('msg') or '').strip()
            if msg and 'no_log' not in msg:
                return msg[:300]
    return ''


def view(job: dict, events: list[dict], push: bool, push_only: bool = False) -> dict:
    """What the page shows for one job: overall state, each stage with its steps, and the playbook's result once it has one.

    push_only is a run that pushes what an earlier one built, so it has no build stage. The playbook still collects the
    diff under a build step; dropping every step outside `wanted` keeps that one from reading as the stage in progress."""
    status = job.get('status', '')
    state = 'done' if status == 'successful' else 'failed' if status in ('failed', 'error', 'canceled') else 'running'
    wanted = [s for s in STAGES if (s != 'push' or push) and (s != 'build' or not push_only)]
    done = [x for x in steps(events) if x['stage'] in wanted]
    ran = [x for x in done if x['state'] != 'skipped']
    current = ran[-1]['stage'] if ran else None
    stages = []
    for i, s in enumerate(wanted):
        mine = [x for x in done if x['stage'] == s]
        if any(x['state'] == 'failed' for x in mine):
            st = 'failed'
        elif current in wanted and i < wanted.index(current):
            st = 'done'
        elif s == current:
            st = 'running'
        else:
            st = 'pending'
        shown = [{k: x[k] for k in ('label', 'state', 'detail')} for x in mine if x['state'] != 'skipped']
        stages.append({'id': s, 'label': STAGE_LABELS[s], 'state': st, 'actions': shown, 'skipped': len(mine) - len(shown)})
    if state == 'failed':
        for st in stages:
            if st['state'] == 'running':
                st['state'] = 'failed'
    result = (job.get('artifacts') or {}).get('app_patch') if isinstance(job.get('artifacts'), dict) else None
    if result and str(result.get('build_rc', '')).lstrip('-').isdigit():
        result = {**result, 'build_rc': int(result['build_rc'])}
    if state == 'done':
        for st in stages:
            st['state'] = 'done'
            for x in st['actions']:
                if x['state'] == 'running':
                    x['state'] = 'ok'
    log = '\n'.join(_ANSI.sub('', e['stdout']).rstrip() for e in events if e.get('stdout'))
    return {'state': state, 'status': status, 'stages': stages, 'result': result or {}, 'failure': failure(events) if state == 'failed' else '',
            'log': log[-MAX_LOG:]}


class DemoRun:
    """A staged run: the steps are the ones the playbook runs, each with a stand-in duration, and a push ends the way a
    real one does. The diff is made by applying the change list to the recorded manifests. Steps advance with the clock.

    push_only stages the second kind of run: the one behind the Push button, which clones and re-applies the same change
    list and then pushes, without building again. Same shape as the playbook's, so the page cannot tell the two apart."""

    CLONE = (('Start from an empty working directory', 0.6), ('Clone the repository', 3.0), ('Cut the branch from the scanned commit', 0.8))
    EDIT = (('Write the change list and the edit script', 0.6), ('Copy the edit script', 0.6), ('Apply the dependency changes', 1.6),
            ('Read the report', 0.6))
    JAVA = (('Point Maven at the Lightwell repositories', 0.8), ('Look for the build files', 0.6), ('Work out which Java the repository needs', 0.8),
            ('Detect the Java version', 1.2), ('Settle on the Java version', 0.5), ('Check the machine type', 0.5),
            ('Look for an installed JDK of that version', 0.8), ('Look for an installed Maven', 0.8), ('Check for a cached JDK', 0.6),
            ('Check for a cached Maven', 0.6), ('Make the tools directory', 0.5), ('Look up the JDK download', 1.5), ('Download the JDK', 5.0),
            ('Unpack the JDK', 4.0), ('Download Maven', 2.0), ('Unpack Maven', 1.0), ('Record which JDK and Maven will be used', 0.5),
            ('Build with Maven', 12.0), ('Record the build result', 0.5), ('Collect what changed', 1.0))
    PIP = (('Look for the build files', 0.6), ('Build with pip', 8.0), ('Record the build result', 0.5), ('Collect what changed', 1.0))
    PUSH = (('Commit the change', 1.0), ('Push the branch', 2.5))
    CHECK = ('Check the tree is the one that was built', 0.8)
    SKIPPED = {'clone': 1, 'edit': 1, 'build': 3}

    def __init__(self, push: bool, diff: str, report: list[dict], started: float | None = None, java: dict | None = None,
                 maven: bool = True, branch: str = '', build_log: str = '', push_only: bool = False, build_rc: int = 0):
        self.push = push or push_only
        self.push_only = push_only
        self.diff = diff
        self.report = report
        self.java = java or {}
        self.branch = branch
        # A staged build that did not compile. The playbook treats Maven's exit code as data rather than as a task
        # failure -- it records the code, publishes the artifacts and only then fails the job -- so a failed build
        # here has to arrive the same way: every step ok, the stage red, and the reason in the output.
        self.build_rc = 0 if push_only else int(build_rc)
        self.build_log = build_log.rstrip('\n')
        self.steps = {'clone': self.CLONE, 'edit': self.EDIT, 'build': self.JAVA if maven else self.PIP,
                      'push': ((self.CHECK,) if push_only else ()) + self.PUSH}
        self.started = time.monotonic() if started is None else started

    def view(self, now: float | None = None) -> dict:
        t = (time.monotonic() if now is None else now) - self.started
        wanted = [s for s in STAGES if (s != 'push' or self.push) and (s != 'build' or not self.push_only)]
        # A build that did not go green stops the run where it stands. The playbook's commit and push tasks are both
        # guarded on the exit code, so the stage is reached and does nothing -- pending, not skipped and not failed.
        broke = self.build_rc != 0
        stages, cursor = [], 0.0
        for s in wanted:
            if broke and s == 'push':
                stages.append({'id': s, 'label': STAGE_LABELS[s], 'state': 'pending', 'actions': [], 'skipped': 0})
                continue
            actions, at = [], cursor
            for label, seconds in self.steps[s]:
                state = 'ok' if t >= at + seconds else 'running' if t >= at else 'pending'
                if state != 'pending':
                    actions.append({'label': label, 'detail': '', 'state': state})
                at += seconds
            skipped = self.SKIPPED.get(s, 0) if s != 'build' or len(self.steps[s]) == len(self.JAVA) else 0
            # Every step within the build is still ok even when the build is not: Maven ran, and what it had to say is
            # its output. Reddening a step would be pointing at the wrong thing.
            done = t >= at
            stages.append({'id': s, 'label': STAGE_LABELS[s],
                           'state': ('failed' if broke and s == 'build' else 'done') if done else 'running' if t >= cursor else 'pending',
                           'actions': actions, 'skipped': skipped if t >= cursor else 0})
            cursor = at
        finished = t >= cursor
        log = self.build_log.splitlines() if finished else []
        # A push-only run reports the push and nothing else. It did not build, so it has no build result to claim; the
        # one it is pushing belongs to the run before it, and Runs.view() is what puts the two back together.
        result = {'pushed': True, 'push_error': '', 'branch': self.branch} if finished and self.push_only else \
                 {'changes': self.report, 'java': self.java, 'diff': self.diff, 'build_rc': self.build_rc,
                  'pushed': self.push and not broke, 'push_error': '',
                  'branch': self.branch, 'build_tail': '\n'.join(log)} if finished else {}
        ended = 'failed' if broke else 'done'
        return {'state': ended if finished else 'running',
                'status': ('failed' if broke else 'successful') if finished else 'running', 'stages': stages, 'result': result,
                # Word for word the playbook's own stop, because the page shows whichever one it is given and the two
                # must not be tellable apart.
                'failure': f'The build failed (rc {self.build_rc}).' if finished and broke else '',
                'log': '\n'.join(log)}
