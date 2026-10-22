"""
Launch and follow the remediation job on an Ansible Automation Platform controller.

The job template clones the repository onto a build host, applies the approved dependency changes, builds, and
optionally pushes a branch (see aap-setup/playbooks/app_clone_update_build.yml). This module only talks to the
controller's API: it launches the template with the change list as extra variables and turns the job's status
and output into the stages the page shows. Demo mode never imports a client; it uses DemoRun instead.

The token is sent only to the controller's own address and never appears in an error message.
"""
from __future__ import annotations

import re
import time
import urllib.parse

from .http import UpstreamError, request

STAGES = ('clone', 'edit', 'build', 'push')
STAGE_LABELS = {'clone': 'Clone the repository', 'edit': 'Update the dependency versions', 'build': 'Build', 'push': 'Push the branch'}
_STAGE_TASK = re.compile(r'TASK \[STAGE (\w+)')
MAX_LOG = 400_000
TEMPLATE = 'App Patch - Clone, Update, Build'


class AapClient:
    def __init__(self, base: str, token: str, template: str = TEMPLATE, limit: str = '', cafile: str | None = None):
        self.base = base.rstrip('/')
        self.token = token
        self.template = template
        self.limit = limit
        self.cafile = cafile

    def _call(self, method: str, path: str, body=None, raw: bool = False, max_bytes: int | None = None):
        payload, _ = request('AAP', self.base + path, method=method, body=body, raw=raw, max_bytes=max_bytes, retries=1, timeout=30,
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

    def stdout(self, job_id: int) -> str:
        try:
            raw = self._call('GET', f'/jobs/{int(job_id)}/stdout/?format=txt', raw=True, max_bytes=MAX_LOG)
        except UpstreamError as exc:
            if 'larger than' in exc.message:
                return ''
            raise
        return raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else ''


def view(job: dict, output: str, push: bool) -> dict:
    """What the page shows for one job: overall state, each stage, and the playbook's result once it has one."""
    status = job.get('status', '')
    state = 'done' if status == 'successful' else 'failed' if status in ('failed', 'error', 'canceled') else 'running'
    seen = _STAGE_TASK.findall(output or '')
    current = seen[-1] if seen else None
    wanted = [s for s in STAGES if s != 'push' or push]
    stages = []
    for i, s in enumerate(wanted):
        if current in wanted and i < wanted.index(current):
            st = 'done'
        elif s == current:
            st = 'running'
        else:
            st = 'pending'
        stages.append({'id': s, 'label': STAGE_LABELS[s], 'state': st})
    if state == 'failed':
        for st in stages:
            if st['state'] == 'running':
                st['state'] = 'failed'
    result = (job.get('artifacts') or {}).get('app_patch') if isinstance(job.get('artifacts'), dict) else None
    if state == 'done':
        for st in stages:
            st['state'] = 'done'
    return {'state': state, 'status': status, 'stages': stages, 'result': result or {},
            'log': (output or '')[-20_000:]}


class DemoRun:
    """A staged run for demo mode: nothing is cloned, built or pushed. The diff is real, made by applying the change
    list to the recorded manifests; the build output is a labelled stand-in. Stages advance with the clock."""

    PACE = {'clone': 1.2, 'edit': 1.2, 'build': 3.0, 'push': 1.2}

    def __init__(self, push: bool, diff: str, report: list[dict], started: float | None = None, java: dict | None = None):
        self.push = push
        self.diff = diff
        self.report = report
        self.java = java or {}
        self.started = time.monotonic() if started is None else started

    def view(self, now: float | None = None) -> dict:
        t = (time.monotonic() if now is None else now) - self.started
        wanted = [s for s in STAGES if s != 'push' or self.push]
        stages, cursor = [], 0.0
        for s in wanted:
            end = cursor + self.PACE[s]
            stages.append({'id': s, 'label': STAGE_LABELS[s], 'state': 'done' if t >= end else 'running' if t >= cursor else 'pending'})
            cursor = end
        finished = t >= cursor
        log = ['Demo mode: nothing was cloned, built or pushed. The diff below is real; the build is simulated.']
        if finished:
            log += ['[INFO] Scanning for projects...', '[INFO] BUILD SUCCESS (simulated)']
        result = {'demo': True, 'changes': self.report, 'java': self.java, 'diff': self.diff, 'build_rc': 0 if finished else None, 'pushed': False,
                  'build_tail': '\n'.join(log)}
        return {'state': 'done' if finished else 'running', 'status': 'demo', 'stages': stages, 'result': result,
                'log': '\n'.join(log)}
