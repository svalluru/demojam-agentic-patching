"""
Remediation runs: the part of the scanner that acts on a finished scan.

A run takes one repository from a scan and the sources of a fix the person accepted, works out the change list
(scanner/remediate.py) and has it carried out: by the AAP job in live mode, by a staged replay in demo mode. This
module holds the runs in memory and answers for their progress. Nothing is saved to disk, so a restart forgets
them; the branch a run pushed is the lasting record.
"""
from __future__ import annotations

import difflib
import hashlib
import importlib.util
import re
import tempfile
import threading
import time
import uuid
from pathlib import Path

from scanner.aap import AapClient, DemoRun, view as job_view
from scanner.http import UpstreamError
from scanner.remediate import resolve
from scanner.repo import RepoRef

BRANCH = 'fix/dependency-vulnerabilities'
MAX_RUNS = 50
# What a push-only run is allowed to say about itself. Everything else on the card -- the diff, the build output, the
# JDK, which changes applied -- belongs to the run that built it and is carried over unchanged.
PUSH_KEYS = ('pushed', 'push_error', 'branch')
REGISTRY_BASE = 'https://packages.redhat.com/api/pulp-content/lightwell'
JAVA_VERSIONS = (8, 11, 17, 21)
SCRIPTS = Path(__file__).resolve().parent.parent / 'aap-setup' / 'playbooks' / 'files'
_scripts: dict = {}


def _script(name: str):
    if name not in _scripts:
        spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + '.py'))
        _scripts[name] = importlib.util.module_from_spec(spec)               # type: ignore[arg-type]
        spec.loader.exec_module(_scripts[name])                              # type: ignore[union-attr]
    return _scripts[name]


def edit_script():
    """The script the job runs on the build host, loaded so demo mode edits the recorded files exactly the way the job edits the real ones."""
    return _script('apply_dependency_changes')


def parse_java(value) -> int | None:
    """The JDK the person chose: one of JAVA_VERSIONS, or None to let the repository decide."""
    if value in (None, '', 'auto'):
        return None
    if isinstance(value, bool) or not isinstance(value, (int, str)) or str(value) not in map(str, JAVA_VERSIONS):
        raise ValueError('"java" must be one of ' + ', '.join(map(str, JAVA_VERSIONS)) + ' or left out')
    return int(value)


def find_repo(scan: dict | None, url: str) -> dict:
    for r in (scan or {}).get('repos', []):
        if r.get('url') == url and r.get('status') == 'done':
            return r
    raise ValueError('that repository has no finished result in this scan')


def preview(repo: dict, sources, allow_major: bool = False) -> dict:
    return resolve(repo['findings'], sources, allow_major)


# ------------------------------------------------------------- build failures

# The class file version javac writes, by the JDK that wrote it. javac reports
# both numbers and neither of them is the JDK number, which is why a build log
# that says exactly what is wrong still leaves people guessing.
CLASS_FILE_JDK = {52: 8, 53: 9, 54: 10, 55: 11, 56: 12, 57: 13, 58: 14, 59: 15,
                  60: 16, 61: 17, 62: 18, 63: 19, 64: 20, 65: 21}
_WRONG_VERSION = re.compile(r'class file has wrong version (\d+)\.\d+, should be (\d+)\.\d+')
_BAD_RELEASE = re.compile(r'invalid (?:target|source) release:?\s*([\d.]+)')
_MISSING = re.compile(r'Could not (?:resolve dependencies|find artifact|transfer artifact)')
_API = re.compile(r'\[ERROR\].*?(cannot find symbol|package [\w.]+ does not exist)')


def build_advice(state: dict) -> str:
    """One line on what to change before running the build again, read out of the build's own output.

    Not a demo prop: the live job publishes the same `build_tail`, and these are javac's and Maven's own words. A
    person who already knows that class file 55.0 means Java 11 does not need this line; everybody else is one web
    search away from the fix, in front of an audience. Empty when nothing in the output is recognised, because a
    guess here would send somebody to the wrong control with confidence."""
    res = state.get('result') or {}
    rc = str(res.get('build_rc', ''))
    if state.get('state') == 'running' or rc in ('', '0'):
        return ''
    tail = str(res.get('build_tail') or state.get('log') or '')
    used = (res.get('java') or {}).get('version')
    m = _WRONG_VERSION.search(tail)
    if m:
        needs, has = CLASS_FILE_JDK.get(int(m.group(1))), CLASS_FILE_JDK.get(int(m.group(2)))
        if needs:
            return (f'A dependency is compiled for Java {needs} and the build ran on Java {has or used}. '
                    f'Set "Java for the build" to {needs} and run it again.')
    m = _BAD_RELEASE.search(tail)
    if m:
        return (f'The build ran on Java {used} and the project asks to compile for {m.group(1)}. '
                'Set "Java for the build" to that version or newer and run it again.')
    if _MISSING.search(tail):
        return ('Maven could not fetch one of the new versions. Check the Lightwell repository credentials in '
                'Settings, or untick the source that offered that version and run it again.')
    if _API.search(tail):
        return ('The new version changed an API this project uses, so the fix is not a version bump alone. Untick '
                '"Allow upgrades across a major version", or leave that dependency out and raise it with the owner.')
    return ''


# --------------------------------------------------------------- staged builds

# Repositories whose Lightwell rebuilds need a newer JDK than the repository itself asks for, and the one they need.
# A rebuilt artifact keeps its coordinates and its API but not necessarily its class file version -- Red Hat builds to
# a supported baseline -- and a project still pinned at source level 1.8 cannot read a class file written by 11.
#
# Demo only, and keyed by slug rather than sampled, because a failure that lands on a different repository each run
# cannot be rehearsed and a presenter who cannot rehearse it will not show it. Live mode finds this out the way
# everyone else does: the build fails and the output says why. Nothing here changes what a live job does.
DEMO_JDK_FLOOR: dict[str, int] = {
    'JoyChou93/java-sec-code': 11,
}


def demo_build_rc(slug: str, plan: dict, java_version: int | None) -> int:
    """The exit code a staged Maven build would come back with: 1 when the JDK is too old for what was just pinned.

    Only the Lightwell rebuilds carry the floor, so a run that takes its fixes from OSV alone builds green on the JDK
    the repository asked for -- which is the honest answer, and also what makes the failure worth showing."""
    needs = DEMO_JDK_FLOOR.get(slug)
    rebuilt = any('.rhlw-' in (c.get('to') or '') for c in plan.get('changes') or [])
    return 1 if needs and rebuilt and (java_version or 0) < needs else 0


def commit_message(plan: dict) -> str:
    n = len(plan['changes'])
    lw = sum(1 for c in plan['changes'] if c['source'] != 'osv')
    return f'Clear known vulnerabilities in {n} dependenc{"y" if n == 1 else "ies"}' + (f' ({lw} with Lightwell builds)' if lw else '')


def clone_url(ref: RepoRef) -> str:
    return f'https://{ref.host}/{ref.path}.git'


def demo_diff(plan: dict, manifests: dict[str, str], java: int | None = None) -> tuple[str, list[dict], dict]:
    """Apply the plan to the recorded manifests with the job's own edit script and return a unified diff, the report, and
    the JDK the job would choose (by its own detection script, or the one the person picked)."""
    script = edit_script()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for path, text in manifests.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_bytes(text.encode('utf-8'))
        detected = _script('detect_java').detect(root)
        chosen = {'version': java, 'reason': 'chosen when the run was approved'} if java else {k: detected[k] for k in ('version', 'reason')}
        report = script.run(root, [{k: c[k] for k in ('name', 'from', 'to', 'manifests')} for c in plan['changes']])
        out = []
        for path, text in manifests.items():
            new = (root / path).read_bytes().decode('utf-8')
            if new != text:
                out += difflib.unified_diff(text.splitlines(keepends=True), new.splitlines(keepends=True), f'a/{path}', f'b/{path}')
    return ''.join(out), report, chosen


class Runs:
    def __init__(self):
        self._lock = threading.Lock()
        self._runs: dict[str, dict] = {}

    def _add(self, run: dict) -> str:
        run_id = uuid.uuid4().hex[:12]
        with self._lock:
            self._runs[run_id] = {'id': run_id, 'created': time.time(), **run}
            for old in sorted(self._runs, key=lambda k: self._runs[k]['created'])[:-MAX_RUNS]:
                del self._runs[old]
        return run_id

    def start_demo(self, repo: dict, plan: dict, push: bool, manifests: dict[str, str], java: int | None = None, build_log: str = '',
                   fail_log: str = '') -> str:
        diff, report, chosen = demo_diff(plan, manifests, java)
        # Whether this one compiles, decided before the clock starts so the run is the same run however long the page
        # is left open. The failing log is a second recording, not a doctored copy of the first.
        rc = demo_build_rc(repo.get('slug') or repo.get('url') or '', plan, chosen.get('version'))
        return self._add({'mode': 'demo', 'url': repo['url'], 'plan': plan, 'push': push,
                          'demo': DemoRun(push, diff, report, java=chosen, branch=BRANCH, build_log=fail_log if rc else build_log,
                                          build_rc=rc, maven=any(m.endswith('pom.xml') for m in manifests))})

    def start_live(self, client: AapClient, repo: dict, ref: RepoRef, plan: dict, push: bool, java: int | None = None) -> str:
        """Launches the job. Raises UpstreamError when the controller cannot be reached or refuses."""
        run_id = uuid.uuid4().hex[:12]
        extra = {
            'patch_run_id': run_id, 'repo_url': clone_url(ref), 'repo_host': ref.host, 'commit': repo.get('commit') or '',
            'new_branch': BRANCH, 'subdir': ref.subpath.strip('/'), 'push': push, 'commit_message': commit_message(plan),
            'changes': [{k: c[k] for k in ('name', 'from', 'to', 'manifests')} for c in plan['changes']], 'registry': plan['registry'],
            'registry_base': REGISTRY_BASE,
        }
        if java:
            extra['java_version'] = java
        if not extra['commit']:
            raise UpstreamError('AAP', 'the scan did not record a commit to build from')
        job = client.launch(extra)
        with self._lock:
            # ref and commit are kept so a later push can be launched from this run alone, without going back to the scan.
            self._runs[run_id] = {'id': run_id, 'created': time.time(), 'mode': 'live', 'url': repo['url'], 'plan': plan, 'push': push,
                                  'ref': ref, 'commit': extra['commit'], 'client': client, 'job': job}
        return run_id

    def start_push(self, client: AapClient | None, run_id: str) -> str:
        """Pushes the branch an earlier run built, without building it again.

        The build is the expensive half and it already passed, so running it a second time buys nothing and can only
        disagree with itself. The job still clones and re-applies the same change list -- there is no working directory
        left on the build host between two AAP jobs -- but that is seconds, and it is deterministic from the same
        commit, so the tree it commits is the tree that was verified. The playbook checks that before it pushes.
        ValueError when the run cannot be pushed, UpstreamError when the controller cannot be reached."""
        with self._lock:
            parent = self._runs.get(run_id)
        if parent is None:
            raise ValueError('that run is not in this process any more. Build it again and push from the new result.')
        done = self.view(run_id) or {}
        res = done.get('result') or {}
        if done.get('state') != 'done' or str(res.get('build_rc')) != '0':
            raise ValueError('only a finished build that went green can be pushed')
        if res.get('pushed'):
            raise ValueError('that branch has already been pushed')
        if parent['mode'] == 'demo':
            return self._add({'mode': 'demo', 'url': parent['url'], 'plan': parent['plan'], 'push': True, 'parent': run_id,
                              'demo': DemoRun(True, '', [], branch=BRANCH, push_only=True)})
        if client is None:
            raise ValueError('remediation is not configured, so there is nothing to push with')
        ref, plan = parent['ref'], parent['plan']
        new_id = uuid.uuid4().hex[:12]
        diff = res.get('diff') or ''
        extra = {
            'patch_run_id': new_id, 'repo_url': clone_url(ref), 'repo_host': ref.host, 'commit': parent['commit'],
            'new_branch': BRANCH, 'subdir': ref.subpath.strip('/'), 'push': True, 'push_only': True,
            'commit_message': commit_message(plan),
            'changes': [{k: c[k] for k in ('name', 'from', 'to', 'manifests')} for c in plan['changes']], 'registry': plan['registry'],
            'registry_base': REGISTRY_BASE,
            'expected_diff_sha256': hashlib.sha256(diff.encode('utf-8')).hexdigest() if diff else '',
        }
        job = client.launch(extra)
        with self._lock:
            self._runs[new_id] = {'id': new_id, 'created': time.time(), 'mode': 'live', 'url': parent['url'], 'plan': plan,
                                  'push': True, 'parent': run_id, 'ref': ref, 'commit': parent['commit'], 'client': client, 'job': job}
        return new_id

    def _carry(self, run: dict, state: dict) -> dict:
        """A push-only run shows the card the run before it left behind, with only the push lines its own."""
        if 'parent' not in run:
            return state
        base = (self.view(run['parent']) or {}).get('result') or {}
        mine = state.get('result') or {}
        return {**state, 'result': {**base, **{k: mine[k] for k in PUSH_KEYS if k in mine}}}

    @staticmethod
    def _seen(head: dict, state: dict) -> dict:
        """One card, with the next step added when the build has one. Every way of reaching a finished run goes
        through here, so a live job and a staged one cannot end up saying different amounts about the same failure."""
        out = {**head, **state}
        out['advice'] = build_advice(out)
        return out

    def view(self, run_id: str) -> dict | None:
        with self._lock:
            run = self._runs.get(run_id)
        if run is None:
            return None
        head = {'id': run['id'], 'mode': run['mode'], 'url': run['url'], 'push': run['push'], 'plan': run['plan'], 'branch': BRANCH,
                'push_only': 'parent' in run}
        if run['mode'] == 'demo':
            return self._seen(head, self._carry(run, run['demo'].view()))
        if 'final' in run:
            return self._seen(head, self._carry(run, run['final']))
        client, job = run['client'], run['job']
        try:
            state = job_view(client.job(job), client.events(job), run['push'], 'parent' in run)
        except UpstreamError as exc:
            return {**head, 'state': 'unknown', 'status': '', 'stages': [], 'result': {}, 'log': '', 'error': exc.message, 'advice': ''}
        if state['state'] != 'running':
            with self._lock:
                run['final'] = state
        return self._seen(head, self._carry(run, state))
