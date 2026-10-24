"""
Remediation runs: the part of the scanner that acts on a finished scan.

A run takes one repository from a scan and the sources of a fix the person accepted, works out the change list
(scanner/remediate.py) and has it carried out: by the AAP job in live mode, by a staged replay in demo mode. This
module holds the runs in memory and answers for their progress. Nothing is saved to disk, so a restart forgets
them; the branch a run pushed is the lasting record.
"""
from __future__ import annotations

import difflib
import importlib.util
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

    def start_demo(self, repo: dict, plan: dict, push: bool, manifests: dict[str, str], java: int | None = None, build_log: str = '') -> str:
        diff, report, chosen = demo_diff(plan, manifests, java)
        return self._add({'mode': 'demo', 'url': repo['url'], 'plan': plan, 'push': push, 'demo': DemoRun(push, diff, report, java=chosen, branch=BRANCH, build_log=build_log,
                                                                                                           maven=any(m.endswith('pom.xml') for m in manifests))})

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
            self._runs[run_id] = {'id': run_id, 'created': time.time(), 'mode': 'live', 'url': repo['url'], 'plan': plan, 'push': push,
                                  'client': client, 'job': job}
        return run_id

    def view(self, run_id: str) -> dict | None:
        with self._lock:
            run = self._runs.get(run_id)
        if run is None:
            return None
        head = {'id': run['id'], 'mode': run['mode'], 'url': run['url'], 'push': run['push'], 'plan': run['plan'], 'branch': BRANCH}
        if run['mode'] == 'demo':
            return {**head, **run['demo'].view()}
        if 'final' in run:
            return {**head, **run['final']}
        client, job = run['client'], run['job']
        try:
            state = job_view(client.job(job), client.events(job), run['push'])
        except UpstreamError as exc:
            return {**head, 'state': 'unknown', 'status': '', 'stages': [], 'result': {}, 'log': '', 'error': exc.message}
        if state['state'] != 'running':
            with self._lock:
                run['final'] = state
        return {**head, **state}
