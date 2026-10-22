#!/usr/bin/env python3
"""
Lightwell dependency scanner: API and page.

Point it at GitHub or GitLab repositories and it reports the known vulnerabilities in their
dependencies. From a finished scan it can also run a remediation: clone the repository, change the versions that were
approved, build, and optionally push a branch, as an AAP job (see remediation.py).

Standard library only, like the rest of this repository. Shares no code and no state with the console. The
console's server (frontend/server.py) loads this module and hands it every request under /lightwell/, so no
second port is needed. Run directly, it listens on port 8790 by default.

    ./start.sh                       demo mode: recorded data, no network
    LIGHTWELL_MODE=live ./start.sh   real GitHub / GitLab and OSV.dev calls

  GET  /                      the page
  GET  /healthz
  GET  /v1/mode               mode, supported GitLab hosts, recorded demo repositories, which tokens are set
  GET  /v1/lightwell/status   checks the Lightwell API credentials (live mode); never shows the secret
  GET  /v1/remediation/status checks the AAP controller, token, job template and build host (live mode); launches nothing
  GET  /v1/repos              saved repository list      PUT /v1/repos  {"repos": [...]}
  POST /v1/scans              {"repos": [...], "reuse": "<scan id>"} -> 202 {"id": ..., "reused": n}; reuse carries over that scan's finished results
  GET  /v1/scans              recent scans
  GET  /v1/scans/{id}         one scan, with findings
  GET  /v1/scans/{id}/findings.csv
  POST /v1/remediations/preview  {"scan", "url", "sources": ["lightwell", "another", "osv"]} -> the changes that choice would make
  POST /v1/remediations          same, plus "push": true to push the branch -> 202 {"id"}; runs on AAP (live) or is staged (demo)
  GET  /v1/remediations/{id}     stages, the diff and the build result
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from remediation import Runs, commit_message, find_repo, parse_java, preview  # noqa: E402
from scanner.aap import TEMPLATE, AapClient                                # noqa: E402
from scanner.http import UpstreamError                                    # noqa: E402
from scanner.github import GitHubClient                                    # noqa: E402
from scanner.gitlab import GitLabClient                                    # noqa: E402
from scanner.lightwell import make_catalog                                 # noqa: E402
from scanner.osv import FixtureOsv, OsvClient
from scanner.pom import CENTRAL_URL, CentralFetcher                              # noqa: E402
from scanner.repo import DemoRepos, RepoRouter, allowed_gitlab_hosts, parse_repo   # noqa: E402
from scanner.scan import now_iso, scan_repository                          # noqa: E402
from store import SCAN_ID, Store                                           # noqa: E402


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        v = v.split('  #', 1)[0].strip().strip('"').strip("'")
        if v:
            os.environ.setdefault(k.strip(), v)


load_dotenv(ROOT / '.env')
load_dotenv(ROOT.parent / '.env')


def env(key: str, default: str = '') -> str:
    return os.environ.get(key, default).strip()


MODE = env('LIGHTWELL_MODE', 'demo').lower()
if MODE not in ('demo', 'live'):
    sys.exit(f'LIGHTWELL_MODE must be demo or live, not {MODE!r}')
HOST = env('LIGHTWELL_HOST', '127.0.0.1')
PORT = int(env('LIGHTWELL_PORT', '8790'))
GITHUB_TOKEN = env('GITHUB_TOKEN')
POM_RESOLUTION = env('RESOLVE_POMS', 'all' if MODE == 'live' else 'off').lower()
if POM_RESOLUTION not in ('off', 'repo', 'all'):
    POM_RESOLUTION = 'all' if MODE == 'live' else 'off'
RANGES = env('RESOLVE_RANGES', 'on' if MODE == 'live' else 'off').lower() in ('on', 'true', '1', 'yes')
POM_FETCH = CentralFetcher(env('MAVEN_REPO_URL', CENTRAL_URL) or CENTRAL_URL)       # one cache for every scan: a published POM never changes
GITLAB_HOSTS = allowed_gitlab_hosts(env('GITLAB_HOSTS').split(','))     # gitlab.com plus any self-hosted hosts listed


def _gitlab_tokens() -> dict[str, str]:
    """A token belongs to one host and is sent only there. GITLAB_TOKEN is for gitlab.com; GITLAB_TOKENS is
    comma-separated host=token pairs for any host."""
    tokens = {}
    for pair in env('GITLAB_TOKENS').split(','):
        host, sep, token = pair.strip().partition('=')
        if sep and host.strip() and token.strip():
            tokens[host.strip().lower()] = token.strip()
    if env('GITLAB_TOKEN'):
        tokens.setdefault('gitlab.com', env('GITLAB_TOKEN'))
    return tokens


GITLAB_TOKENS = _gitlab_tokens()
AAP_BASE_URL = env('AAP_BASE_URL')
AAP_TOKEN = env('AAP_TOKEN')
MAX_REPOS = 25
MAX_BODY = 64 * 1024

STORE = Store(ROOT / 'data')
RUNS = Runs()
DEMO_DIR = ROOT / 'demo'
_LOCK = threading.Lock()
SCANS: dict[str, dict] = {}


def log(msg: str) -> None:
    print(f'{time.strftime("%H:%M:%S")} [lightwell] {msg}', file=sys.stderr, flush=True)


# ------------------------------------------------------------------ scanning

def make_clients():
    if MODE == 'demo':
        return DemoRepos(DEMO_DIR / 'repos'), FixtureOsv(DEMO_DIR / 'osv.json'), make_catalog(MODE, DEMO_DIR, env)
    router = RepoRouter(GitHubClient(GITHUB_TOKEN, api=env('GITHUB_API', 'https://api.github.com')),
                        {h: GitLabClient(h, GITLAB_TOKENS.get(h, '')) for h in GITLAB_HOSTS})
    return router, OsvClient(env('OSV_BASE_URL', 'https://api.osv.dev')), make_catalog(MODE, DEMO_DIR, env)


def clean_repos(raw: object) -> list[str]:
    if not isinstance(raw, list):
        raise ValueError('"repos" must be a list')
    out = []
    for item in raw:
        if not isinstance(item, str):
            raise ValueError('each repository must be a string')
        item = item.strip()
        if not item:
            continue
        parse_repo(item, GITLAB_HOSTS)                     # raises ValueError with a readable reason
        if item not in out:
            out.append(item)
    if not out:
        raise ValueError('give at least one repository')
    if len(out) > MAX_REPOS:
        raise ValueError(f'at most {MAX_REPOS} repositories per scan')
    return out


def overview(scan: dict) -> dict:
    done = [r for r in scan['repos'] if r.get('status') == 'done']
    return {
        'id': scan['id'], 'created': scan['created'], 'mode': scan['mode'], 'status': scan['status'],
        'repos': len(scan['repos']), 'failed': sum(1 for r in scan['repos'] if r.get('status') == 'error'),
        'issues': sum(r.get('summary', {}).get('issues', 0) for r in done),
        'vulnerable_components': sum(r.get('summary', {}).get('vulnerable_components', 0) for r in done),
    }


MAX_LOG = 200


def progress_writer(entry: dict):
    """Returns the callback scan_repository reports to. It keeps the latest state of each step and a capped activity log on the
    entry, in memory only: the finished result replaces the entry, so none of this is stored with the scan."""
    prog = entry['progress'] = {'started': time.time(), 'steps': {}, 'log': []}

    def report(step: str, state: str, detail: str = '', done: int | None = None, total: int | None = None) -> None:
        now = time.time()
        with _LOCK:
            s = prog['steps'].setdefault(step, {'state': 'waiting', 'detail': '', 'done': None, 'total': None, 'at': now})
            if s['state'] != state:
                s['at'] = now
            s.update({'state': state, 'detail': detail, 'done': done, 'total': total})
            if len(prog['log']) < MAX_LOG:
                prog['log'].append({'t': round(now - prog['started'], 1), 'step': step, 'state': state, 'text': detail})
    return report


def run_scan(scan_id: str) -> None:
    repos, osv, catalog = make_clients()
    with _LOCK:
        scan = SCANS[scan_id]
    for i, entry in enumerate(scan['repos']):
        if entry.get('reused'):
            continue
        with _LOCK:
            entry['status'] = 'running'
        log(f'scan {scan_id}: {entry["url"]}')
        try:
            result = scan_repository(entry['url'], repos, osv, catalog, GITLAB_HOSTS, progress_writer(entry), POM_RESOLUTION, POM_FETCH, RANGES)
        except Exception as exc:                           # a bug must not leave a scan "running" forever
            log(f'scan {scan_id}: unexpected {type(exc).__name__}: {exc}')
            result = {'url': entry['url'], 'status': 'error', 'error': f'unexpected error: {type(exc).__name__}'}
        with _LOCK:
            scan['repos'][i] = result
            STORE.save_scan(scan)
    with _LOCK:
        scan['status'] = 'done'
        scan['finished'] = now_iso()
        STORE.save_scan(scan)
    log(f'scan {scan_id}: finished')


def _repo_key(spec: str) -> tuple[str, str, str, str]:
    ref = parse_repo(spec, GITLAB_HOSTS)
    return ref.host, ref.path.lower(), ref.ref, ref.subpath


def finished_results(scan_id: object) -> dict:
    """The finished repository results of an earlier scan from this mode, by repository, for a new scan to carry over.
    Failed ones are left out so they run again. An unknown id, or a scan from the other mode, gives nothing."""
    if not isinstance(scan_id, str) or not SCAN_ID.match(scan_id):
        return {}
    old = get_scan(scan_id)
    if not old or old.get('mode') != MODE:
        return {}
    out = {}
    for r in old['repos']:
        if r.get('status') == 'done':
            try:
                out.setdefault(_repo_key(r['url']), r)
            except ValueError:
                pass
    return out


def start_scan(repos: list[str], reuse: object = None) -> tuple[str | None, int]:
    """Starts a scan of `repos` and returns (id, how many were carried over from the scan `reuse`). The id is None when every
    repository was carried over and so there is nothing new to run."""
    held = finished_results(reuse)
    entries = []
    for r in repos:
        prior = held.get(_repo_key(r))
        entries.append({**prior, 'url': r, 'reused': True, 'reused_from': reuse} if prior else {'url': r, 'status': 'queued'})
    carried = sum(1 for e in entries if e.get('reused'))
    if carried == len(entries):
        return None, carried
    scan_id = uuid.uuid4().hex[:12]
    scan = {'id': scan_id, 'created': now_iso(), 'mode': MODE, 'status': 'running', 'repos': entries}
    with _LOCK:
        SCANS[scan_id] = scan
        STORE.save_scan(scan)
    threading.Thread(target=run_scan, args=(scan_id,), daemon=True, name=f'scan-{scan_id}').start()
    return scan_id, carried


def get_scan(scan_id: str) -> dict | None:
    with _LOCK:
        if scan_id in SCANS:
            out = json.loads(json.dumps(SCANS[scan_id]))
            for r in out['repos']:
                if r.get('progress'):
                    r['progress']['now'] = time.time()
            return out
    return STORE.load_scan(scan_id)


def _cell(value: object) -> str:
    s = '' if value is None else str(value)
    return "'" + s if s[:1] in ('=', '+', '-', '@', '\t', '\r') else s     # spreadsheet formula guard


def findings_csv(scan: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(['repository', 'host', 'commit', 'ecosystem', 'package', 'version', 'declared_range', 'declared_in', 'advisory', 'cve',
                'severity', 'score', 'fixed_versions', 'suggested_fix', 'fix_clears_all', 'lightwell_status',
                'lightwell_build', 'lightwell_build_date', 'lightwell_fixes_this', 'lightwell_severity', 'lightwell_nearest_version',
                'lightwell_lead_days', 'sample_coverage', 'url'])
    for r in scan['repos']:
        for f in r.get('findings', []):
            c = f['component']
            for v in f['vulns']:
                w.writerow([_cell(x) for x in (r.get('slug', r['url']), r.get('host', ''), r.get('commit', '')[:12], c['ecosystem'],
                                               c['name'], c['version'], ' '.join(c.get('ranges', [])), ' '.join(c['sources']), v['id'], v['cve'],
                                               v['severity'], v['score'], ' '.join(v['fixed_versions']),
                                               v['suggested_fix'], f.get('fix_all'), f['lightwell']['status'],
                                               f['lightwell']['build'],
                                               ((f['lightwell'].get('detail') or {}).get('build') or {}).get('created_at', ''),
                                               v.get('lightwell_fixed'), v.get('lightwell_severity'),
                                               ((f['lightwell'].get('versions') or {}).get('nearest') or {}).get('version', ''),
                                               f['lightwell'].get('lead_days', ''),
                                               (r.get('summary', {}).get('lightwell') or {}).get('sample'), v['url'])])
    return buf.getvalue()


# ------------------------------------------------------------------ HTTP API

# ------------------------------------------------------------ remediation

def remediation_status() -> dict:
    if MODE == 'demo':
        return {'ready': True, 'detail': 'Demo mode: a staged run. Nothing is cloned, built or pushed; the diff is made from the recorded files.'}
    if not (AAP_BASE_URL and AAP_TOKEN):
        return {'ready': False, 'detail': 'Set AAP_BASE_URL and AAP_TOKEN in .env to run remediation on the controller.'}
    return {'ready': True, 'detail': f'Runs the job template "{env("AAP_APP_TEMPLATE", TEMPLATE)}" on {AAP_BASE_URL}.'}


def remediation_client() -> AapClient:
    return AapClient(AAP_BASE_URL, AAP_TOKEN, env('AAP_APP_TEMPLATE', TEMPLATE), env('AAP_BUILD_HOST'), env('AAP_CA_BUNDLE') or None)


def _remediation_target(body: dict) -> tuple[dict, list[str]]:
    scan_id = body.get('scan')
    if not isinstance(scan_id, str) or not SCAN_ID.match(scan_id):
        raise ValueError('"scan" must be a scan id')
    url, sources = body.get('url'), body.get('sources')
    if not isinstance(url, str) or not isinstance(sources, list) or not all(isinstance(s, str) for s in sources):
        raise ValueError('"url" must be a repository and "sources" a list')
    scan = get_scan(scan_id)
    if scan is None:
        raise ValueError('scan not found')
    return find_repo(scan, url), sources


def start_remediation(body: dict) -> str:
    """Starts a run for the repository and fix sources in `body` and returns its id. ValueError for a bad request,
    UpstreamError when the controller cannot be reached."""
    repo, sources = _remediation_target(body)
    plan = preview(repo, sources)
    if not plan['changes']:
        raise ValueError('nothing to change with those choices')
    push = body.get('push') is True
    java = parse_java(body.get('java'))
    ref = parse_repo(repo['url'], GITLAB_HOSTS)
    if MODE == 'demo':
        manifests = dict(make_clients()[0].snapshot(ref).manifests)
        return RUNS.start_demo(repo, plan, push, manifests, java)
    if not remediation_status()['ready']:
        raise ValueError(remediation_status()['detail'])
    client = remediation_client()
    log(f'remediation: {repo["url"]} {len(plan["changes"])} changes, push={push}')
    return RUNS.start_live(client, repo, ref, plan, push, java)


class Handler(BaseHTTPRequestHandler):
    server_version = 'lightwell-scanner'

    def log_message(self, fmt, *args):
        pass

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Cache-Control', 'no-store')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, code: int, payload: object) -> None:
        self._send(code, json.dumps(payload).encode(), 'application/json')

    def _error(self, code: int, message: str) -> None:
        self._json(code, {'ok': False, 'error': message})

    def _body(self) -> dict | None:
        try:
            length = int(self.headers.get('Content-Length', '0') or '0')
        except ValueError:
            self._error(400, 'bad Content-Length')
            return None
        if length > MAX_BODY:
            self._error(413, 'request body too large')
            return None
        try:
            data = json.loads(self.rfile.read(length).decode() or '{}')
        except (ValueError, UnicodeDecodeError):
            self._error(400, 'body is not valid JSON')
            return None
        if not isinstance(data, dict):
            self._error(400, 'body must be a JSON object')
            return None
        return data

    def do_GET(self):
        path = urlparse(self.path).path.rstrip('/') or '/'
        if path == '/':
            page = ROOT / 'ui' / 'index.html'
            if page.is_file():
                self._send(200, page.read_bytes(), 'text/html; charset=utf-8')
            else:
                self._error(404, 'ui/index.html not found')
        elif path == '/healthz':
            self._json(200, {'ok': True})
        elif path == '/v1/mode':
            self._json(200, {'ok': True, 'mode': MODE, 'github_token': bool(GITHUB_TOKEN),
                             'gitlab_token': 'gitlab.com' in GITLAB_TOKENS, 'gitlab_hosts': GITLAB_HOSTS, 'pom_resolution': POM_RESOLUTION, 'ranges': RANGES,
                             'demo_repos': DemoRepos(DEMO_DIR / 'repos').available(),
                             'lightwell': make_catalog(MODE, DEMO_DIR, env).describe(), 'remediation': remediation_status()})
        elif path == '/v1/lightwell/status':
            cat = make_catalog(MODE, DEMO_DIR, env)
            check = getattr(cat, 'status', None)
            self._json(200, {'ok': True, **(check() if check else {'source': cat.source, 'ok': cat.sample,
                                                                  'detail': 'Demo mode uses a sample catalog and contacts nothing.'})})
        elif path == '/v1/remediation/status':
            ready = remediation_status()
            self._json(200, {'ok': True, **(remediation_client().status() if MODE == 'live' and ready['ready'] else ready)})
        elif path == '/v1/repos':
            self._json(200, {'ok': True, 'repos': STORE.load_repos()})
        elif path == '/v1/scans':
            with _LOCK:
                live = [overview(s) for s in SCANS.values()]
            known = {s['id'] for s in live}
            saved = [overview(s) for s in STORE.list_scans() if s['id'] not in known]
            self._json(200, {'ok': True, 'scans': sorted(live + saved, key=lambda s: s['created'], reverse=True)[:50]})
        elif path.startswith('/v1/remediations/'):
            run = RUNS.view(path.rsplit('/', 1)[1]) if re.fullmatch(r'/v1/remediations/[0-9a-f]{12}', path) else None
            if run:
                self._json(200, {'ok': True, 'run': run})
            else:
                self._error(404, 'run not found')
        else:
            m = re.match(r'^/v1/scans/([^/]+)(/findings\.csv)?$', path)
            if not m or not SCAN_ID.match(m.group(1)):
                self._error(404, 'not found')
                return
            scan = get_scan(m.group(1))
            if scan is None:
                self._error(404, 'scan not found')
            elif m.group(2):
                self._send(200, findings_csv(scan).encode(), 'text/csv; charset=utf-8',
                           {'Content-Disposition': f'attachment; filename="findings-{scan["id"]}.csv"'})
            else:
                self._json(200, {'ok': True, 'scan': scan})

    def do_PUT(self):
        if urlparse(self.path).path.rstrip('/') != '/v1/repos':
            self._error(404, 'not found')
            return
        body = self._body()
        if body is None:
            return
        try:
            repos = clean_repos(body.get('repos'))
        except ValueError as exc:
            self._error(400, str(exc))
            return
        STORE.save_repos(repos)
        self._json(200, {'ok': True, 'repos': repos})

    def _remediate(self, path: str) -> None:
        body = self._body()
        if body is None:
            return
        try:
            if path == '/v1/remediations/preview':
                repo, sources = _remediation_target(body)
                plan = preview(repo, sources)
                self._json(200, {'ok': True, 'plan': plan, 'message': commit_message(plan) if plan['changes'] else ''})
            else:
                self._json(202, {'ok': True, 'id': start_remediation(body)})
        except ValueError as exc:
            self._error(400, str(exc))
        except UpstreamError as exc:
            self._error(502, exc.message)

    def do_POST(self):
        path = urlparse(self.path).path.rstrip('/')
        if path in ('/v1/remediations', '/v1/remediations/preview'):
            self._remediate(path)
            return
        if path != '/v1/scans':
            self._error(404, 'not found')
            return
        body = self._body()
        if body is None:
            return
        try:
            repos = clean_repos(body.get('repos'))
        except ValueError as exc:
            self._error(400, str(exc))
            return
        scan_id, carried = start_scan(repos, body.get('reuse'))
        if scan_id is None:
            self._json(200, {'ok': True, 'id': None, 'reused': carried, 'message': 'Nothing new to scan: every repository already has a finished result.'})
            return
        self._json(202, {'ok': True, 'id': scan_id, 'reused': carried})


def main() -> None:
    log(f'mode: {MODE}' + ('  (recorded data, no network)' if MODE == 'demo' else
                           f'  (GitHub token {"set" if GITHUB_TOKEN else "not set, 60 API calls an hour"})'))
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    log(f'listening on http://{HOST}:{PORT}')
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log('stopped')


if __name__ == '__main__':
    main()
