"""
Applications v2: event-driven patching of applications already running on servers.

    Lightwell build lands in Nexus ──webhook──▶ Intake agent ──▶ Inventory agent (app BOMs)
        ──▶ Playbook agent (LLM draft, checked) ──▶ AO workflow "App Patch v2":
              Commit to Gitea ─▶ [Approval, Prod only] ─▶ Sync and Run (AAP) ─▶ Verify
        ──▶ Learn (the BOM is updated, so the next event sees the new version)

The console never touches git: committing the playbook and syncing it are AO workflow actions
(AAP job templates), the same pattern as the lab's own Fetch and Commit / Sync and Deploy pair.
This module decides what to change and hands it over; the workflow does it.

Standard library only, like the rest of the console. agentic-patching.py imports it and calls
configure() with the pieces it already owns (env, demo mode, the LLM, the AO client), so nothing
here opens a connection of its own except through those.

Demo mode stages everything and contacts nothing: two Nexus events (real Lightwell builds and the
CVEs Lightwell says they fix, checked against the Lightwell API on 2026-11-05), a small fleet of
apps, and a simulated AO run in which one Prod host fails its health check and is rolled back.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent

# The nine stages of a v2 run, in order. The console's stage bar is drawn from the same keys.
STAGES = ('intake', 'impact', 'generate', 'commit', 'approval', 'sync', 'remediate', 'verify', 'learn')

# Node ids in ao-setup/app_v2_workflow.json. The console reads each one's outcome by id. Sync and Run exists once per
# branch (AO nodes do not join), and its own set_stats (patched / rolled_back, from the generated playbook) is the
# verify result: the playbook checks health and checksum itself and rolls back on failure.
NODE_COMMIT, NODE_APPROVAL = 'commit_to_gitea', 'approval_prod'
NODES_RUN = ('run_app_patch', 'run_app_patch_prod')

RHLW = re.compile(r'^(?P<upstream>.+?)\.rhlw-(?P<build>\d+)(?:-n\d+)?$')

# Modules a generated playbook may use. No command, shell or raw: a playbook the LLM drafted can
# only fetch a file with a pinned checksum, move files, restart a unit and check a URL.
ALLOWED_MODULES = frozenset({
    'ansible.builtin.stat', 'ansible.builtin.get_url', 'ansible.builtin.copy', 'ansible.builtin.file',
    'ansible.builtin.systemd', 'ansible.builtin.systemd_service', 'ansible.builtin.uri',
    'ansible.builtin.set_stats', 'ansible.builtin.assert', 'ansible.builtin.fail', 'ansible.builtin.debug',
})
# Keys that may sit beside a module in a task. Anything else at that indent is read as a module.
TASK_KEYWORDS = frozenset({
    'name', 'register', 'when', 'loop', 'until', 'retries', 'delay', 'vars', 'become', 'tags',
    'ignore_errors', 'changed_when', 'failed_when', 'no_log', 'block', 'rescue', 'always', 'notify',
})


# ---------------------------------------------------------------------------- wiring

class _Hooks:
    env: Callable[[str, str], str] = staticmethod(lambda k, d='': d)
    demo_mode: Callable[[], bool] = staticmethod(lambda: True)
    demo_pause: Callable[[float], None] = staticmethod(lambda f=1.0: None)
    llm: Callable[[str], str] | None = None              # prompt -> answer text
    ao_call: Callable[..., Any] | None = None            # (path, method='GET', body=None)
    fixed_cves: Callable[[str, str, str], list] | None = None   # (group, artifact, version) -> CVE ids


H = _Hooks()


def configure(**kw) -> None:
    for k, v in kw.items():
        setattr(H, k, v)


def env(key: str, default: str = '') -> str:
    return (H.env(key, default) or default).strip()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


# ---------------------------------------------------------------------------- demo data

# Real Lightwell facts (registry and /advisories, 2026-11-05). The apps and servers are staged.
DEMO_EVENTS = [
    {'id': 'evt-log4j-core', 'source': 'nexus', 'repository': 'lightwell-remediated', 'format': 'maven2',
     'group': 'org.apache.logging.log4j', 'artifact': 'log4j-core', 'version': '2.24.3.rhlw-00004',
     'received_at': '2026-11-05T18:37:12Z',
     'cves': ['CVE-2025-68161', 'CVE-2026-34477', 'CVE-2026-34478', 'CVE-2026-34480'],
     'cves_source': 'lightwell'},
    {'id': 'evt-commons-io', 'source': 'nexus', 'repository': 'lightwell-remediated', 'format': 'maven2',
     'group': 'commons-io', 'artifact': 'commons-io', 'version': '2.11.0.rhlw-00009',
     'received_at': '2026-11-05T17:02:40Z',
     'cves': ['CVE-2024-47554'], 'cves_source': 'lightwell'},
]

DEMO_BOM = [
    {'app': 'orders-service', 'owner': 'payments', 'path': '/opt/apps/orders-service', 'service': 'orders-service',
     'health_url': 'http://localhost:8080/actuator/health',
     'servers': [{'host': 'orders-qa-01.acme.internal', 'env': 'qa'},
                 {'host': 'orders-prod-01.acme.internal', 'env': 'prod'},
                 {'host': 'orders-prod-02.acme.internal', 'env': 'prod'}],
     'dependencies': [{'group': 'org.apache.logging.log4j', 'artifact': 'log4j-core', 'version': '2.24.3'},
                      {'group': 'org.apache.logging.log4j', 'artifact': 'log4j-api', 'version': '2.24.3'},
                      {'group': 'commons-io', 'artifact': 'commons-io', 'version': '2.16.1'}]},
    {'app': 'billing-api', 'owner': 'payments', 'path': '/opt/apps/billing-api', 'service': 'billing-api',
     'health_url': 'http://localhost:8081/health',
     'servers': [{'host': 'billing-prod-01.acme.internal', 'env': 'prod'}],
     'dependencies': [{'group': 'org.apache.logging.log4j', 'artifact': 'log4j-core', 'version': '2.24.3'},
                      {'group': 'commons-io', 'artifact': 'commons-io', 'version': '2.11.0'}]},
    {'app': 'catalog-web', 'owner': 'storefront', 'path': '/opt/apps/catalog-web', 'service': 'catalog-web',
     'health_url': 'http://localhost:8082/health',
     'servers': [{'host': 'catalog-qa-01.acme.internal', 'env': 'qa'},
                 {'host': 'catalog-prod-01.acme.internal', 'env': 'prod'}],
     'dependencies': [{'group': 'org.apache.logging.log4j', 'artifact': 'log4j-core', 'version': '2.25.1'},
                      {'group': 'commons-io', 'artifact': 'commons-io', 'version': '2.11.0'}]},
]

# The staged failure: this host's health check fails after the swap and the playbook rolls it back.
DEMO_FAILING_HOST = 'orders-prod-02.acme.internal'


# ---------------------------------------------------------------------------- versions

def upstream(version: str) -> str:
    """'2.24.3.rhlw-00004' -> '2.24.3'. A version with no Lightwell suffix is returned as is."""
    m = RHLW.match(version or '')
    return m.group('upstream') if m else (version or '')


def is_lightwell(version: str) -> bool:
    return bool(RHLW.match(version or ''))


# ---------------------------------------------------------------------------- intake (Nexus)

def verify_signature(body: bytes, signature: str, secret: str) -> bool:
    """Nexus signs a webhook body with HMAC-SHA1 of the shared secret, hex, in X-Nexus-Webhook-Signature."""
    if not secret or not signature:
        return False
    want = hmac.new(secret.encode(), body, hashlib.sha1).hexdigest()
    return hmac.compare_digest(want, signature.strip().lower())


def parse_nexus(payload: dict) -> dict | None:
    """An event from a Nexus repository-component webhook, or None if it is not a new Lightwell build.

    Only CREATED components count: Nexus also reports updates and deletes, and a proxy repository
    reports a component the first time it caches it, which is exactly when a new build arrives."""
    if not isinstance(payload, dict) or str(payload.get('action', '')).upper() != 'CREATED':
        return None
    comp = payload.get('component') or {}
    version = str(comp.get('version') or '')
    if (comp.get('format') or payload.get('format')) not in ('maven2', None) or not is_lightwell(version):
        return None
    group, artifact = str(comp.get('group') or ''), str(comp.get('name') or '')
    if not group or not artifact:
        return None
    return {'id': f'evt-{uuid.uuid4().hex[:10]}', 'source': 'nexus',
            'repository': payload.get('repositoryName', ''), 'format': 'maven2',
            'group': group, 'artifact': artifact, 'version': version,
            'received_at': now_iso(), 'cves': [], 'cves_source': 'pending'}


class EventStore:
    """The inbox. A JSON file in live mode, so events survive a restart; memory in demo mode."""

    def __init__(self, path: Path | None):
        self.path, self._lock, self._items = path, threading.Lock(), None

    def _load(self) -> list[dict]:
        if self._items is None:
            if self.path is None:
                self._items = [dict(e) for e in DEMO_EVENTS]
            else:
                try:
                    self._items = json.loads(self.path.read_text())
                except (OSError, ValueError):
                    self._items = []
        return self._items

    def _save(self) -> None:
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix('.tmp')
            tmp.write_text(json.dumps(self._items, indent=1))
            tmp.replace(self.path)

    def all(self) -> list[dict]:
        with self._lock:
            return sorted((dict(e) for e in self._load()), key=lambda e: e.get('received_at', ''), reverse=True)

    def get(self, event_id: str) -> dict | None:
        with self._lock:
            return next((dict(e) for e in self._load() if e['id'] == event_id), None)

    def add(self, event: dict) -> dict:
        """Idempotent on the build: Nexus retries a webhook, and a second copy is not a second event."""
        with self._lock:
            items = self._load()
            for e in items:
                if (e['group'], e['artifact'], e['version']) == (event['group'], event['artifact'], event['version']):
                    return dict(e)
            items.append(dict(event))
            self._save()
            return dict(event)

    def update(self, event_id: str, **fields) -> None:
        with self._lock:
            for e in self._load():
                if e['id'] == event_id:
                    e.update(fields)
            self._save()


# ---------------------------------------------------------------------------- new builds (Nexus poller)
#
# Lightwell does not announce a new build (its webhook is "TBD" on the diagram), and a Nexus proxy only learns of a
# build when something asks for it. So this asks: for every library in the app BOMs, read maven-metadata.xml through
# the proxy, and request the jar of any Lightwell build of an installed version that has not been seen before. Nexus
# caches it, and its repository webhook calls /api/v2/webhook. With NEXUS_EVENTS=poller (for a Nexus without
# webhooks) the poller records the event itself.

def _versions(xml: str) -> list[str]:
    return re.findall(r'<version>([^<]+)</version>', xml or '')


def poll_nexus(fetch: Callable[[str], bytes], seen: set[str], apps: list[dict] | None = None) -> list[dict]:
    """One pass. fetch(url) -> bytes (raises on HTTP errors). Returns the builds requested this pass; adds them to seen."""
    base = env('NEXUS_URL').rstrip('/')
    repo = env('NEXUS_REPOSITORY', 'lightwell-remediated')
    if not base:
        return []
    wanted: dict[tuple[str, str], set[str]] = {}
    for app in (apps if apps is not None else load_bom()):
        for dep in app.get('dependencies', []):
            wanted.setdefault((dep['group'], dep['artifact']), set()).add(dep.get('version', ''))
    found = []
    for (group, artifact), installed in sorted(wanted.items()):
        path = f"{base}/repository/{repo}/{group.replace('.', '/')}/{artifact}"
        try:
            versions = _versions(fetch(f'{path}/maven-metadata.xml').decode('utf-8', 'replace'))
        except Exception:
            continue                       # not in Lightwell, or Nexus is down; next pass tries again
        for v in versions:
            key = f'{group}:{artifact}:{v}'
            if key in seen or not is_lightwell(v) or upstream(v) not in installed:
                continue
            try:
                fetch(f'{path}/{v}/{jar_name(artifact, v)}')       # this is what makes Nexus cache it
            except Exception:
                continue
            seen.add(key)
            ev = {'id': f'evt-{uuid.uuid4().hex[:10]}', 'source': 'nexus-poller', 'repository': repo,
                  'format': 'maven2', 'group': group, 'artifact': artifact, 'version': v,
                  'received_at': now_iso(), 'cves': [], 'cves_source': 'pending'}
            if env('NEXUS_EVENTS', 'webhook') == 'poller':
                enrich(events().add(ev))
            found.append(ev)
    return found


def poller_loop() -> None:
    """Live mode only, started by the console when NEXUS_POLL_SECONDS > 0."""
    import urllib.request
    state_file = ROOT / 'runs' / 'nexus-poller.json'
    try:
        seen = set(json.loads(state_file.read_text()))
    except (OSError, ValueError):
        seen = set()

    def fetch(url: str) -> bytes:
        with urllib.request.urlopen(url, timeout=60) as r:
            return r.read()

    while True:
        if not H.demo_mode():
            if poll_nexus(fetch, seen):
                state_file.parent.mkdir(parents=True, exist_ok=True)
                state_file.write_text(json.dumps(sorted(seen)))
        time.sleep(max(30, int(env('NEXUS_POLL_SECONDS', '300') or 300)))


# ---------------------------------------------------------------------------- inventory (app BOMs)

def bom_dir() -> Path:
    return Path(env('BOM_DIR', str(ROOT / 'rag-setup' / 'data' / 'bom')))


def load_bom() -> list[dict]:
    """Every app's BOM. Demo: the staged fleet. Live: one JSON file per app under BOM_DIR, the same
    records rag-setup/ingest.py --bom loads into the BOM vector store for the LLM's context."""
    if H.demo_mode():
        apps = json.loads(json.dumps(DEMO_BOM))
    else:
        apps = []
        for f in sorted(bom_dir().glob('*.json')):
            try:
                rec = json.loads(f.read_text())
            except (OSError, ValueError):
                continue
            apps += rec if isinstance(rec, list) else [rec]
    for app in apps:                      # write-backs from earlier runs, newest last
        for dep in app.get('dependencies', []):
            key = f"{app['app']}|{dep['group']}:{dep['artifact']}"
            if key in _BOM_UPDATES:
                dep['version'] = _BOM_UPDATES[key]
    return apps


_BOM_UPDATES: dict[str, str] = {}


def impact(event: dict, apps: list[dict]) -> dict:
    """Which deployed apps and servers run the vulnerable version this build replaces.

    Exact match on group, artifact and version: a Lightwell build fixes one upstream version, and an
    app on any other version of the same library is not helped by it. Those are listed apart, so a
    reviewer can see the library is there and why it was left alone."""
    want = upstream(event['version'])
    targets, other = [], []
    for app in apps:
        for dep in app.get('dependencies', []):
            if (dep.get('group'), dep.get('artifact')) != (event['group'], event['artifact']):
                continue
            if dep.get('version') == want:
                for s in app.get('servers', []):
                    targets.append({'app': app['app'], 'owner': app.get('owner', ''), 'host': s['host'],
                                    'env': s.get('env', 'prod'), 'path': app.get('path', ''),
                                    'service': app.get('service', app['app']),
                                    'health_url': app.get('health_url', ''), 'installed': dep['version']})
            elif dep.get('version') == event['version']:
                other.append({'app': app['app'], 'installed': dep['version'], 'why': 'already on this build'})
            else:
                other.append({'app': app['app'], 'installed': dep.get('version', ''),
                              'why': f'different version; this build replaces {want} only'})
    # QA first, so a bad build shows up where it costs least.
    targets.sort(key=lambda t: (t['env'] != 'qa', t['app'], t['host']))
    return {'targets': targets, 'other': other, 'apps': sorted({t['app'] for t in targets})}


def helpful_info(event: dict, imp: dict) -> tuple[str, str]:
    """(text, source). The agent's note for the reviewer: what is affected and in what order to patch."""
    t = imp['targets']
    qa = [x for x in t if x['env'] == 'qa']
    prod = [x for x in t if x['env'] != 'qa']
    pkg = f"{event['artifact']} {upstream(event['version'])}"
    if not t:
        return (f'No deployed app runs {pkg}, so nothing needs patching for this build. '
                + (f"{len(imp['other'])} app(s) use another version of {event['artifact']}." if imp['other'] else ''),
                'rules')
    facts = (f"{pkg} is in {len(imp['apps'])} app(s) ({', '.join(imp['apps'])}) on {len(t)} server(s): "
             f"{len(qa)} QA, {len(prod)} Prod. The build {event['version']} fixes "
             f"{', '.join(event.get('cves') or []) or 'CVEs not yet itemised by Lightwell'}.")
    if H.llm and not H.demo_mode():
        prompt = ('You are helping an operator review an application patch. In 3 short sentences, say what '
                  'is affected, the order to patch in (QA before Prod), and anything a reviewer should watch '
                  'for when the jar is swapped and the service restarted. Begin with the finding itself, no '
                  f'preamble.\n\nFacts: {facts}\nServers: '
                  + '; '.join(f"{x['host']} ({x['env']}, {x['app']})" for x in t))
        try:
            return H.llm(prompt), 'llm'
        except Exception:
            pass                           # the facts alone are still the right answer
    order = ('Patch QA first' + (f" ({', '.join(x['host'].split('.')[0] for x in qa)})" if qa else '')
             + (f"; Prod waits for your approval ({len(prod)} server(s))." if prod else '.'))
    return f'{facts} {order} Each server keeps a backup of the old jar and rolls back if the health check fails.', \
        'rules' if not H.demo_mode() else 'staged'


# ---------------------------------------------------------------------------- playbook

def jar_name(artifact: str, version: str) -> str:
    return f'{artifact}-{version}.jar'


def jar_url(event: dict) -> str:
    """Where the hosts fetch the build from: Nexus, never packages.redhat.com, so the registry token
    stays in one place and every host gets the copy Nexus already holds."""
    base = env('NEXUS_URL', 'https://nexus.example').rstrip('/')
    repo = env('NEXUS_REPOSITORY', 'lightwell-remediated')
    return (f"{base}/repository/{repo}/{event['group'].replace('.', '/')}/{event['artifact']}/"
            f"{event['version']}/{jar_name(event['artifact'], event['version'])}")


def render_playbook(event: dict, app: dict) -> str:
    """The template. Also what the LLM is shown as the shape to follow, and the fallback when its
    draft does not pass check_playbook()."""
    old = jar_name(event['artifact'], app['installed'])
    new = jar_name(event['artifact'], event['version'])
    return f"""---
# Generated by the Applications v2 agent for {app['app']}: {event['artifact']} {app['installed']} -> {event['version']}
# Fixes: {', '.join(event.get('cves') or []) or 'see Lightwell advisories'}
- name: Swap {event['artifact']} in {app['app']} for the Lightwell build
  hosts: "{{{{ target_hosts }}}}"
  become: true
  gather_facts: false
  vars:
    lib_dir: {app['path']}/lib
    backup_dir: {app['path']}/backup
    old_jar: {old}
    new_jar: {new}
    jar_url: "{{{{ nexus_jar_url }}}}"
    jar_sha256: "{{{{ verified_sha256 }}}}"
    service: {app['service']}
    health_url: {app['health_url']}
  tasks:
    - name: Swap the jar, restart and verify
      block:
        - name: Check the vulnerable jar is present
          ansible.builtin.stat:
            path: "{{{{ lib_dir }}}}/{{{{ old_jar }}}}"
          register: old_stat

        - name: Download the Lightwell build from Nexus, pinned to the verified checksum
          ansible.builtin.get_url:
            url: "{{{{ jar_url }}}}"
            dest: "{{{{ lib_dir }}}}/{{{{ new_jar }}}}"
            checksum: "sha256:{{{{ jar_sha256 }}}}"
            mode: "0644"

        - name: Back up the old jar
          ansible.builtin.copy:
            src: "{{{{ lib_dir }}}}/{{{{ old_jar }}}}"
            dest: "{{{{ backup_dir }}}}/{{{{ old_jar }}}}"
            remote_src: true
            mode: "0644"
          when: old_stat.stat.exists

        - name: Remove the old jar
          ansible.builtin.file:
            path: "{{{{ lib_dir }}}}/{{{{ old_jar }}}}"
            state: absent

        - name: Restart the service
          ansible.builtin.systemd_service:
            name: "{{{{ service }}}}"
            state: restarted

        - name: Verify the service is healthy
          ansible.builtin.uri:
            url: "{{{{ health_url }}}}"
            status_code: 200
          register: health
          until: health.status == 200
          retries: 12
          delay: 5

        - name: Verify the new jar is the one on disk
          ansible.builtin.stat:
            path: "{{{{ lib_dir }}}}/{{{{ new_jar }}}}"
            checksum_algorithm: sha256
          register: new_stat

        - name: Verify the checksum matches
          ansible.builtin.assert:
            that:
              - new_stat.stat.exists
              - new_stat.stat.checksum == jar_sha256

        - name: Report patched
          ansible.builtin.set_stats:
            data:
              patched: true
              rolled_back: false
              version: "{{{{ new_jar }}}}"
      rescue:
        - name: Roll back to the old jar
          ansible.builtin.copy:
            src: "{{{{ backup_dir }}}}/{{{{ old_jar }}}}"
            dest: "{{{{ lib_dir }}}}/{{{{ old_jar }}}}"
            remote_src: true
            mode: "0644"
          when: old_stat.stat.exists | default(false)

        - name: Remove the new jar
          ansible.builtin.file:
            path: "{{{{ lib_dir }}}}/{{{{ new_jar }}}}"
            state: absent

        - name: Restart the service on the old jar
          ansible.builtin.systemd_service:
            name: "{{{{ service }}}}"
            state: restarted

        - name: Report rolled back
          ansible.builtin.set_stats:
            data:
              patched: false
              rolled_back: true
              version: "{{{{ old_jar }}}}"

        - name: Fail the run so the workflow records it
          ansible.builtin.fail:
            msg: "Health check failed after the swap; {{{{ old_jar }}}} restored."
"""


def pinned_vars(template: str) -> list[str]:
    """The template's vars lines: paths, jar names, service, health URL and the checksum variable. These are set by
    the system, not the LLM; a draft must carry every one of them verbatim."""
    block = template.split('\n  vars:\n', 1)[1].split('\n  tasks:', 1)[0]
    return [l.strip() for l in block.splitlines() if l.strip()]


def check_playbook(text: str, template: str | None = None) -> list[dict]:
    """The guardrail between an LLM draft and a host. Each check is {'id','label','ok','detail'}.

    Not a YAML parser (there is none in the standard library): it reads the task lines the template
    produces. A draft written in some other shape fails 'modules' and is replaced by the template,
    which is the safe outcome."""
    modules, unknown = set(), set()
    for line in text.splitlines():
        m = re.match(r'^\s*-?\s*([a-z0-9_]+(?:\.[a-z0-9_]+)+|[a-z_]+):\s*(\S.*)?$', line)
        if not m:
            continue
        key = m.group(1)
        if '.' in key:
            (modules if key in ALLOWED_MODULES else unknown).add(key)
        elif re.match(r'^\s{8,}(?:-\s*)?' + re.escape(key) + r':', line) and key in (
                'command', 'shell', 'raw', 'script', 'expect', 'win_shell', 'win_command'):
            unknown.add(key)
    low = text.lower()
    missing = [v for v in (pinned_vars(template) if template else []) if v not in [l.strip() for l in text.splitlines()]]
    checks = [
        {'id': 'play', 'label': 'A play for the target hosts',
         'ok': re.search(r'^\s*hosts:\s*"\{\{ target_hosts \}\}"\s*$', text, re.M) is not None
               and re.search(r'^\s*become:\s*true\s*$', text, re.M) is not None,
         'detail': 'needs hosts: "{{ target_hosts }}" and become: true'},
        {'id': 'pinned', 'label': 'Paths, jars and checksum as set by the system',
         'ok': not missing, 'detail': ('changed or missing: ' + '; '.join(missing)) if missing else ''},
        {'id': 'modules', 'label': 'Only allowed modules',
         'ok': bool(modules) and not unknown,
         'detail': ('not allowed: ' + ', '.join(sorted(unknown))) if unknown else
                   (', '.join(sorted(m.split('.')[-1] for m in modules)) if modules else 'no modules found')},
        {'id': 'checksum', 'label': 'Download pinned to a sha256',
         'ok': 'ansible.builtin.get_url' in modules and 'checksum: "sha256:' in text, 'detail': ''},
        {'id': 'verify', 'label': 'Health check and checksum verified',
         'ok': 'ansible.builtin.uri' in modules and 'ansible.builtin.assert' in modules, 'detail': ''},
        {'id': 'rollback', 'label': 'Rolls back on failure',
         'ok': re.search(r'^\s+rescue:\s*$', text, re.M) is not None and 'backup' in low, 'detail': ''},
        {'id': 'report', 'label': 'Reports patched / rolled_back',
         'ok': 'ansible.builtin.set_stats' in modules and 'patched:' in text and 'rolled_back:' in text, 'detail': ''},
    ]
    return checks


def draft_playbook(event: dict, app: dict) -> tuple[str, str, list[dict], str]:
    """(playbook, source, checks, note). The LLM drafts in live mode; the template stands in when
    there is no LLM, in demo mode, or when the draft fails a check — and the note says which."""
    template = render_playbook(event, app)
    if H.demo_mode() or not H.llm:
        return template, 'template', check_playbook(template, template), ''
    prompt = ('Write an Ansible playbook, and nothing else, no prose and no code fences. It must do exactly '
              'what this example does for the same variables: download the new jar with a pinned sha256, back '
              'up and remove the old jar, restart the service, verify health and checksum, report with '
              'set_stats, and roll back in a rescue block. Use only these modules: '
              + ', '.join(sorted(ALLOWED_MODULES)) + '. Keep the same vars.\n\n' + template)
    try:
        draft = H.llm(prompt)
    except Exception as exc:
        return template, 'template', check_playbook(template, template), f'LLM unavailable ({exc}); used the template.'
    draft = re.sub(r'(?s)^```[a-z]*\n|```\s*$', '', draft.strip()).strip() + '\n'
    checks = check_playbook(draft, template)
    if all(c['ok'] for c in checks):
        return draft, 'llm', checks, ''
    failed = ', '.join(c['label'] for c in checks if not c['ok'])
    return template, 'template', check_playbook(template, template), f'The LLM draft failed: {failed}. Used the template.'


# ---------------------------------------------------------------------------- the run

_RUN: dict[str, Any] = {'status': 'idle'}
_LOCK = threading.Lock()
EVENTS: EventStore | None = None


def events() -> EventStore:
    global EVENTS
    if EVENTS is None:
        EVENTS = EventStore(None if H.demo_mode() else ROOT / 'runs' / 'appv2-events.json')
    return EVENTS


def reset() -> None:
    """Back to an empty run. Called on a mode switch too: a demo inbox must not leak into live."""
    global EVENTS
    with _LOCK:
        _RUN.clear()
        _RUN['status'] = 'idle'
    EVENTS = None


def state() -> dict:
    with _LOCK:
        return json.loads(json.dumps(_RUN))


def _trace(src: str, dst: str, msg: str) -> None:
    with _LOCK:
        _RUN.setdefault('events', []).append({'t': now_iso(), 'src': src, 'dst': dst, 'msg': msg})


def _stage(key: str, value: str) -> None:
    with _LOCK:
        _RUN.setdefault('stages', {})[key] = value


def _set(**kw) -> None:
    with _LOCK:
        _RUN.update(kw)


def busy() -> bool:
    with _LOCK:
        return _RUN.get('status') in ('assessing', 'generating', 'dispatching', 'running')


def enrich(event: dict) -> None:
    """Fill in the CVEs a build fixes, from the Lightwell API. Run off the webhook's thread: Nexus
    gives a webhook a few seconds and a slow API must not make it retry."""
    if event.get('cves') or not H.fixed_cves:
        return
    try:
        cves = H.fixed_cves(event['group'], event['artifact'], event['version'])
        events().update(event['id'], cves=cves, cves_source='lightwell')
    except Exception as exc:
        events().update(event['id'], cves_source=f'not itemised ({exc})')


def accept_webhook(body: bytes, signature: str) -> tuple[int, dict]:
    secret = env('NEXUS_WEBHOOK_SECRET')
    if secret:
        if not verify_signature(body, signature, secret):
            return 401, {'ok': False, 'error': 'bad or missing X-Nexus-Webhook-Signature'}
    elif not H.demo_mode():
        return 503, {'ok': False, 'error': 'NEXUS_WEBHOOK_SECRET is not set, so no webhook is trusted'}
    try:
        payload = json.loads(body or b'{}')
    except ValueError:
        return 400, {'ok': False, 'error': 'body is not JSON'}
    ev = parse_nexus(payload)
    if ev is None:
        return 202, {'ok': True, 'ignored': True, 'why': 'not a newly created Lightwell build'}
    stored = events().add(ev)
    threading.Thread(target=enrich, args=(stored,), daemon=True, name='appv2-enrich').start()
    return 200, {'ok': True, 'event': stored}


def start_assess(event_id: str) -> tuple[int, dict]:
    if busy():
        return 409, {'ok': False, 'error': 'a v2 run is already in progress'}
    ev = events().get(event_id)
    if not ev:
        return 404, {'ok': False, 'error': f'no event {event_id}'}
    with _LOCK:
        _RUN.clear()
        _RUN.update(status='assessing', run_id=uuid.uuid4().hex[:8], event=ev, events=[],
                    stages={k: 'pending' for k in STAGES}, started_at=now_iso())
    threading.Thread(target=_assess, args=(ev,), daemon=True, name='appv2-assess').start()
    return 200, {'ok': True}


def _assess(ev: dict) -> None:
    try:
        _stage('intake', 'active')
        _trace('nexus', 'intake', f"{ev['group']}:{ev['artifact']} {ev['version']} created in {ev.get('repository') or 'Nexus'}")
        H.demo_pause(1.0)
        _trace('intake', 'lightwell', f"fixes {', '.join(ev.get('cves') or []) or 'not itemised yet'}")
        _stage('intake', 'done')
        _stage('impact', 'active')
        _trace('intake', 'inventory', f"who runs {ev['artifact']} {upstream(ev['version'])}?")
        H.demo_pause(1.2)
        imp = impact(ev, load_bom())
        _trace('inventory', 'intake', f"{len(imp['targets'])} server(s) in {len(imp['apps'])} app(s)")
        info, source = helpful_info(ev, imp)
        _set(impact=imp, info=info, info_source=source)
        _stage('impact', 'done')
        if not imp['targets']:
            for k in STAGES[2:]:
                _stage(k, 'skipped')
            _set(status='nothing', finished_at=now_iso())
            _trace('inventory', 'console', 'nothing to patch')
            return
        _set(status='assessed')
    except Exception as exc:
        _stage('impact', 'failed')
        _set(status='failed', error=str(exc))


def start_generate() -> tuple[int, dict]:
    with _LOCK:
        if _RUN.get('status') != 'assessed':
            return 409, {'ok': False, 'error': 'assess an event first'}
        _RUN['status'] = 'generating'
    threading.Thread(target=_generate, daemon=True, name='appv2-generate').start()
    return 200, {'ok': True}


def _generate() -> None:
    try:
        st = state()
        ev, imp = st['event'], st['impact']
        _stage('generate', 'active')
        playbooks = []
        for app in imp['apps']:
            target = next(t for t in imp['targets'] if t['app'] == app)
            _trace('intake', 'playbook', f'draft for {app}')
            H.demo_pause(1.4)
            text, source, checks, note = draft_playbook(ev, target)
            ok = all(c['ok'] for c in checks)
            _trace('playbook', 'intake', f"{app}: {'checks passed' if ok else 'checks FAILED'} ({source})")
            playbooks.append({'app': app, 'filename': f"app-v2/{app}-{ev['artifact']}-{st['run_id']}.yml",
                              'text': text, 'source': source, 'checks': checks, 'ok': ok, 'note': note,
                              'sha256': hashlib.sha256(text.encode()).hexdigest()})
        _set(playbooks=playbooks)
        if not all(p['ok'] for p in playbooks):
            _stage('generate', 'failed')
            _set(status='failed', error='a playbook failed its checks')
            return
        _stage('generate', 'done')
        _set(status='generated')
    except Exception as exc:
        _stage('generate', 'failed')
        _set(status='failed', error=str(exc))


def start_dispatch() -> tuple[int, dict]:
    with _LOCK:
        if _RUN.get('status') != 'generated':
            return 409, {'ok': False, 'error': 'generate the playbook first'}
        _RUN['status'] = 'dispatching'
        st = json.loads(json.dumps(_RUN))
    hosts = []
    for t in st['impact']['targets']:
        pb = next(p for p in st['playbooks'] if p['app'] == t['app'])
        hosts.append({**t, 'playbook': pb['filename'], 'outcome': 'queued', 'steps': {}, 'execution_id': ''})
    _set(hosts=hosts)
    target = _simulate if H.demo_mode() else _dispatch_live
    threading.Thread(target=target, daemon=True, name='appv2-run').start()
    return 200, {'ok': True}


def _host(host: str, **kw) -> None:
    with _LOCK:
        for h in _RUN.get('hosts', []):
            if h['host'] == host:
                h.update({k: v for k, v in kw.items() if k != 'steps'})
                if 'steps' in kw:
                    h.setdefault('steps', {}).update(kw['steps'])


def _roll_stages() -> None:
    """The bar from the hosts: a stage is done when every host that goes through it is past it."""
    st = state()
    hosts = st.get('hosts') or []
    if not hosts:
        return
    for key in ('commit', 'approval', 'sync', 'remediate', 'verify'):
        vals = [h['steps'].get(key) for h in hosts if not (key == 'approval' and h['env'] == 'qa')]
        if not vals:
            _stage(key, 'skipped')
        elif any(v == 'failed' for v in vals) and all(v in ('done', 'failed', 'skipped') for v in vals):
            _stage(key, 'failed')
        elif all(v in ('done', 'skipped') for v in vals):
            _stage(key, 'done')
        # Pulsing only while a host is actually in it. QA can be through Sync while Prod waits at
        # the gate; lighting Sync then would say work is happening that is waiting on a person.
        elif any(v in ('active', 'waiting') for v in vals):
            _stage(key, 'active')
        else:
            _stage(key, 'pending')


def _simulate() -> None:
    """Demo: the AO workflow, staged. Nothing is committed, synced or patched."""
    st = state()
    _set(status='running', simulated=True)
    sha = hashlib.sha1(st['run_id'].encode()).hexdigest()
    jar_sha = hashlib.sha256(st['event']['version'].encode()).hexdigest()
    for h in st['hosts']:
        _host(h['host'], execution_id=f'sim-{uuid.uuid4().hex[:12]}', outcome='running')
    _trace('console', 'ao', f"{len(st['hosts'])} execution(s) of App Patch v2")
    # Commit runs once per playbook; every host's execution reports the same commit.
    for h in st['hosts']:
        _host(h['host'], steps={'commit': 'active'})
    _roll_stages()
    H.demo_pause(1.6)
    _trace('ao', 'gitea', f'committed {len(st["playbooks"])} playbook(s) at {sha[:8]}; provenance verified (cosign)')
    gitea = env('GITEA_URL', 'https://gitea.example') + '/' + env('GITEA_REPO', 'lab-user/app_v2_playbooks')
    for h in st['hosts']:
        _host(h['host'], commit_sha=sha, commit_url=f'{gitea}/src/commit/{sha}/{h["playbook"]}',
              provenance='verified', jar_sha256=jar_sha,
              steps={'commit': 'done', 'approval': 'skipped' if h['env'] == 'qa' else 'waiting'},
              outcome='running' if h['env'] == 'qa' else 'awaiting_approval')
    _roll_stages()
    for h in [x for x in st['hosts'] if x['env'] == 'qa']:
        _run_host_sim(h)
    _set(status='awaiting_approval' if any(x['env'] != 'qa' for x in st['hosts']) else 'running')
    _maybe_finish()


def _run_host_sim(h: dict, delay: float = 1.0) -> None:
    host = h['host']
    for step in ('sync', 'remediate', 'verify'):
        _host(host, steps={step: 'active'})
        _roll_stages()
        H.demo_pause(delay)
        if step == 'verify' and host == DEMO_FAILING_HOST:
            _host(host, steps={'verify': 'failed'}, outcome='rolled_back',
                  detail='Health check failed after the swap (HTTP 503 for 60s); the old jar was restored and the service restarted.')
            _trace('aap', 'ao', f'{host.split(".")[0]}: health check failed, rolled back')
            _roll_stages()
            return
        _host(host, steps={step: 'done'})
    _host(host, outcome='patched', detail=f"{h['service']} healthy on {jar_name(state()['event']['artifact'], state()['event']['version'])}")
    _trace('aap', 'ao', f'{host.split(".")[0]}: patched and healthy')
    _roll_stages()


def decide(host: str, decision: str) -> tuple[int, dict]:
    if decision not in ('approved', 'rejected'):
        return 400, {'ok': False, 'error': "decision must be 'approved' or 'rejected'"}
    st = state()
    h = next((x for x in st.get('hosts', []) if x['host'] == host), None)
    if not h or h.get('outcome') != 'awaiting_approval':
        return 409, {'ok': False, 'error': f'{host} is not waiting for approval'}
    _trace('console', 'ao', f"{decision} {host.split('.')[0]}")
    if decision == 'rejected':
        _host(host, outcome='rejected', steps={'approval': 'failed', 'sync': 'skipped', 'remediate': 'skipped', 'verify': 'skipped'})
        if not st.get('simulated'):
            _signal(h, 'rejected')
        _roll_stages()
        _maybe_finish()
        return 200, {'ok': True}
    _host(host, outcome='running', steps={'approval': 'done'})
    _set(status='running')
    if st.get('simulated'):
        threading.Thread(target=lambda: (_run_host_sim(h), _maybe_finish()), daemon=True).start()
    else:
        _signal(h, 'approved')
        threading.Thread(target=_follow_live, args=(h,), daemon=True).start()
    _roll_stages()
    return 200, {'ok': True}


def _maybe_finish() -> None:
    st = state()
    hosts = st.get('hosts') or []
    if not hosts or any(h['outcome'] in ('queued', 'running') for h in hosts):
        return
    if any(h['outcome'] == 'awaiting_approval' for h in hosts):
        _set(status='awaiting_approval')
        return
    _learn(st)


def _learn(st: dict) -> None:
    """Write the new version back to the BOM for every app whose servers are all patched, so the next
    event for this library sees it. An app with a rolled-back or rejected server keeps the old version:
    that server is still running it."""
    _stage('learn', 'active')
    ev = st['event']
    for app in st['impact']['apps']:
        mine = [h for h in st['hosts'] if h['app'] == app]
        if mine and all(h['outcome'] == 'patched' for h in mine):
            _BOM_UPDATES[f"{app}|{ev['group']}:{ev['artifact']}"] = ev['version']
            _trace('learn', 'inventory', f"{app}: BOM now {ev['artifact']} {ev['version']}")
        else:
            _trace('learn', 'inventory', f'{app}: BOM unchanged (not every server patched)')
    if not st.get('simulated'):
        try:
            p = ROOT / 'runs' / 'appv2-history.jsonl'
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open('a') as f:
                f.write(json.dumps({'run_id': st['run_id'], 'event': ev, 'finished_at': now_iso(),
                                    'hosts': [{k: h.get(k) for k in ('host', 'app', 'env', 'outcome', 'commit_sha')}
                                              for h in st['hosts']]}) + '\n')
        except OSError:
            pass
    H.demo_pause(0.6)
    _stage('learn', 'done')
    outcomes = [h['outcome'] for h in st['hosts']]
    _set(status='complete', finished_at=now_iso(),
         summary={k: outcomes.count(k) for k in ('patched', 'rolled_back', 'rejected', 'failed')})


# ---------------------------------------------------------------------------- live AO

_workflow_id: dict[str, str] = {}


def _wf_id() -> str:
    name = env('AO_APP_V2_WORKFLOW', 'App Patch v2')
    if name not in _workflow_id:
        found = H.ao_call('/api/v1/workflows') or {}
        for w in found.get('resources', []):
            if w.get('name') == name:
                _workflow_id[name] = w['id']
        if name not in _workflow_id:
            raise RuntimeError(f'AO workflow {name!r} not found; run ao-setup/create-ao-workflow.sh')
    return _workflow_id[name]


def _dispatch_live() -> None:
    st = state()
    _set(status='running', simulated=False)
    ev = st['event']
    try:
        wf = _wf_id()
    except Exception as exc:
        _set(status='failed', error=str(exc))
        _stage('commit', 'failed')
        return
    for h in st['hosts']:
        pb = next(p for p in st['playbooks'] if p['app'] == h['app'])
        inputs = {'host': h['host'].split('.')[0] if env('AO_HOST_SHORTNAME', 'true') == 'true' else h['host'],
                  'group': 'qa_auto' if h['env'] == 'qa' else 'prod_review',
                  'app': h['app'], 'run_id': st['run_id'],
                  'gitea_repo': env('GITEA_REPO', 'lab-user/app_v2_playbooks'),
                  'playbook_filename': pb['filename'],
                  'playbook_b64': base64.b64encode(pb['text'].encode()).decode(),
                  'playbook_sha256': pb['sha256'],
                  'jar_url': jar_url(ev),
                  'provenance_url': jar_url(ev).rsplit('.jar', 1)[0] + '.provenance.sigstore.json'}
        try:
            created = H.ao_call('/api/v1/executions', 'POST', {
                'workflow_id': wf, 'trigger_node_id': env('AO_APP_V2_TRIGGER_NODE', 'trigger_manual'),
                'input_data': inputs}) or {}
        except Exception as exc:
            _host(h['host'], outcome='failed', detail=f'not dispatched: {exc}', steps={'commit': 'failed'})
            continue
        _host(h['host'], execution_id=created.get('id', ''), outcome='running', steps={'commit': 'active'})
        _trace('console', 'ao', f"{h['host'].split('.')[0]} -> App Patch v2 ({inputs['group']})")
        threading.Thread(target=_follow_live, args=({**h, 'execution_id': created.get('id', '')},), daemon=True).start()
    _roll_stages()


def _activities(exec_id: str) -> dict[str, dict]:
    found = H.ao_call(f'/api/v1/executions/{exec_id}/activities') or {}
    return {(a.get('temporal_activity_id') or a.get('activity_name')): a for a in found.get('resources', [])}


def _out(a: dict | None) -> dict:
    out = (a or {}).get('output_data') or {}
    if isinstance(out, dict) and isinstance(out.get('artifacts'), dict):
        return out['artifacts']
    return out if isinstance(out, dict) else {}


STEP_OF = {NODE_COMMIT: 'commit', NODE_APPROVAL: 'approval', NODES_RUN[0]: 'sync', NODES_RUN[1]: 'sync'}
AO_STATE = {'completed': 'done', 'succeeded': 'done', 'failed': 'failed', 'running': 'active',
            'waiting': 'waiting', 'pending': 'waiting', 'skipped': 'skipped', 'cancelled': 'failed'}


def _follow_live(h: dict) -> None:
    """Poll one execution until it settles or stops at the approval gate."""
    exec_id = h.get('execution_id') or next((x['execution_id'] for x in state()['hosts'] if x['host'] == h['host']), '')
    deadline = time.time() + int(env('AO_POLL_TIMEOUT', '900'))
    while exec_id and time.time() < deadline:
        time.sleep(3)
        try:
            ex = H.ao_call(f'/api/v1/executions/{exec_id}') or {}
            acts = _activities(exec_id)
        except Exception:
            continue
        steps = {}
        for node, step in STEP_OF.items():
            a = acts.get(node)
            if a and a.get('status'):
                s = AO_STATE.get(str(a.get('status', '')).lower(), 'active')
                if s == 'waiting' and not a.get('started_at') and step != 'approval':
                    continue                      # a node the run has not reached, not a gate
                steps[step] = s
        if h['env'] == 'qa':
            steps['approval'] = 'skipped'
        run_node = next((acts[n] for n in NODES_RUN if n in acts and acts[n].get('started_at')), None)
        verify = _out(run_node)
        run_state = steps.get('sync')
        if run_state in ('done', 'failed'):
            steps['sync'] = 'done'                # the project synced and the playbook started
            steps['remediate'] = 'done' if verify else run_state
            steps['verify'] = ('done' if verify.get('patched') in (True, 'true', 'True')
                               else 'failed')
        elif run_state == 'active':
            steps['remediate'] = 'active'
        commit = _out(acts.get(NODE_COMMIT))
        extra = {}
        if commit.get('commit_sha'):
            extra.update(commit_sha=commit['commit_sha'], commit_url=commit.get('commit_url', ''),
                         provenance='verified' if commit.get('provenance_verified') else 'not verified',
                         jar_sha256=commit.get('jar_sha256', ''))
        status = str(ex.get('status', '')).lower()
        if steps.get('approval') == 'waiting' and h['env'] != 'qa':
            _host(h['host'], steps=steps, outcome='awaiting_approval', **extra)
            _roll_stages()
            _maybe_finish()
            return
        if status in ('completed', 'succeeded', 'failed', 'cancelled'):
            if verify.get('patched') in (True, 'true', 'True'):
                outcome, detail = 'patched', f"healthy on {verify.get('version', '')}"
            elif verify.get('rolled_back') in (True, 'true', 'True'):
                outcome, detail = 'rolled_back', 'health check failed after the swap; old jar restored'
            else:
                outcome, detail = 'failed', str(ex.get('error_details') or status)
            _host(h['host'], steps=steps, outcome=outcome, detail=detail, **extra)
            _roll_stages()
            _maybe_finish()
            return
        _host(h['host'], steps=steps, **extra)
        _roll_stages()
    _host(h['host'], outcome='failed', detail='timed out following the execution')
    _maybe_finish()


def _signal(h: dict, decision: str) -> None:
    H.ao_call(f"/api/v1/executions/{h['execution_id']}/activities/{NODE_APPROVAL}/signal",
              'POST', {'signal_data': {'decision': decision}})
