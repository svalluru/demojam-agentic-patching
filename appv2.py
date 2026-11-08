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
STAGES = ('intake', 'impact', 'generate', 'commit', 'approval', 'sync', 'remediate', 'verify', 'report', 'learn')

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
    rag_search: Callable[[str, str], list] | None = None        # (vector store id, query) -> hit texts
    rag_add: Callable[[str, Path], None] | None = None          # (vector store id, file) -> added to the store
    lightwell_get: Callable[..., dict] | None = None            # (path, **params) -> Lightwell API body


H = _Hooks()


def configure(**kw) -> None:
    for k, v in kw.items():
        setattr(H, k, v)


def env(key: str, default: str = '') -> str:
    return (H.env(key, default) or default).strip()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


# ---------------------------------------------------------------------------- demo data

# A telco estate. The fixed builds and their CVEs are real Lightwell facts (registry and /advisories, checked
# 2026-11-08); the apps, sites and reasoning are staged for the demo. Java-led, because that is where Lightwell's
# catalog is (1,009 remediated Java packages against 7 Python and no npm): the Python and JS apps are in the estate
# so the gaps show honestly.
DEMO_EVENTS = [
    {'id': 'evt-mina-core', 'source': 'nexus', 'repository': 'lightwell-remediated', 'format': 'maven2',
     'group': 'org.apache.mina', 'artifact': 'mina-core', 'version': '2.2.5.rhlw-00002',
     'received_at': '2026-11-08T18:37:12Z', 'cves': ['CVE-2026-41635'], 'cves_source': 'lightwell',
     'note': 'The SSH library behind NETCONF: what the orchestrator uses to configure network elements.'},
    {'id': 'evt-postgresql', 'source': 'nexus', 'repository': 'lightwell-remediated', 'format': 'maven2',
     'group': 'org.postgresql', 'artifact': 'postgresql', 'version': '42.3.3.rhlw-00006',
     'received_at': '2026-11-08T17:02:40Z',
     'cves': ['CVE-2022-31197', 'CVE-2022-41946', 'CVE-2024-1597', 'CVE-2026-42198'], 'cves_source': 'lightwell',
     'note': 'The JDBC driver under billing and inventory; the fix includes a SQL injection.'},
    {'id': 'evt-zookeeper', 'source': 'nexus', 'repository': 'lightwell-remediated', 'format': 'maven2',
     'group': 'org.apache.zookeeper', 'artifact': 'zookeeper', 'version': '3.5.9.rhlw-00001',
     'received_at': '2026-11-08T16:21:05Z', 'cves': ['CVE-2023-44981'], 'cves_source': 'lightwell',
     'note': 'Coordination for the orchestrator and inventory clusters.'},
]

# More real Lightwell builds the estate's libraries have (registry and /advisories, 2026-11-08). In the demo
# catalog and the estate view, not in the inbox: they have not "arrived" in Nexus in the staged story.
DEMO_CATALOG_EXTRA = [
    {'name': 'org.apache.httpcomponents.client5:httpclient5', 'build': '5.6.2.rhlw-00005', 'status': 'remediated',
     'cves': ['CVE-2026-64607', 'CVE-2026-71290']},
    {'name': 'org.springframework.security:spring-security-web', 'build': '5.7.11.rhlw-00006', 'status': 'remediated',
     'cves': ['CVE-2024-38821', 'CVE-2026-22732']},
    {'name': 'org.apache.avro:avro', 'build': '1.11.0.rhlw-00002', 'status': 'remediated',
     'cves': ['CVE-2023-39410', 'CVE-2024-47561']},
]

# Telco domains, grouped as on Lightwell's "One implementation, whole network" slide.
NETWORK_DOMAINS = {'NFVO / MANO', '5G Core (SBA)', 'O-RAN Near-RT RIC', 'IMS / Voice', 'Transport / SDN', 'Edge / MEC'}

DEMO_BOM = [
    {'app': 'nfvo-orchestrator', 'domain': 'NFVO / MANO', 'languages': {'java': 'H', 'python': '', 'js': ''},
     'path': '/opt/apps/nfvo-orchestrator', 'service': 'nfvo-orchestrator', 'health_url': 'http://localhost:8080/health',
     'servers': [{'host': 'lab', 'env': 'qa'}, {'host': 'edge-site-1', 'env': 'prod'},
                 {'host': 'core-dc-1', 'env': 'prod'}, {'host': 'core-dc-2', 'env': 'prod'}],
     'dependencies': [{'group': 'org.apache.mina', 'artifact': 'mina-core', 'version': '2.2.5'},
                      {'group': 'org.apache.zookeeper', 'artifact': 'zookeeper', 'version': '3.5.9'},
                      {'group': 'org.springframework.security', 'artifact': 'spring-security-web', 'version': '5.7.11'}]},
    {'app': 'oss-inventory', 'domain': 'OSS – Inventory', 'languages': {'java': 'H', 'python': 'M', 'js': ''},
     'path': '/opt/apps/oss-inventory', 'service': 'oss-inventory', 'health_url': 'http://localhost:8081/health',
     'servers': [{'host': 'lab', 'env': 'qa'}, {'host': 'core-dc-1', 'env': 'prod'}],
     'dependencies': [{'group': 'org.postgresql', 'artifact': 'postgresql', 'version': '42.3.3'},
                      {'group': 'org.apache.zookeeper', 'artifact': 'zookeeper', 'version': '3.5.9'},
                      {'group': 'org.apache.mina', 'artifact': 'mina-core', 'version': '2.1.6'}]},
    {'app': 'charging-engine', 'domain': 'BSS – Charging', 'languages': {'java': 'H', 'python': '', 'js': ''},
     'path': '/opt/apps/charging-engine', 'service': 'charging-engine', 'health_url': 'http://localhost:8082/health',
     'servers': [{'host': 'core-dc-1', 'env': 'prod'}, {'host': 'core-dc-2', 'env': 'prod'}],
     'dependencies': [{'group': 'org.postgresql', 'artifact': 'postgresql', 'version': '42.3.3'},
                      {'group': 'org.apache.avro', 'artifact': 'avro', 'version': '1.11.0'},
                      {'group': 'org.apache.logging.log4j', 'artifact': 'log4j-core', 'version': '2.24.3'}]},
    {'app': 'sba-gateway', 'domain': '5G Core (SBA)', 'languages': {'java': 'M', 'python': 'M', 'js': ''},
     'path': '/opt/apps/sba-gateway', 'service': 'sba-gateway', 'health_url': 'http://localhost:8083/health',
     'servers': [{'host': 'edge-site-1', 'env': 'prod'}],
     'dependencies': [{'group': 'org.apache.httpcomponents.client5', 'artifact': 'httpclient5', 'version': '5.6.2'},
                      {'group': 'org.springframework.security', 'artifact': 'spring-security-web', 'version': '5.7.11'}]},
    {'app': 'ric-xapp', 'domain': 'O-RAN Near-RT RIC', 'languages': {'java': '', 'python': 'H', 'js': ''},
     'servers': [], 'dependencies': [{'ecosystem': 'pypi', 'group': '', 'artifact': 'ricxappframe', 'version': '3.2.2'}]},
    {'app': 'selfcare-api', 'domain': 'Self-care API gateway', 'languages': {'java': '', 'python': '', 'js': 'H'},
     'servers': [], 'dependencies': [{'ecosystem': 'npm', 'group': '', 'artifact': 'express', 'version': '4.18.2'}]},
]

# The staged failure: this pair's health check fails after the swap and the playbook rolls it back.
DEMO_FAILING_KEY = 'nfvo-orchestrator|core-dc-2'

# What the reasoning step says per app and site in demo mode. Live mode retrieves the same kind of thing from the
# app history store (APP_VECTOR_DB_ID, app-data/history/) and has the LLM write one line per row.
DEMO_REASONING = {
    'nfvo-orchestrator|lab': 'No live network elements; restarts in 15s. Goes first.',
    'nfvo-orchestrator|edge-site-1': '120 NEs over NETCONF; drain sessions before restart.',
    'nfvo-orchestrator|core-dc-1': '340 NEs; only in the 00:00–04:00 network change window. Last change rolled back on '
                                   'a 30s health window.',
    'nfvo-orchestrator|core-dc-2': 'Standby of core-dc-1. Patch the night after, once core-dc-1 is stable.',
    'oss-inventory|lab': 'Lab copy with synthetic topology; safe at any time.',
    'oss-inventory|core-dc-1': 'Feeds topology to the orchestrator; patch after the NFVO change has settled.',
    'charging-engine|core-dc-1': 'CDR backlog grows if down more than 30s; avoid the month-end billing run.',
    'charging-engine|core-dc-2': 'Standby for billing; patch it before core-dc-1.',
    'sba-gateway|edge-site-1': 'Single instance with no standby; a restart drops in-flight SBA sessions.',
}

# The estate view's priority and note per app, in demo mode. Live: the app history store plus the Lightwell
# advisories, one LLM call for all apps.
DEMO_ESTATE = {
    'nfvo-orchestrator': ('CRITICAL', 'mina-core carries NETCONF to 340 network elements: a compromise here reaches '
                          'every element it configures. Drain NETCONF sessions before the restart, and take the '
                          'zookeeper fix in the same change so the orchestrator restarts once.'),
    'sba-gateway': ('HIGH', 'Fronts the SBA control plane; the spring-security fix closes an authorization bypass. '
                    'Single instance on edge-site-1 with no standby: a restart drops in-flight sessions, so patch '
                    'inside the 00:00–04:00 window.'),
    'ric-xapp': ('MEDIUM', 'Python only; Lightwell has no build for its libraries. Track the upstream fixes and keep the '
                 'xApp constrained by RIC platform policy until a fixed build exists.'),
    'charging-engine': ('CRITICAL', 'The postgresql driver fix covers 4 CVEs including SQL injection on the billing '
                        'path. A restart stalls CDR intake beyond 30s: avoid the month-end billing run, and patch the '
                        'standby (core-dc-2) before core-dc-1.'),
    'oss-inventory': ('HIGH', 'Feeds network topology to the orchestrator. Patch after the NFVO change has settled, so '
                      'the window never runs with both down. Its mina-core 2.1.6 is a different version and not '
                      'touched by the mina-core fix.'),
    'selfcare-api': ('LOW', "JavaScript; Lightwell builds aren't available for npm here. Customer-facing, so rely on "
                     'upstream npm updates and the WAF; no action from this console.'),
}


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
            if dep.get('ecosystem', 'maven') == 'maven':
                wanted.setdefault((dep['group'], dep['artifact']), set()).add(dep.get('version', ''))
    found = []
    for (group, artifact), installed in sorted(wanted.items()):
        path = f"{base}/repository/{repo}/{group.replace('.', '/')}/{artifact}"
        try:
            versions = _versions(fetch(f'{path}/maven-metadata.xml').decode('utf-8', 'replace'))
        except Exception:
            continue                       # not in Lightwell, or Nexus is down; next pass tries again
        # The newest Lightwell build of each version in use, not every build: 2.11.0.rhlw-00001 and
        # 2.11.0.rhlw-00009 are the same fix at two points in time, and the later one is the fix to apply.
        newest: dict[str, str] = {}
        for v in versions:
            m = RHLW.match(v)
            if not m or m.group('upstream') not in installed:
                continue
            current = newest.get(m.group('upstream'))
            if current is None or int(m.group('build')) > int(RHLW.match(current).group('build')):
                newest[m.group('upstream')] = v
        for v in newest.values():
            key = f'{group}:{artifact}:{v}'
            if key in seen:
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
    state_file = state_dir() / 'nexus-poller.json'
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
    # Not under rag-setup/data: that folder is ingested, recursively, into the infra history store.
    return Path(env('BOM_DIR', str(ROOT / 'app-data' / 'bom')))


def load_bom() -> list[dict]:
    """Every app's BOM. Demo: the staged fleet. Live: one JSON file per app under BOM_DIR (app-data/bom)."""
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
            if dep.get('ecosystem', 'maven') != 'maven':
                continue                   # a Python or npm library is never the same package as a Maven build
            if (dep.get('group'), dep.get('artifact')) != (event['group'], event['artifact']):
                continue
            if dep.get('version') == want:
                for order, s in enumerate(app.get('servers', [])):
                    targets.append({'key': f"{app['app']}|{s['host']}", 'domain': app.get('domain', ''), 'order': order,
                                    'site': s.get('site', s['host']),
                                    'app': app['app'], 'owner': app.get('owner', ''), 'host': s['host'],
                                    'env': s.get('env', 'prod'), 'path': app.get('path', ''),
                                    'service': app.get('service', app['app']),
                                    'health_url': app.get('health_url', ''), 'installed': dep['version']})
            elif dep.get('version') == event['version']:
                other.append({'app': app['app'], 'installed': dep['version'], 'why': 'already on this build'})
            else:
                other.append({'app': app['app'], 'installed': dep.get('version', ''),
                              'why': f'different version; this build replaces {want} only'})
    # QA first, so a bad build shows up where it costs least.
    # The lab first, so a bad build shows up where it costs least; then each app's sites in the order its BOM lists.
    targets.sort(key=lambda t: (t['env'] != 'qa', t['app'], t['order']))
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
    facts = (f"{pkg} is in {len(imp['apps'])} app(s) ({', '.join(imp['apps'])}) at {len(t)} site(s): "
             f"{len(qa)} lab, {len(prod)} live. The build {event['version']} fixes "
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
    order = ('The lab goes first, automatically' + (f" ({', '.join(x['host'].split('.')[0] for x in qa)})" if qa else '')
             + (f"; live sites wait for your approval ({len(prod)})." if prod else '.'))
    return f'{facts} {order} Each site keeps a backup of the old jar and rolls back if the health check fails.', \
        'rules' if not H.demo_mode() else 'staged'


def reasoning(targets: list[dict]) -> tuple[dict[str, str], str]:
    """({target key: one line}, source). What the history says about patching this app on this server.

    Live: one vector search per row in the app history store, keeping only records that name both the app and
    the server, then one LLM call that writes a line per row. A row with no records says so; nothing is
    invented for it."""
    if H.demo_mode():
        return ({t['key']: DEMO_REASONING.get(t['key'], 'No earlier changes recorded for this app on this server.')
                 for t in targets}, 'staged')
    store = env('APP_VECTOR_DB_ID')
    if not store or not H.rag_search:
        return {t['key']: 'No app history store configured (APP_VECTOR_DB_ID).' for t in targets}, 'none'
    excerpts: dict[str, str] = {}
    for t in targets:
        short = t['host'].split('.')[0]
        try:
            hits = H.rag_search(store, f"patch history of {t['app']} on {short}")
        except Exception:
            hits = []
        mine = [h for h in hits if t['app'] in h and re.search(rf'\b{re.escape(short)}\b', h)]
        if mine:
            excerpts[t['key']] = '\n---\n'.join(mine)[:2500]
    out = {t['key']: 'No history found for this app on this server.' for t in targets if t['key'] not in excerpts}
    if not excerpts:
        return out, 'rag'
    keys = list(excerpts)
    prompt = ('For each numbered app and server below, write ONE short sentence a reviewer needs before a library '
              'jar is swapped and the service restarted: timing, past failures, traffic windows. Use only the '
              'records given. Answer as JSON, {"1": "...", "2": "..."}, and nothing else.\n\n'
              + '\n\n'.join(f"{i + 1}. {k.replace('|', ' on ')}\n{excerpts[k]}" for i, k in enumerate(keys)))
    try:
        answer = H.llm(prompt) if H.llm else ''
        parsed = json.loads(re.search(r'\{.*\}', answer, re.S).group(0))
        for i, k in enumerate(keys):
            out[k] = str(parsed.get(str(i + 1)) or '').strip() or _lesson(excerpts[k])
        return out, 'rag+llm'
    except Exception:
        for k in keys:
            out[k] = _lesson(excerpts[k])     # the record's own words when the LLM cannot be used
        return out, 'rag'


def _lesson(excerpt: str) -> str:
    m = re.search(r'Lessons:\s*(.+?)(?:\n\n|$)', excerpt, re.S)
    return ' '.join((m.group(1) if m else excerpt).split())[:220]


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


def structure_ok(text: str) -> tuple[bool, str]:
    """The block/rescue shape, read from indentation (there is no YAML parser in the standard library).

    Every rescue: or always: needs a block: at the same indent in the same task, and each of the three must hold
    a task list indented under it. The live LLM has flattened a block and left its rescue: hanging: lines that
    read correctly one by one and do not parse as a whole."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r'^(\s*)(block|rescue|always):\s*$', line)
        if not m:
            continue
        ind, key = len(m.group(1)), m.group(2)
        nxt = next((x for x in lines[i + 1:] if x.strip()), '')
        if not re.match(r'^ {%d,}- ' % (ind + 1), nxt):
            return False, f'{key}: on line {i + 1} holds no task list'
        if key == 'block':
            continue
        for j in range(i - 1, -1, -1):
            prev = lines[j]
            if not prev.strip():
                continue
            k = len(prev) - len(prev.lstrip())
            if k == ind and re.match(r'^\s*block:\s*$', prev):
                break
            if k < ind:
                return False, f'{key}: on line {i + 1} has no block: in its task'
        else:
            return False, f'{key}: on line {i + 1} has no block: in its task'
    return True, ''


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
    shape_ok, shape_why = structure_ok(text)
    checks = [
        {'id': 'structure', 'label': 'Block and rescue nested correctly', 'ok': shape_ok, 'detail': shape_why},
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


def _split_play(template: str) -> tuple[str, str]:
    """(header through vars, the tasks list at its own indent)."""
    head, tasks = template.split('\n  tasks:\n', 1)
    return head, tasks


def _tasks_only(draft: str) -> str:
    """The task list out of whatever the LLM returned: a bare list, or a whole play (whose header is dropped,
    because the header is the system's). Dedented so it can be placed under `tasks:`."""
    text = re.sub(r'(?s)^```[a-z]*\n|```\s*$', '', draft.strip()).strip('\n')
    m = re.search(r'^(\s*)tasks:\s*$', text, re.M)
    if m:
        text = text[m.end():].strip('\n')
    lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith('---')]
    indent = min((len(l) - len(l.lstrip()) for l in lines), default=0)
    return '\n'.join(l[indent:] if l.strip() else '' for l in text.splitlines())


def assemble(template: str, tasks: str) -> str:
    """The system's header (hosts, become, the pinned vars) with the LLM's tasks under it."""
    head, _ = _split_play(template)
    return head + '\n  tasks:\n' + '\n'.join(('    ' + l) if l.strip() else '' for l in tasks.splitlines()) + '\n'


def draft_playbook(event: dict, app: dict) -> tuple[str, str, list[dict], str]:
    """(playbook, source, checks, note). In live mode the LLM writes the tasks and the system supplies everything
    it should not decide: the hosts, become, and the paths, jar names and checksum in vars. The checks then judge
    the tasks: allowed modules only, a pinned download, health and checksum verified, a rollback, the report. The
    template stands in when there is no LLM, in demo mode, or when the tasks fail a check, and the note says why."""
    template = render_playbook(event, app)
    if H.demo_mode() or not H.llm:
        return template, 'template', check_playbook(template, template), ''
    _, example = _split_play(template)
    prompt = ('Write the tasks for an Ansible play, and nothing else: no prose, no code fences, no play header '
              'and no vars, which are supplied. Return a YAML list of tasks starting with "- name:". They must do '
              'what these example tasks do, using the same variables: download the new jar with a pinned sha256, '
              'back up and remove the old jar, restart the service, verify health and checksum, report patched / '
              'rolled_back with set_stats, and roll back in a rescue block. Use only these modules: '
              + ', '.join(sorted(ALLOWED_MODULES)) + '. Keep the example\'s shape exactly: ONE task with a '
              '"block:" list and a "rescue:" list, both keys indented the same, under the same "- name:", and the '
              'tasks inside each indented two spaces further. Two-space indentation throughout.'
              '\n\nVariables available: '
              + ', '.join(re.findall(r'^    ([a-z_]+):', template, re.M)) + '\n\nExample tasks:\n' + example)
    try:
        draft = H.llm(prompt)
    except Exception as exc:
        return template, 'template', check_playbook(template, template), \
            f'The LLM was not reachable ({exc}), so the checked template was used.'
    playbook = assemble(template, _tasks_only(draft))
    checks = check_playbook(playbook, template)
    if all(c['ok'] for c in checks):
        return playbook, 'llm', checks, ''
    failed = ', '.join(c['label'].lower() for c in checks if not c['ok'])
    return template, 'template', check_playbook(template, template), \
        f'The LLM draft was not used (checks not met: {failed}), so the checked template was used instead.'


# ---------------------------------------------------------------------------- the run

_RUN: dict[str, Any] = {'status': 'idle'}
_LOCK = threading.Lock()
EVENTS: EventStore | None = None

# Live mode keeps the run and the BOM write-backs beside the inbox, on the console's volume (runs/ is the PVC on
# OpenShift). Without this a console restart forgot a run whose Prod servers were still waiting at the AO gate: the
# executions went on waiting, and nothing could approve them any more. Demo mode keeps everything in memory.
_PERSIST_LOCK = threading.Lock()


def state_dir() -> Path:
    return Path(env('APPV2_STATE_DIR', str(ROOT / 'runs')))


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, indent=1))
    tmp.replace(path)                      # atomic: a crash mid-write leaves the previous copy, never half of one


def _persist() -> None:
    if H.demo_mode():
        return
    with _LOCK:
        snapshot = json.loads(json.dumps(_RUN))
        bom = dict(_BOM_UPDATES)
    with _PERSIST_LOCK:
        try:
            _write_json(state_dir() / 'appv2-run.json', snapshot)
            _write_json(state_dir() / 'appv2-bom-updates.json', bom)
        except OSError:
            pass                           # a full or read-only volume must not stop a run that is patching


# What a console restart interrupts. These ran in a thread of the process that died, so they are not coming back.
_IN_PROCESS = {'assessing': 'assess', 'generating': 'generate', 'dispatching': 'dispatch'}


def restore() -> dict:
    """Load the saved run and BOM write-backs (live mode). Hosts at the gate stay approvable; executions that were
    running in AO are followed again; a step that was running inside the console is marked interrupted."""
    if H.demo_mode():
        return {'restored': False}
    try:
        saved = json.loads((state_dir() / 'appv2-run.json').read_text())
    except (OSError, ValueError):
        saved = None
    try:
        _BOM_UPDATES.update(json.loads((state_dir() / 'appv2-bom-updates.json').read_text()))
    except (OSError, ValueError):
        pass
    if not isinstance(saved, dict) or saved.get('status', 'idle') == 'idle':
        return {'restored': False}
    for h in saved.get('hosts') or []:          # saved before hosts were keyed by app|host
        h.setdefault('key', f"{h.get('app', '')}|{h.get('host', '')}")
    with _LOCK:
        _RUN.clear()
        _RUN.update(saved)
    status = saved.get('status')
    if status in _IN_PROCESS:
        step = _IN_PROCESS[status]
        _set(status='failed', error=f'The console restarted during {step}; start the run again.')
        _trace('console', 'console', f'restarted during {step}; run stopped')
    resumed = []
    for h in saved.get('hosts') or []:
        if h.get('outcome') in ('running', 'queued') and h.get('execution_id') and not saved.get('simulated'):
            threading.Thread(target=_follow_live, args=(h,), daemon=True, name=f'appv2-resume-{h["key"]}').start()
            resumed.append(h['key'])
    if resumed or status == 'awaiting_approval':
        _trace('console', 'ao', 'restarted; ' + (f"following {', '.join(resumed)} again" if resumed
                                                 else 'run restored, Prod waiting at the gate'))
    _persist()
    return {'restored': True, 'status': state().get('status'), 'resumed': resumed}


def events() -> EventStore:
    global EVENTS
    if EVENTS is None:
        EVENTS = EventStore(None if H.demo_mode() else state_dir() / 'appv2-events.json')
    return EVENTS


def reset() -> None:
    """Back to an empty run. Called on a mode switch too: a demo inbox must not leak into live."""
    global EVENTS
    with _LOCK:
        _RUN.clear()
        _RUN['status'] = 'idle'
        _DEMO_RUNS.clear()          # demo history is memory only; it goes with the demo
    EVENTS = None
    _persist()


def state() -> dict:
    with _LOCK:
        return json.loads(json.dumps(_RUN))


def _trace(src: str, dst: str, msg: str) -> None:
    with _LOCK:
        _RUN.setdefault('events', []).append({'t': now_iso(), 'src': src, 'dst': dst, 'msg': msg})
    _persist()


def _stage(key: str, value: str) -> None:
    with _LOCK:
        _RUN.setdefault('stages', {})[key] = value
    _persist()


def _set(**kw) -> None:
    with _LOCK:
        _RUN.update(kw)
    _persist()


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
    _persist()
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
        if imp['targets']:
            _trace('inventory', 'reasoning', f"past changes for {len(imp['targets'])} app/server pair(s)")
            H.demo_pause(1.0)
            notes, rsource = reasoning(imp['targets'])
            if rsource == 'rag+llm':
                _trace('reasoning', 'llm', 'one line per app and server')
            for t in imp['targets']:
                t['reasoning'] = notes.get(t['key'], '')
            imp['reasoning_source'] = rsource
        if H.llm and not H.demo_mode() and imp['targets']:
            _trace('inventory', 'llm', 'note for the reviewer')
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
    _persist()
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
            if H.llm and not H.demo_mode():
                _trace('playbook', 'llm', f'draft for {app}')
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


SKIPPED_STEPS = {k: 'skipped' for k in ('commit', 'approval', 'sync', 'remediate', 'verify')}


def start_dispatch(targets: list[str] | None = None) -> tuple[int, dict]:
    """Run on the selected app/server pairs (all of them when targets is None). The rest are recorded as
    skipped, so the run and its history say what was left out and why."""
    with _LOCK:
        if _RUN.get('status') != 'generated':
            return 409, {'ok': False, 'error': 'generate the playbook first'}
        known = {t['key'] for t in _RUN['impact']['targets']}
        chosen = known if targets is None else {k for k in targets if k in known}
        if not chosen:
            return 400, {'ok': False, 'error': 'select at least one app and server'}
        _RUN['status'] = 'dispatching'
        st = json.loads(json.dumps(_RUN))
    hosts = []
    for t in st['impact']['targets']:
        pb = next(p for p in st['playbooks'] if p['app'] == t['app'])
        if t['key'] in chosen:
            hosts.append({**t, 'playbook': pb['filename'], 'outcome': 'queued', 'steps': {}, 'execution_id': ''})
        else:
            hosts.append({**t, 'playbook': pb['filename'], 'outcome': 'skipped', 'steps': dict(SKIPPED_STEPS),
                          'execution_id': '', 'detail': 'Not selected for this run.'})
    _set(hosts=hosts)
    if len(chosen) < len(known):
        _trace('console', 'ao', f'{len(chosen)} of {len(known)} app/server pair(s) selected')
    target = _simulate if H.demo_mode() else _dispatch_live
    threading.Thread(target=target, daemon=True, name='appv2-run').start()
    return 200, {'ok': True}


def _host(key: str, **kw) -> None:
    """Update one app/server pair. Keyed by app|host: two apps can share a server."""
    with _LOCK:
        for h in _RUN.get('hosts', []):
            if h['key'] == key:
                h.update({k: v for k, v in kw.items() if k != 'steps'})
                if 'steps' in kw:
                    h.setdefault('steps', {}).update(kw['steps'])
    _persist()


def _roll_stages() -> None:
    """The bar from the hosts: a stage is done when every host that goes through it is past it."""
    st = state()
    hosts = [h for h in (st.get('hosts') or []) if h['outcome'] != 'skipped']
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


def _label(h: dict) -> str:
    return f"{h['app']}@{h['host'].split('.')[0]}"


def _simulate() -> None:
    """Demo: the AO workflow, staged. Nothing is committed, synced or patched."""
    st = state()
    _set(status='running', simulated=True)
    sha = hashlib.sha1(st['run_id'].encode()).hexdigest()
    jar_sha = hashlib.sha256(st['event']['version'].encode()).hexdigest()
    active = [h for h in st['hosts'] if h['outcome'] == 'queued']
    for h in active:
        _host(h['key'], execution_id=f'sim-{uuid.uuid4().hex[:12]}', outcome='running', steps={'commit': 'active'})
    _trace('console', 'ao', f"{len(active)} execution(s) of App Patch v2")
    _roll_stages()
    H.demo_pause(1.6)
    _trace('ao', 'gitea', f'committed {len({h["app"] for h in active})} playbook(s) at {sha[:8]}; provenance verified (cosign)')
    gitea = env('GITEA_URL', 'https://gitea.example') + '/' + env('GITEA_REPO', 'lab-user/app_v2_playbooks')
    for h in active:
        _host(h['key'], commit_sha=sha, commit_url=f'{gitea}/src/commit/{sha}/{h["playbook"]}',
              provenance='verified', jar_sha256=jar_sha,
              steps={'commit': 'done', 'approval': 'skipped' if h['env'] == 'qa' else 'waiting'},
              outcome='running' if h['env'] == 'qa' else 'awaiting_approval')
    _roll_stages()
    for h in [x for x in active if x['env'] == 'qa']:
        _run_host_sim(h)
    _set(status='awaiting_approval' if any(x['env'] != 'qa' for x in active) else 'running')
    _maybe_finish()


def _run_host_sim(h: dict, delay: float = 1.0) -> None:
    key = h['key']
    for step in ('sync', 'remediate', 'verify'):
        _host(key, steps={step: 'active'})
        if step == 'sync':
            _trace('ao', 'aap', f'{_label(h)}: sync and run')
        elif step == 'remediate':
            _trace('aap', 'servers', f'{_label(h)}: swap the jar, restart {h["service"]}')
        _roll_stages()
        H.demo_pause(delay)
        if step == 'verify' and h['key'] == DEMO_FAILING_KEY:
            _host(key, steps={'verify': 'failed'}, outcome='rolled_back',
                  detail='Health check failed after the swap (HTTP 503 for 60s); the old jar was restored and the service restarted.')
            _trace('aap', 'ao', f'{_label(h)}: health check failed, rolled back')
            _roll_stages()
            return
        _host(key, steps={step: 'done'})
    _host(key, outcome='patched', detail=f"{h['service']} healthy on {jar_name(state()['event']['artifact'], state()['event']['version'])}")
    _trace('aap', 'ao', f'{_label(h)}: patched and healthy')
    _roll_stages()


def decide(key: str, decision: str) -> tuple[int, dict]:
    """Approve or reject one app/server pair at the gate. A bare host name is accepted when only one app on that
    server is waiting."""
    if decision not in ('approved', 'rejected'):
        return 400, {'ok': False, 'error': "decision must be 'approved' or 'rejected'"}
    st = state()
    waiting = [x for x in st.get('hosts', []) if x.get('outcome') == 'awaiting_approval']
    h = next((x for x in waiting if x['key'] == key), None) or (
        [x for x in waiting if x['host'] == key][0] if len([x for x in waiting if x['host'] == key]) == 1 else None)
    if not h:
        return 409, {'ok': False, 'error': f'{key} is not waiting for approval'}
    key = h['key']
    _trace('console', 'ao', f"{decision} {_label(h)}")
    if decision == 'rejected':
        _host(key, outcome='rejected', steps={'approval': 'failed', 'sync': 'skipped', 'remediate': 'skipped', 'verify': 'skipped'})
        if not st.get('simulated'):
            _signal(h, 'rejected')
        _roll_stages()
        _maybe_finish()
        return 200, {'ok': True}
    _host(key, outcome='running', steps={'approval': 'done'})
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
    """Agents 4 and 5, once every selected site has settled. The Report agent writes the PDF status report; the
    Results agent feeds the outcome back: the BOM moves to the new version for apps whose selected sites were all
    patched, and each site's outcome goes into the app history the Reasoning column reads next time."""
    ev = st['event']
    _stage('report', 'active')
    _trace('aap', 'report', 'status report for the change board')
    H.demo_pause(0.6)
    try:
        report = write_report(st)
        _trace('report', 'console', f"report written: {report['file']}")
        _stage('report', 'done')
    except Exception as exc:                 # never lose a run's outcome over a PDF
        report = {'error': str(exc)}
        _trace('report', 'console', f'report failed: {exc}')
        _stage('report', 'failed')
    _set(report=report)

    _stage('learn', 'active')
    _trace('report', 'results', 'feed the outcome back')
    bom = []
    for app in st['impact']['apps']:
        mine = [h for h in st['hosts'] if h['app'] == app and h['outcome'] != 'skipped']
        if mine and all(h['outcome'] == 'patched' for h in mine):
            with _LOCK:
                _BOM_UPDATES[f"{app}|{ev['group']}:{ev['artifact']}"] = ev['version']
            bom.append({'app': app, 'version': ev['version'], 'changed': True})
            _trace('results', 'inventory', f"{app}: BOM now {ev['artifact']} {ev['version']}")
        else:
            bom.append({'app': app, 'version': upstream(ev['version']), 'changed': False})
            _trace('results', 'inventory', f'{app}: BOM unchanged (not every selected site patched)')
    history = feed_history(st)
    _trace('results', 'inventory', f"{history['records']} outcome record(s) to the app history ({history['where']})")
    H.demo_pause(0.6)
    _stage('learn', 'done')
    outcomes = [h['outcome'] for h in st['hosts']]
    _set(status='complete', finished_at=now_iso(), feedback={'bom': bom, 'history': history},
         summary={k: outcomes.count(k) for k in ('patched', 'rolled_back', 'rejected', 'failed', 'skipped')})
    _record(state())


def reports_dir() -> Path:
    return Path(env('REPORTS_DIR', str(ROOT / 'reports')))


def write_report(st: dict) -> dict:
    """The status report, a PDF for the change board: the fix and its CVEs, each site's outcome, the commit and
    provenance, and what was fed back. Same writer as the infrastructure side's report (pdf.py)."""
    import pdf
    ev = st['event']
    now = datetime.now(timezone.utc)
    doc = pdf.Doc()
    doc.text('Application Patch Report', size=19, bold=True)
    doc.text(f"{ev['group']}:{ev['artifact']}  ·  {upstream(ev['version'])} → {ev['version']}  ·  "
             f"{now.strftime('%d %b %Y %H:%M UTC')}", size=9.5, color='#6a6e73')
    doc.rule()
    doc.gap(4)
    if st.get('simulated'):
        doc.banner('Simulated run — nothing was patched',
                   'Demo mode: the App Patch v2 workflow ran in the console\'s simulator. No site was changed.',
                   '#fdf0d5')
    hosts = [h for h in st.get('hosts') or []]
    m = _summary_of(hosts)
    doc.banner(f"{m['patched']} patched · {m['rolled_back']} rolled back · {m['rejected']} rejected · "
               f"{m['skipped']} not selected", ev.get('note', ''), '#eef3ee' if not m['rolled_back'] else '#fdecec')
    doc.text('Fixes', size=11, bold=True)
    doc.text(', '.join(ev.get('cves') or []) or 'Not itemised by Lightwell.', size=9)
    doc.gap(8)
    doc.text('Per-site outcome', size=11, bold=True)
    doc.gap(2)
    doc.table(['Site', 'App', 'Domain', 'Env', 'Outcome', 'Detail'],
              [[h.get('site') or h['host'], h['app'], h.get('domain', ''), 'LAB' if h.get('env') == 'qa' else 'LIVE',
                h.get('outcome', '').replace('_', ' '), h.get('detail', '')] for h in hosts] or [['—'] * 6],
              [70, 90, 80, 32, 60, 167])
    doc.gap(10)
    commit = next((h for h in hosts if h.get('commit_sha')), {})
    doc.text('Change record', size=11, bold=True)
    doc.gap(2)
    doc.table(['Field', 'Value'], [
        ['Run', st.get('run_id', '')],
        ['Playbook commit', (commit.get('commit_sha') or '—')[:12]],
        ['Build provenance', commit.get('provenance', '—')],
        ['Started', st.get('started_at', '')],
        ['Workflow', env('AO_APP_V2_WORKFLOW', 'App Patch v2')],
    ], [130, 369])
    doc.gap(14)
    doc.rule()
    doc.text('Generated by the Report agent (Applications v2, agent 4).', size=8, color='#6a6e73')
    out = reports_dir()
    out.mkdir(parents=True, exist_ok=True)
    name = f"{re.sub(r'[^A-Za-z0-9._-]', '_', ev['artifact'])}-{ev['version']}-{st.get('run_id', '')}.pdf"
    path = doc.save(out / name)
    return {'file': path.name, 'bytes': path.stat().st_size, 'created_at': now_iso()}


def feed_history(st: dict) -> dict:
    """One outcome record per site, written so the inventory agent's next search finds it: the app, the site, what
    happened and how long it took. Live: added to the app history store. Demo: counted, nothing written."""
    ev = st['event']
    records = []
    for h in st.get('hosts') or []:
        if h['outcome'] == 'skipped':
            continue
        site = h.get('site') or h['host']
        records.append((f"{now_iso()[:10]}-{h['app']}-{site}-{ev['artifact']}-{h['outcome'].upper()}.md",
                        f"# App patch record — {h['app']} on {site} ({h['host']}) — {now_iso()[:10]}\n\n"
                        f"App: {h['app']}   Site: {site}   Server: {h['host']}   "
                        f"Environment: {'LAB' if h.get('env') == 'qa' else 'LIVE'}\n"
                        f"Change: {ev['artifact']} {upstream(ev['version'])} -> {ev['version']} (run {st.get('run_id')})\n"
                        f"Result: {h['outcome'].replace('_', ' ').upper()}\n\nWhat happened:\n{h.get('detail') or '—'}\n"))
    if H.demo_mode():
        return {'records': len(records), 'where': 'demo, not stored'}
    folder = state_dir() / 'app-history'
    folder.mkdir(parents=True, exist_ok=True)
    added = 0
    for name, text in records:
        path = folder / name
        path.write_text(text)
        store = env('APP_VECTOR_DB_ID')
        if store and H.rag_add:
            try:
                H.rag_add(store, path)
                added += 1
            except Exception:
                pass
    return {'records': len(records), 'where': f'{added} added to the app history store' if added else 'saved locally'}


# ---------------------------------------------------------------------------- the telco estate

def estate() -> dict:
    """Every app by telco domain: what it is written in, which Lightwell fixes exist for the versions it runs, and
    the agent's priority and note: what is critical, how patching affects the current setup, what else to watch."""
    apps = load_bom()
    cat = catalog('mine', 1, 1000)
    fixes: dict[str, list[dict]] = {}
    for r in cat.get('rows') or []:
        for a in r.get('affects') or []:
            fixes.setdefault(a, []).append({'artifact': r['artifact'], 'build': r['build'], 'cves': r.get('cves') or []})
    rows = []
    for a in apps:
        maven = [d for d in a.get('dependencies', []) if d.get('ecosystem', 'maven') == 'maven']
        other = sorted({d.get('ecosystem') for d in a.get('dependencies', []) if d.get('ecosystem', 'maven') != 'maven'})
        rows.append({'app': a['app'], 'domain': a.get('domain', ''),
                     'group': 'network' if a.get('domain') in NETWORK_DOMAINS else 'it',
                     'languages': a.get('languages') or {},
                     'sites': [s.get('site', s['host']) for s in a.get('servers', [])],
                     'fixes': fixes.get(a['app'], []), 'covered': bool(maven), 'other': other})
    notes, source = estate_reasoning(rows)
    for r in rows:
        r['priority'], r['note'] = notes.get(r['app'], ('LOW', ''))
    return {'ok': True, 'rows': rows, 'source': source, 'catalog_source': cat.get('source')}


def _estate_rule(r: dict) -> tuple[str, str]:
    if not r['covered']:
        what = 'npm' if 'npm' in r['other'] else 'Python' if 'pypi' in r['other'] else 'this ecosystem'
        return 'LOW', f'No Lightwell build for {what} here; track upstream fixes.'
    if not r['fixes']:
        return 'LOW', 'No Lightwell fix for the versions this app runs.'
    cves = sum(len(f['cves']) for f in r['fixes'])
    return ('HIGH' if cves >= 2 else 'MEDIUM'), (f"{len(r['fixes'])} Lightwell fix(es), {cves} CVE(s), across "
                                                 f"{len(r['sites'])} site(s).")


def estate_reasoning(rows: list[dict]) -> tuple[dict, str]:
    if H.demo_mode():
        return {r['app']: DEMO_ESTATE.get(r['app'], _estate_rule(r)) for r in rows}, 'staged'
    store = env('APP_VECTOR_DB_ID')
    excerpts = {}
    if store and H.rag_search:
        for r in rows:
            try:
                hits = [h for h in H.rag_search(store, f"patch history of {r['app']}") if r['app'] in h]
            except Exception:
                hits = []
            if hits:
                excerpts[r['app']] = '\n---\n'.join(hits)[:1800]
    out = {r['app']: _estate_rule(r) for r in rows}
    if not H.llm:
        return out, 'rules'
    facts = '\n'.join(f"- {r['app']} ({r['domain']}; sites: {', '.join(r['sites']) or 'none'}): fixes "
                      + (', '.join(f"{f['artifact']} {f['build']} [{', '.join(f['cves'])}]" for f in r['fixes'])
                         or ('none' if r['covered'] else f"not covered ({', '.join(r['other'])})"))
                      + (f"\n  history: {excerpts[r['app']]}" if r['app'] in excerpts else '') for r in rows)
    prompt = ('You are advising a telco operations team. For each app below, give a priority (CRITICAL, HIGH, MEDIUM '
              'or LOW) for applying its Lightwell fixes, and one or two sentences: what is critical, how patching '
              'affects the current setup (restarts, sessions, windows, order), and anything else to watch. Use only the '
              'facts and history given. Answer as JSON, {"app": {"priority": "...", "note": "..."}}, nothing else.\n\n'
              + facts)
    try:
        parsed = json.loads(re.search(r'\{.*\}', H.llm(prompt), re.S).group(0))
        for r in rows:
            v = parsed.get(r['app']) or {}
            pr = str(v.get('priority', '')).upper()
            if pr in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') and v.get('note'):
                out[r['app']] = (pr, str(v['note']).strip())
        return out, 'rag+llm' if excerpts else 'llm'
    except Exception:
        return out, 'rules'


# ---------------------------------------------------------------------------- run history

_DEMO_RUNS: list[dict] = []


def _summary_of(hosts: list[dict]) -> dict:
    outcomes = [h.get('outcome') for h in hosts]
    return {k: outcomes.count(k) for k in ('patched', 'rolled_back', 'rejected', 'failed', 'skipped')}


def _record(st: dict) -> None:
    """One line of history per finished run: the summary for the Runs list and the whole run, so opening it
    later shows what the reviewer saw. Live: appv2-history.jsonl on the volume. Demo: memory."""
    rec = {'run_id': st.get('run_id'), 'event': st.get('event'), 'started_at': st.get('started_at'),
           'finished_at': st.get('finished_at'), 'simulated': bool(st.get('simulated')),
           'summary': st.get('summary') or _summary_of(st.get('hosts') or []),
           'hosts': [{k: h.get(k) for k in ('key', 'app', 'host', 'env', 'outcome', 'commit_sha', 'commit_url',
                                            'execution_id')} for h in st.get('hosts') or []],
           'snapshot': st}
    if H.demo_mode():
        _DEMO_RUNS.append(rec)
        return
    try:
        p = state_dir() / 'appv2-history.jsonl'
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open('a') as f:
            f.write(json.dumps(rec) + '\n')
    except OSError:
        pass


def _staged_runs() -> list[dict]:
    """Two past runs, so the demo's Runs screen has history before anything is run."""
    out = []
    for i, (ev, day, outcomes) in enumerate([
            (DEMO_EVENTS[2], '2026-11-03', {'oss-inventory|lab': 'patched', 'oss-inventory|core-dc-1': 'patched'}),
            (DEMO_EVENTS[1], '2026-10-28', {'charging-engine|core-dc-2': 'patched',
                                             'charging-engine|core-dc-1': 'rejected'})]):
        hosts = [{'key': k, 'app': k.split('|')[0], 'host': k.split('|')[1],
                  'env': 'qa' if k.endswith('|lab') else 'prod', 'outcome': o, 'commit_sha': f'{i + 7:x}' * 8,
                  'commit_url': '', 'execution_id': f'sim-past-{i}'} for k, o in outcomes.items()]
        snap = {'run_id': f'past{i + 1}', 'status': 'complete', 'simulated': True, 'event': ev,
                'started_at': f'{day}T21:04:00Z', 'finished_at': f'{day}T21:11:00Z',
                'stages': {k: 'done' for k in STAGES}, 'events': [],
                'impact': {'targets': [dict(h, installed=upstream(ev['version'])) for h in hosts],
                           'apps': sorted({h['app'] for h in hosts}), 'other': []},
                'hosts': [dict(h, steps={}, detail='') for h in hosts], 'summary': _summary_of(hosts)}
        out.append({k: snap[k] for k in ('run_id', 'event', 'started_at', 'finished_at', 'summary')}
                   | {'simulated': True, 'hosts': hosts, 'snapshot': snap})
    return out


def _history() -> list[dict]:
    if H.demo_mode():
        return _staged_runs() + _DEMO_RUNS
    try:
        return [json.loads(l) for l in (state_dir() / 'appv2-history.jsonl').read_text().splitlines() if l.strip()]
    except (OSError, ValueError):
        return []


def runs() -> list[dict]:
    """Newest first, without the snapshots; the run in progress (if any) on top."""
    out = [{k: v for k, v in r.items() if k != 'snapshot'} | {'current': False} for r in reversed(_history())]
    st = state()
    if st.get('status') not in (None, 'idle', 'complete') and st.get('event'):
        out.insert(0, {'run_id': st.get('run_id'), 'event': st['event'], 'started_at': st.get('started_at'),
                       'finished_at': None, 'simulated': bool(st.get('simulated')), 'status': st.get('status'),
                       'summary': _summary_of(st.get('hosts') or []), 'hosts': st.get('hosts') or [],
                       'current': True})
    return out


def run_detail(run_id: str) -> dict | None:
    st = state()
    if st.get('run_id') == run_id:
        return st
    return next((r.get('snapshot') for r in _history() if r.get('run_id') == run_id), None)


# ---------------------------------------------------------------------------- the Lightwell catalog

def _installed() -> dict[tuple[str, str], dict[str, list[str]]]:
    """(group, artifact) -> {version in use: [apps]}."""
    out: dict[tuple[str, str], dict[str, list[str]]] = {}
    for app in load_bom():
        for dep in app.get('dependencies', []):
            if dep.get('ecosystem', 'maven') == 'maven':
                out.setdefault((dep['group'], dep['artifact']), {}).setdefault(dep['version'], []).append(app['app'])
    return out


def catalog(scope: str = 'mine', page: int = 1, size: int = 25) -> dict:
    """Remediated builds Lightwell publishes, each marked with the deployed apps it would fix.

    scope 'mine': only builds of versions the apps run (asked per library, so it is exact and cheap).
    scope 'all': Lightwell's whole remediated catalog, a page at a time."""
    inst = _installed()

    def affects(group: str, artifact: str, version: str) -> list[str]:
        return sorted(inst.get((group, artifact), {}).get(upstream(version), []))

    rows: list[dict] = []
    total = None
    if H.demo_mode():
        try:
            saved = json.loads((ROOT / 'lightwell' / 'demo' / 'lightwell_catalog.json').read_text())
        except (OSError, ValueError):
            saved = {'entries': []}
        seen = set()
        for e in [{'name': f"{x['group']}:{x['artifact']}", 'build': x['version'], 'cves': x['cves'],
                   'status': 'remediated'} for x in DEMO_EVENTS] + DEMO_CATALOG_EXTRA + list(saved.get('entries') or []):
            if e.get('status') != 'remediated' or not e.get('build') or e['build'] in seen:
                continue
            seen.add(e['build'])
            group, _, artifact = e['name'].partition(':')
            rows.append({'group': group, 'artifact': artifact, 'build': e['build'], 'upstream': upstream(e['build']),
                         'cves': e.get('cves') or [], 'affects': affects(group, artifact, e['build'])})
        source = 'saved'
    elif not H.lightwell_get:
        return {'ok': False, 'error': 'Lightwell API not configured (LIGHTWELL_CLIENT_ID / _SECRET)'}
    elif scope == 'mine':
        for (group, artifact), versions in sorted(inst.items()):
            for version in versions:
                body = H.lightwell_get('/advisories', package_name=f'{group}:{artifact}',
                                       package_version=version, limit=100)
                builds: dict[str, set] = {}
                for adv in body.get('data') or []:
                    ids = {i for i in [adv.get('advisory_id', '')] + list(adv.get('aliases') or [])
                           if str(i).startswith('CVE-')}
                    for b in adv.get('fixed_versions') or []:
                        if is_lightwell(b) and upstream(b) == version:
                            builds.setdefault(b, set()).update(ids)
                for b, cves in sorted(builds.items()):
                    rows.append({'group': group, 'artifact': artifact, 'build': b, 'upstream': version,
                                 'cves': sorted(cves), 'affects': affects(group, artifact, b)})
        source = 'lightwell'
    else:
        body = H.lightwell_get('/package_versions', limit=size, offset=(page - 1) * size)
        total = int((body.get('meta') or {}).get('count') or 0)
        for r in body.get('data') or []:
            rows.append({'group': r.get('group', ''), 'artifact': r.get('name', ''), 'build': r.get('version', ''),
                         'upstream': upstream(r.get('version', '')), 'repository': r.get('repository', ''),
                         'cves': [], 'affects': affects(r.get('group', ''), r.get('name', ''), r.get('version', ''))
                         if 'remediated' in (r.get('repository') or '') else []})
        return {'ok': True, 'scope': scope, 'source': 'lightwell', 'rows': rows, 'page': page, 'size': size,
                'total': total, 'apps': app_names(), 'lens_url': LENS_URL}
    if scope == 'mine':
        rows = [r for r in rows if r['affects']]
    total = len(rows)
    start = (page - 1) * size
    return {'ok': True, 'scope': scope, 'source': source, 'rows': rows[start:start + size], 'page': page,
            'size': size, 'total': total, 'apps': app_names(), 'lens_url': LENS_URL}


# ---------------------------------------------------------------------------- SBOM export (for Lightwell Lens)

LENS_URL = 'https://console.redhat.com/lightwell/lens'


def app_names() -> list[str]:
    return sorted(a['app'] for a in load_bom())


def sbom(app_name: str) -> dict | None:
    """A CycloneDX 1.5 SBOM for one app, from its BOM: the file Lightwell Lens takes to show which of the app's
    packages Lightwell covers. Versions are the ones in use now, write-backs included."""
    app = next((a for a in load_bom() if a['app'] == app_name), None)
    if not app:
        return None
    ref = f"app:{app['app']}"
    return {
        'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
        'serialNumber': f'urn:uuid:{uuid.uuid4()}',
        'metadata': {
            'timestamp': now_iso(),
            'tools': {'components': [{'type': 'application', 'name': 'agentic-patching-console',
                                      'description': 'Applications v2 app BOM export'}]},
            'component': {'type': 'application', 'name': app['app'], 'bom-ref': ref,
                          'properties': [{'name': 'servers', 'value': ', '.join(
                              f"{s['host']} ({s.get('env', 'prod')})" for s in app.get('servers', []))}]},
        },
        'components': [{'type': 'library', 'group': d['group'], 'name': d['artifact'], 'version': d['version'],
                        'purl': f"pkg:maven/{d['group']}/{d['artifact']}@{d['version']}",
                        'bom-ref': f"pkg:maven/{d['group']}/{d['artifact']}@{d['version']}"}
                       for d in app.get('dependencies', [])],
        'dependencies': [{'ref': ref, 'dependsOn': [f"pkg:maven/{d['group']}/{d['artifact']}@{d['version']}"
                                                   for d in app.get('dependencies', [])]}],
    }


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
    for h in [x for x in st['hosts'] if x['outcome'] == 'queued']:
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
            _host(h['key'], outcome='failed', detail=f'not dispatched: {exc}', steps={'commit': 'failed'})
            continue
        _host(h['key'], execution_id=created.get('id', ''), outcome='running', steps={'commit': 'active'})
        _trace('console', 'ao', f"{_label(h)} -> App Patch v2 ({inputs['group']})")
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
    key = h['key']
    exec_id = h.get('execution_id') or next((x['execution_id'] for x in state()['hosts'] if x['key'] == key), '')
    deadline = time.time() + int(env('AO_POLL_TIMEOUT', '900'))
    said: set[str] = set()                 # each hop traced once, for the architecture diagram

    def hop(name: str, src: str, dst: str, msg: str) -> None:
        if name not in said:
            said.add(name)
            _trace(src, dst, msg)

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
                # AO lists every node from the start, the ones not reached as 'waiting' (a real gate has started),
                # and the branch not taken as 'skipped'. Neither says anything about this host's run.
                if (s == 'waiting' and not a.get('started_at')) or s == 'skipped':
                    continue
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
        if steps.get('commit') in ('active', 'done'):
            hop('commit', 'ao', 'gitea', f'{_label(h)}: verify the build, commit the playbook')
        if steps.get('sync') in ('active', 'done'):
            hop('sync', 'ao', 'aap', f'{_label(h)}: sync and run')
            hop('servers', 'aap', 'servers', f'{_label(h)}: swap the jar, restart {h.get("service", "")}')
        commit = _out(acts.get(NODE_COMMIT))
        extra = {}
        if commit.get('commit_sha'):
            extra.update(commit_sha=commit['commit_sha'], commit_url=commit.get('commit_url', ''),
                         provenance='verified' if commit.get('provenance_verified') else 'not verified',
                         jar_sha256=commit.get('jar_sha256', ''))
        status = str(ex.get('status', '')).lower()
        if steps.get('approval') == 'waiting' and h['env'] != 'qa':
            _host(key, steps=steps, outcome='awaiting_approval', **extra)
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
            _host(key, steps=steps, outcome=outcome, detail=detail, **extra)
            _trace('aap', 'ao', f'{_label(h)}: {outcome.replace("_", " ")}')
            _roll_stages()
            _maybe_finish()
            return
        _host(key, steps=steps, **extra)
        _roll_stages()
    _host(key, outcome='failed', detail='timed out following the execution')
    _maybe_finish()


def _signal(h: dict, decision: str) -> None:
    H.ao_call(f"/api/v1/executions/{h['execution_id']}/activities/{NODE_APPROVAL}/signal",
              'POST', {'signal_data': {'decision': decision}})
