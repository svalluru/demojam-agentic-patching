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
from concurrent.futures import ThreadPoolExecutor
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent

# The nine stages of a v2 run, in order. The console's stage bar is drawn from the same keys.
STAGES = ('intake', 'impact', 'generate', 'commit', 'test', 'approval', 'sync', 'remediate', 'verify', 'report', 'learn')

# Node ids in ao-setup/app_v2_workflow.json. The console reads each one's outcome by id. Sync and Run exists once per
# branch (AO nodes do not join), and its own set_stats (patched / rolled_back, from the generated playbook) is the
# verify result: the playbook checks health and checksum itself and rolls back on failure.
NODE_COMMIT, NODE_APPROVAL, NODE_TEST = 'commit_to_gitea', 'approval_prod', 'test_in_pod'
NODES_RUN = ('run_app_patch', 'run_app_patch_prod')
# The rollback route (a site whose run reported outcome: failed) and the Mattermost card that ends every route.
NODES_ROLLBACK = ('rollback', 'rollback_prod')
NODES_NOTIFY = ('notify_patched', 'notify_patched_prod', 'notify_rolled_back', 'notify_rolled_back_prod',
                'notify_test_failed')

RHLW = re.compile(r'^(?P<upstream>.+?)\.rhlw-(?P<build>\d+)(?:-n\d+)?$')

# Modules a generated playbook may use. No command, shell or raw: a playbook the LLM drafted can
# only fetch a file with a pinned checksum, move files, restart a unit and check a URL.
ALLOWED_MODULES = frozenset({
    'ansible.builtin.stat', 'ansible.builtin.get_url', 'ansible.builtin.copy', 'ansible.builtin.file',
    'ansible.builtin.systemd', 'ansible.builtin.systemd_service', 'ansible.builtin.uri',
    'ansible.builtin.set_stats', 'ansible.builtin.assert', 'ansible.builtin.fail', 'ansible.builtin.debug',
    'ansible.builtin.unarchive',          # Rebuild from source: unpack the built bundle, downloaded checksum-pinned
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
    osv_lookup: Callable[[list], dict] | None = None             # [(ecosystem, name, version)] -> {key: [advisory]}
    lightwell_builds: Callable[[str, str], list] | None = None   # (group, artifact) -> [{version, build}], every version
    k8s_get: Callable[..., Any] | None = None                   # (api path, text=False) -> JSON body, or text for logs
    k8s_patch: Callable[[str, dict], Any] | None = None         # (api path, merge patch) -> body; cancels a PipelineRun
    aap_call: Callable[..., Any] | None = None                  # (path, method='GET', body=None) -> AAP controller API
    lab_ping: Callable[[], None] | None = None                  # raises fast when the lab (llamastack) does not answer
    roi: Callable[[dict], dict | None] | None = None            # run state -> the Calculate ROI figures for it


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
     'note': 'The JDBC driver under the inventory service; the fix includes a SQL injection.'},
    {'id': 'evt-zookeeper', 'source': 'nexus', 'repository': 'lightwell-remediated', 'format': 'maven2',
     'group': 'org.apache.zookeeper', 'artifact': 'zookeeper', 'version': '3.5.9.rhlw-00001',
     'received_at': '2026-11-08T16:21:05Z', 'cves': ['CVE-2023-44981'], 'cves_source': 'lightwell',
     'note': 'Coordination for the orchestrator and inventory clusters.'},
]

# More real Lightwell builds the estate's libraries have (registry and /advisories, 2026-11-08). In the demo
# catalog and the estate view, not in the inbox: they have not "arrived" in Nexus in the staged story.
DEMO_CATALOG_EXTRA = [
    {'name': 'org.springframework.security:spring-security-web', 'build': '5.7.11.rhlw-00006', 'status': 'remediated',
     'cves': ['CVE-2024-38821', 'CVE-2026-22732']},
]

# Telco domains, grouped as on Lightwell's "One implementation, whole network" slide.
NETWORK_DOMAINS = {'NFVO / MANO', '5G Core (SBA)', 'O-RAN Near-RT RIC', 'IMS / Voice', 'Transport / SDN', 'Edge / MEC'}

def _demo_bom() -> list[dict]:
    """The demo estate is the live one: the same BOM files (app-data/bom), so apps, domains, sites and versions
    always match live mode. Each server is keyed by its site name (lab, edge-site-1, core-dc-1) rather than the lab
    node it runs on, so a demo key reads workflow-engine|core-dc-1."""
    apps = []
    for f in sorted((ROOT / 'app-data' / 'bom').glob('*.json')):
        try:
            rec = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        for app in (rec if isinstance(rec, list) else [rec]):
            app['servers'] = [{'host': x.get('site', x['host']), 'site': x.get('site', x['host']), 'env': x.get('env', 'prod')}
                              for x in app.get('servers', [])]
            apps.append(app)
    return apps


DEMO_BOM = _demo_bom()

# The staged failure: this pair's health check fails after the swap and the playbook rolls it back.
DEMO_FAILING_KEY = 'workflow-engine|edge-site-1'

# What the reasoning step says per app and site in demo mode. Live mode retrieves the same kind of thing from the
# app history store (APP_VECTOR_DB_ID, app-data/history/) and has the LLM write one line per row.
DEMO_REASONING = {
    'workflow-engine|lab': 'No live network elements; restarts in 15s. Goes first.',
    'workflow-engine|edge-site-1': '120 NEs over NETCONF; drain sessions before restart.',
    'workflow-engine|core-dc-1': '340 NEs; only in the 00:00–04:00 network change window. Last change rolled back on '
                                   'a 30s health window.',
    'inventory-service|lab': 'Lab copy with synthetic topology; safe at any time.',
    'inventory-service|core-dc-1': 'Feeds topology to the orchestrator; patch after the NFVO change has settled.',
}

# The estate view's priority and note per app, in demo mode. Live: the app history store plus the Lightwell
# advisories, one LLM call for all apps.
DEMO_ESTATE = {
    'workflow-engine': ('CRITICAL', 'mina-core carries NETCONF to 340 network elements: a compromise here reaches '
                          'every element it configures. Drain NETCONF sessions before the restart, and take the '
                          'zookeeper fix in the same change so the orchestrator restarts once.'),
    'analytics-agent': ('MEDIUM', 'Python only; Lightwell has no build for its libraries. Track the upstream fixes and keep the '
                 'xApp constrained by RIC platform policy until a fixed build exists.'),
    'inventory-service': ('HIGH', 'Feeds network topology to the orchestrator. Patch after the NFVO change has settled, so '
                      'the window never runs with both down. Its mina-core 2.1.6 is a different version and not '
                      'touched by the mina-core fix.'),
    'customer-portal': ('LOW', "JavaScript; Lightwell builds aren't available for npm here. Customer-facing, so rely on "
                     'upstream npm updates and the WAF; no action from this console.'),
}


# The Reasoning line for a version change offered in Impact, in demo mode, per app.
DEMO_VERSION_CHANGE = {
    'inventory-service': 'Version change 2.1.6 → 2.2.5: the 2.2 API broke its SFTP export last time (2026-03-03). Leave '
                         'it unticked unless the app team has re-tested; the osv.dev row offers upstream 2.1.13 instead.',
}

# What the reasoning says about each osv.dev package in demo mode (live: the app history store plus the LLM).
# Keyed app|group:artifact. The advisories and fix versions themselves are real (osv.dev, 2026-11-09).
DEMO_EXTRA_REASONING = {
    'inventory-service|org.apache.mina:mina-core':
        'Six critical deserialization CVEs and no Lightwell build at 2.1.6. Take upstream 2.1.13: it stays on the '
        '2.1 line inventory-service pins for its SFTP export (the 2.2 API broke it last time), and it rides the same '
        'restart as this fix.',
    'workflow-engine|org.apache.mina:mina-core':
        "Lightwell's 2.2.5.rhlw-00002 closes the NETCONF deserialization CVE: take it with zookeeper so the "
        'orchestrator restarts once. Four more critical CVEs stay open until upstream 2.2.8, a version change.',
    'workflow-engine|org.springframework.security:spring-security-web':
        'Lightwell has 5.7.11.rhlw-00006 for two critical CVEs: same version, Red Hat provenance. Two moderate '
        'ones stay open until a 6.x upgrade, which is the app team\'s change.',
    'workflow-engine|org.apache.zookeeper:zookeeper':
        'Lightwell has 3.5.9.rhlw-00001 for the SASL authorization bypass; same version, and the orchestrator is '
        'restarting anyway, so take it in this window instead of booking a second one.',
    'inventory-service|org.apache.zookeeper:zookeeper':
        'Lightwell has 3.5.9.rhlw-00001; the last zookeeper change here was clean (2026-11-03). Same restart, no API risk.',
    'inventory-service|org.postgresql:postgresql':
        'Lightwell has 42.3.3.rhlw-00006 for all four CVEs, including SQL injection; same version, so no API risk.',
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

    Exact match on group, artifact and version: a Lightwell build fixes one upstream version. An app on an older
    version of the same major line is offered the build too, as a version change (version_change: True), which
    the operator opts into: it moves the app to another version, not just a patched copy of its own. Anything
    else is listed apart, so a reviewer can see the library is there and why it was left alone."""
    want = upstream(event['version'])
    targets, other = [], []
    for app in apps:
        for dep in app.get('dependencies', []):
            if dep.get('ecosystem', 'maven') != 'maven':
                continue                   # a Python or npm library is never the same package as a Maven build
            if (dep.get('group'), dep.get('artifact')) != (event['group'], event['artifact']):
                continue
            change = (dep.get('version') != want and dep.get('version') != event['version']
                      and _major(dep.get('version', '')) == _major(want)
                      and _vkey(dep.get('version', '')) < _vkey(want))
            if dep.get('version') == want or change:
                for order, s in enumerate(app.get('servers', [])):
                    targets.append({'key': f"{app['app']}|{s['host']}", 'domain': app.get('domain', ''), 'order': order,
                                    'site': s.get('site', s['host']),
                                    'app': app['app'], 'owner': app.get('owner', ''), 'host': s['host'],
                                    'env': s.get('env', 'prod'), 'path': app.get('path', ''),
                                    'service': app.get('service', app['app']),
                                    'health_url': app.get('health_url', ''), 'installed': dep['version'],
                                    'repo': app.get('repo', ''),
                                    **({'version_change': True, 'to_version': want} if change else {})})
            elif dep.get('version') == event['version']:
                other.append({'app': app['app'], 'installed': dep['version'], 'why': 'already on this build'})
            elif _major(dep.get('version', '')) != _major(want):
                other.append({'app': app['app'], 'installed': dep.get('version', ''),
                              'why': f'major version {_major(dep.get("version", ""))}; this build is for {want}, a code change away'})
            else:
                other.append({'app': app['app'], 'installed': dep.get('version', ''),
                              'why': f'newer than {want}; this build would be a downgrade'})
    # QA first, so a bad build shows up where it costs least.
    # The lab first, so a bad build shows up where it costs least; then each app's sites in the order its BOM lists.
    # Exact matches before version changes, which are opt-in.
    targets.sort(key=lambda t: (bool(t.get('version_change')), t['env'] != 'qa', t['app'], t['order']))
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


def _search_all(store: str, queries: dict[str, str]) -> dict[str, list[str]]:
    """{key: hits} for many app history searches at once. Each search is a few seconds (embedding plus the vector
    store), and they do not depend on each other, so they run side by side. A failed search is no hits."""
    def one(q: str) -> list[str]:
        try:
            return H.rag_search(store, q) or []
        except Exception:
            return []
    if not queries:
        return {}
    with ThreadPoolExecutor(max_workers=min(8, len(queries))) as pool:
        futures = {k: pool.submit(one, q) for k, q in queries.items()}
        return {k: f.result() for k, f in futures.items()}


def reasoning(targets: list[dict]) -> tuple[dict[str, str], str]:
    """({target key: one line}, source). What the history says about patching this app on this server.

    Live: one vector search per row in the app history store, keeping only records that name both the app and
    the server, then one LLM call that writes a line per row. A row with no records says so; nothing is
    invented for it."""
    if H.demo_mode():
        return ({t['key']: (DEMO_VERSION_CHANGE.get(t['app'], 'A version change: verify the app against the new API first.')
                            if t.get('version_change') else
                            DEMO_REASONING.get(t['key'], 'No earlier changes recorded for this app on this server.'))
                 for t in targets}, 'staged')
    store = env('APP_VECTOR_DB_ID')
    if not store or not H.rag_search:
        return {t['key']: 'No app history store configured (APP_VECTOR_DB_ID).' for t in targets}, 'none'
    excerpts: dict[str, str] = {}
    found = _search_all(store, {t['key']: f"patch history of {t['app']} on {t['host'].split('.')[0]}" for t in targets})
    for t in targets:
        short = t['host'].split('.')[0]
        hits = found.get(t['key']) or []
        mine = [h for h in hits if t['app'] in h and re.search(rf'\b{re.escape(short)}\b', h)]
        if mine:
            excerpts[t['key']] = '\n---\n'.join(mine)[:2500]
    out = {t['key']: 'No history found for this app on this server.' for t in targets if t['key'] not in excerpts}
    if not excerpts:
        return out, 'rag'
    keys = list(excerpts)
    # A version change is a different risk from a patched copy of the same version: say so, so the line can weigh
    # the API change against the history.
    vc = {t['key']: f" (VERSION CHANGE {t['installed']} -> {t.get('to_version', '')}: the app moves to another version)"
          for t in targets if t.get('version_change')}
    prompt = ('For each numbered app and server below, write ONE short sentence (at most 25 words) a reviewer needs '
              'before a library jar is swapped and the service restarted: timing, past failures, traffic windows. Use only the '
              'records given. Answer as JSON, {"1": "...", "2": "..."}, and nothing else.\n\n'
              + '\n\n'.join(f"{i + 1}. {k.replace('|', ' on ')}{vc.get(k, '')}\n{excerpts[k]}" for i, k in enumerate(keys)))
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


# ---------------------------------------------------------------------------- osv.dev packages
#
# With "Include osv.dev packages" on, Assess also lists what else is open on the affected apps: osv.dev's advisories
# for every Maven library they run, minus what a Lightwell build already fixes. Each row proposes one change: a
# Lightwell build of the same version when there is one (Red Hat provenance), else the lowest upstream version that
# clears every advisory on the same major line (Maven Central, checked by sha1). A fix only across a major version is
# listed but not offered: that is a code change, not a jar swap.

def osv_enabled() -> bool:
    # Demo answers from saved osv.dev data (no network), so it is on unless set off; live is opt-in.
    return env('APPV2_OSV', 'true' if H.demo_mode() else 'false').lower() in ('1', 'true', 'yes', 'on')


def _vkey(v: str) -> tuple:
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in re.split(r'[.\-]', upstream(v)))


def _major(v: str) -> str:
    return re.split(r'[.\-]', upstream(v))[0]


_LW_BUILDS: dict[str, Any] = {}


def _lightwell_builds() -> dict[tuple[str, str, str], dict]:
    """(group, artifact, upstream version) -> the newest Lightwell build of it that names CVEs, with those CVEs.
    One Lightwell call per library version the apps run, so kept for 10 minutes (live; the BOM can change it)."""
    key = json.dumps(sorted((k[0], k[1], sorted(v)) for k, v in _installed().items()))
    hit = _LW_BUILDS.get('v')
    if not H.demo_mode() and hit and hit[0] == key and time.time() - hit[1] < 600:
        return hit[2]
    out = _lightwell_builds_uncached()
    _LW_BUILDS['v'] = (key, time.time(), out)
    return out


def _lightwell_builds_uncached() -> dict[tuple[str, str, str], dict]:
    out: dict[tuple[str, str, str], dict] = {}
    for r in (catalog('mine', 1, 1000).get('rows') or []):
        key = (r['group'], r['artifact'], r['upstream'])
        m = RHLW.match(r['build'])
        if not m or not r.get('cves'):
            continue
        cur = out.get(key)
        if cur is None or int(m.group('build')) > int(RHLW.match(cur['build']).group('build')):
            out[key] = {'build': r['build'], 'cves': list(r['cves'])}
    return out


def lightwell_builds(group: str, artifact: str) -> list[dict]:
    """Every Lightwell build of one package, best build per upstream version: [{version, build, cves?}].
    Live: the Lightwell API (/package_versions, through the scanner's client). Demo: the saved builds."""
    if H.demo_mode():
        try:
            saved = json.loads((ROOT / 'lightwell' / 'demo' / 'lightwell_catalog.json').read_text()).get('entries') or []
        except (OSError, ValueError):
            saved = []
        best: dict[str, dict] = {}
        for e in ([{'name': f"{x['group']}:{x['artifact']}", 'build': x['version'], 'cves': x['cves'], 'status': 'remediated'}
                   for x in DEMO_EVENTS] + DEMO_CATALOG_EXTRA + saved):
            if e.get('name') != f'{group}:{artifact}' or e.get('status') != 'remediated' or not RHLW.match(e.get('build') or ''):
                continue
            up, cur = upstream(e['build']), best.get(upstream(e['build']))
            if cur is None or int(RHLW.match(e['build']).group('build')) > int(RHLW.match(cur['build']).group('build')):
                best[up] = {'version': up, 'build': e['build'], 'cves': list(e.get('cves') or [])}
        return sorted(best.values(), key=lambda x: _vkey(x['version']))
    if not H.lightwell_builds:
        return []
    return H.lightwell_builds(group, artifact) or []


def _lightwell_newer(group: str, artifact: str, base: str) -> dict | None:
    """The nearest Lightwell build of a newer version on the same major line, with the CVEs it fixes."""
    try:
        cands = [b for b in lightwell_builds(group, artifact)
                 if _major(b['version']) == _major(base) and _vkey(b['version']) > _vkey(base)]
    except Exception:
        return None
    if not cands:
        return None
    pick = dict(min(cands, key=lambda b: _vkey(b['version'])))
    if not pick.get('cves') and H.lightwell_get and not H.demo_mode():
        # The newest build of a version is not always one an advisory names (a later rebuild); offer the newest build
        # that an advisory does name, with its CVEs, as the inbox does.
        try:
            body = H.lightwell_get('/advisories', package_name=f'{group}:{artifact}', package_version=pick['version'], limit=100)
            named: dict[str, set] = {}
            for adv in body.get('data') or []:
                ids = {i for i in [adv.get('advisory_id', '')] + list(adv.get('aliases') or []) if str(i).startswith('CVE-')}
                for b in adv.get('fixed_versions') or []:
                    if RHLW.match(b) and upstream(b) == pick['version']:
                        named.setdefault(b, set()).update(ids)
            if named:
                best = max(named, key=lambda b: int(RHLW.match(b).group('build')))
                pick.update(build=best, cves=sorted(named[best]))
        except Exception:
            pass
    return pick


def extras(event: dict, imp: dict, apps: list[dict]) -> dict:
    """{'rows', 'source', 'error'}: the open osv.dev advisories on the apps in this impact, one row per app and
    library, with the proposed change. Never raises: osv.dev being down leaves the run as it was."""
    if not H.osv_lookup:
        return {'rows': [], 'source': 'none', 'error': 'osv.dev lookup not configured'}
    by_app = {a['app']: a for a in apps}
    sites = {}
    for t in imp['targets']:
        sites.setdefault(t['app'], []).append(t.get('site') or t['host'])
    wanted: list[tuple[str, dict]] = []
    for name in imp['apps']:
        for dep in (by_app.get(name) or {}).get('dependencies', []):
            if dep.get('ecosystem', 'maven') == 'maven':
                wanted.append((name, dep))
    try:
        answers = H.osv_lookup([('maven', f"{d['group']}:{d['artifact']}", upstream(d['version'])) for _, d in wanted])
        lw = _lightwell_builds()
    except Exception as exc:
        return {'rows': [], 'source': 'osv.dev', 'error': str(exc)}
    rows = []
    for name, dep in wanted:
        coord = f"{dep['group']}:{dep['artifact']}"
        base = upstream(dep['version'])
        advisories = answers.get(('Maven', coord, base)) or []
        # The event's own library at the version it replaces: what is left open after it is information. On any
        # other version the build does not apply as is, so the library gets the usual options.
        mine = (dep['artifact'] == event['artifact'] and dep['group'] == event['group']
                and upstream(dep['version']) == upstream(event['version']))
        build = lw.get((dep['group'], dep['artifact'], base))
        # What Lightwell fixes for this library: the event's own build, the build already installed, or another
        # Lightwell build of the same version.
        fixed = set(event.get('cves') or []) if mine else set()
        if is_lightwell(dep['version']) or (build and not mine):
            fixed |= set((build or {}).get('cves') or [])

        def ids(a):
            return {a.get('id'), a.get('cve')} | set(a.get('aliases') or [])
        open_ = [a for a in advisories if not (ids(a) & fixed)]
        covered = [a for a in advisories if ids(a) & fixed]
        if not open_ and not (build and not mine and not is_lightwell(dep['version'])):
            continue
        fixes = [a.get('suggested_fix') for a in open_ if a.get('suggested_fix')]
        fix_all = max(fixes, key=_vkey) if fixes else ''
        row = {'id': f'{name}|{coord}', 'app': name, 'group': dep['group'], 'artifact': dep['artifact'],
               'installed': dep['version'], 'sites': sites.get(name, []),
               'advisories': [{'id': a.get('cve') or a.get('id'), 'severity': a.get('severity', 'unknown'),
                               'score': a.get('score'), 'fix': a.get('suggested_fix') or '', 'url': a.get('url', '')}
                              for a in sorted(open_, key=lambda a: -(a.get('score') or 0))],
               'lightwell_covers': [a.get('cve') or a.get('id') for a in covered],
               'kind': '', 'to': '', 'source': '', 'selectable': False, 'why': ''}
        if mine:
            row.update(kind='residual', to=fix_all, why=(
                f'Still open after the Lightwell build: {len(open_)} advisory(ies); upstream {fix_all} closes them.'
                if fix_all else f'Still open after the Lightwell build: {len(open_)} advisory(ies), no fix published.'))
        elif build and not is_lightwell(dep['version']):
            # The Lightwell build first (same version, Red Hat provenance); the upstream release as the alternative,
            # since it can close what the build leaves open (a major one only behind "Major upgrades").
            opts = [{'source': 'lightwell', 'to': build['build'], 'version_change': False, 'cves': list(build['cves'])}]
            # The upstream release that clears every advisory on this version, the build's own ones included.
            every = [a.get('suggested_fix') for a in advisories if a.get('suggested_fix')]
            up = max(every, key=_vkey) if every else ''
            if up and _vkey(up) > _vkey(base) and all(a.get('suggested_fix') for a in advisories):
                opts.append({'source': 'upstream', 'to': up, 'version_change': True, 'major': _major(up) != _major(base),
                             'cves': sorted({a.get('cve') or a.get('id') for a in advisories})})
            row.update(kind='lightwell', to=build['build'], source='lightwell', selectable=True, options=opts, default=0,
                       why=f"Lightwell build of the same version fixes {', '.join(build['cves'])}."
                           + (f" Upstream {opts[1]['to']} would also close the {len(open_)} it leaves open." if len(opts) > 1 and open_ else ''))
        else:
            # No Lightwell build of this version. Up to two ways forward on the same major line: the upstream fix,
            # and a Lightwell build of a newer version (Red Hat provenance, but a version change).
            opts = []
            if fix_all and _major(fix_all) == _major(base):
                opts.append({'source': 'upstream', 'to': fix_all, 'version_change': fix_all.split('.')[:2] != base.split('.')[:2],
                             'cves': [a.get('cve') or a.get('id') for a in open_]})
            alt = _lightwell_newer(dep['group'], dep['artifact'], base)
            if alt:
                opts.append({'source': 'lightwell', 'to': alt['build'], 'version_change': True, 'cves': alt['cves']})
            if opts:
                # The upstream fix by default when it is a patch release on the same minor line (no API change);
                # otherwise the Lightwell build.
                default = 0 if opts[0]['source'] == 'upstream' and not opts[0]['version_change'] else len(opts) - 1
                pick = opts[default]
                row.update(kind='upstream' if pick['source'] == 'upstream' else 'lightwell_vc', to=pick['to'],
                           source=pick['source'], selectable=True, options=opts, default=default,
                           why=('; '.join(
                               (f"upstream {o['to']} clears every advisory" + (' (a minor version change)' if o['version_change'] else ' on the same minor line'))
                               if o['source'] == 'upstream' else
                               f"Lightwell has {o['to']}, a version change from {base}, fixing {', '.join(o['cves']) or 'its listed CVEs'}"
                               for o in opts) + f'. No Lightwell build at {base}.'))
            elif fix_all:
                # Offered only when the operator allows major upgrades (the Change list's major chip).
                row.update(kind='major', to=fix_all, source='upstream', default=0,
                           options=[{'source': 'upstream', 'to': fix_all, 'version_change': True, 'major': True,
                                     'cves': [a.get('cve') or a.get('id') for a in open_]}],
                           why=f'Only fixed in {fix_all}, a major upgrade: a code change for the app team, not a jar swap.')
            else:
                row.update(kind='none', why='No fixed version published yet.')
        rows.append(row)
    order = {'lightwell': 0, 'upstream': 1, 'lightwell_vc': 1, 'major': 2, 'residual': 3, 'none': 4}
    rows.sort(key=lambda r: (order[r['kind']], -max([a['score'] or 0 for a in r['advisories']] or [0]), r['app']))
    notes, rsource = extras_reasoning(rows)
    for r in rows:
        r['reasoning'] = notes.get(r['id'], r['why'])
    return {'rows': rows, 'source': 'saved osv.dev answers' if H.demo_mode() else 'osv.dev',
            'reasoning_source': rsource, 'error': ''}


def _two_sentences(text: str) -> str:
    """At most two sentences: the model does not always keep to the length it is asked for, and the cell is small."""
    parts = re.split(r'(?<=[.!?])\s+', ' '.join(text.split()))
    keep = 3 if parts and re.fullmatch(r'(TAKE|SKIP)[.:]?', parts[0], re.I) else 2   # a bare "SKIP." is a label
    return ' '.join(parts[:keep]).strip()


def extras_reasoning(rows: list[dict]) -> tuple[dict[str, str], str]:
    """{row id: one or two sentences}: why take it now or not, from the app history store and the LLM."""
    if not rows:
        return {}, 'none'
    if H.demo_mode():
        return {r['id']: (r['why'] if r['kind'] == 'residual' else DEMO_EXTRA_REASONING.get(r['id'], r['why']))
                for r in rows}, 'staged'
    store = env('APP_VECTOR_DB_ID')
    excerpts = {}
    if store and H.rag_search:
        found = _search_all(store, {r['id']: f"{r['app']} {r['artifact']} patch history" for r in rows})
        for r in rows:
            hits = [h for h in found.get(r['id']) or [] if r['app'] in h]
            if hits:
                excerpts[r['id']] = '\n---\n'.join(hits)[:1200]
    if not H.llm:
        return {}, 'rules'
    def fact(r: dict) -> str:
        sev = ', '.join(f"{a['id']} ({a['severity']})" for a in r['advisories'][:6]) or 'none'
        if r['kind'] == 'lightwell':
            what = (f"proposed: Lightwell build {r['to']} (same version, Red Hat provenance). It fixes these CVEs that "
                    f"are open on the app today: {', '.join(r['lightwell_covers']) or 'none listed'}. Still open after it: {sev}.")
        elif r['kind'] in ('upstream', 'lightwell_vc'):
            def opt(o: dict) -> str:
                if o['source'] == 'upstream':
                    same_minor = upstream(r['installed']).split('.')[:2] == o['to'].split('.')[:2]
                    return (f"upstream {o['to']}, " + (f"a patch release on the same {'.'.join(o['to'].split('.')[:2])} line"
                            if same_minor else 'a minor version change') + ', fixing all of them')
                return (f"Lightwell build {o['to']} (Red Hat provenance), a version change from {upstream(r['installed'])}, "
                        f"fixing {', '.join(o['cves']) or 'its listed CVEs'}")
            options = r.get('options') or []
            what = (f"open today: {sev}. Options: " + '; or '.join(opt(o) for o in options)
                    + f". Proposed by default: {r['to']}. Say which option you would take.")
        else:
            what = f"open today: {sev}. {r['why']} Not offered in this change."
        return f"{r['app']} (sites {', '.join(r['sites'])}): {r['artifact']} {r['installed']}. {what}"
    facts = '\n'.join(f"{i + 1}. {fact(r)}" + (f"\n   history: {excerpts[r['id']]}" if r['id'] in excerpts else '')
                      for i, r in enumerate(rows))
    prompt = ('You advise a telco operations team patching application libraries in a change window. Each library '
              'below would ride the same restart as a Lightwell fix already being applied. For each numbered library '
              'write at most 35 words: start with TAKE or SKIP, then whether to take the proposed change in this window and why, how it '
              'affects the running app (API change or not, what to verify), and anything the history says. Use only '
              'the facts and history given. Answer as JSON, {"1": "...", "2": "..."}, nothing else.\n\n' + facts)
    try:
        parsed = json.loads(re.search(r'\{.*\}', H.llm(prompt), re.S).group(0))
        return {r['id']: _two_sentences(str(parsed.get(str(i + 1)) or '')) or r['why'] for i, r in enumerate(rows)}, \
            'rag+llm' if excerpts else 'llm'
    except Exception:
        return {}, 'rules'


# ---------------------------------------------------------------------------- playbook

def jar_name(artifact: str, version: str) -> str:
    return f'{artifact}-{version}.jar'


def jar_url(event: dict) -> str:
    """Where the hosts fetch the build from: Nexus, never packages.redhat.com, so the registry token
    stays in one place and every host gets the copy Nexus already holds."""
    return maven_url(event['group'], event['artifact'], event['version'], env('NEXUS_REPOSITORY', 'lightwell-remediated'))


def maven_url(group: str, artifact: str, version: str, repo: str) -> str:
    """A jar in one of the Nexus repositories: lightwell-remediated for Lightwell builds, maven-central (the proxy
    Nexus ships with) for upstream ones. Without Nexus, upstream jars come from Maven Central itself."""
    base = env('NEXUS_URL', '').rstrip('/')
    path = f"{group.replace('.', '/')}/{artifact}/{version}/{jar_name(artifact, version)}"
    if not base:
        return (f'https://repo1.maven.org/maven2/{path}' if repo != env('NEXUS_REPOSITORY', 'lightwell-remediated')
                else f'https://nexus.example/repository/{repo}/{path}')
    return f'{base}/repository/{repo}/{path}'


def change_for_event(event: dict, target: dict) -> dict:
    url = jar_url(event)
    return {'group': event['group'], 'artifact': event['artifact'], 'from': target['installed'],
            'to': event['version'], 'source': 'lightwell', 'cves': list(event.get('cves') or []),
            'version_change': upstream(event['version']) != upstream(target['installed']),
            'old_jar': jar_name(event['artifact'], target['installed']), 'new_jar': jar_name(event['artifact'], event['version']),
            'url': url, 'provenance_url': url.rsplit('.jar', 1)[0] + '.provenance.sigstore.json'}


def change_for_extra(row: dict, option: int | None = None) -> dict:
    """An osv.dev row the operator selected, with the option chosen (the row's default when None): a Lightwell build
    (provenance checked) or an upstream release (Maven Central's sha1 checked)."""
    opts = row.get('options') or [{'source': row['source'], 'to': row['to'], 'version_change': False,
                                   'cves': row['lightwell_covers'] if row['source'] == 'lightwell' else [a['id'] for a in row['advisories']]}]
    o = opts[option if option is not None and 0 <= option < len(opts) else row.get('default', 0)]
    lw = o['source'] == 'lightwell'
    url = maven_url(row['group'], row['artifact'], o['to'],
                    env('NEXUS_REPOSITORY', 'lightwell-remediated') if lw else env('NEXUS_CENTRAL_REPOSITORY', 'maven-central'))
    out = {'group': row['group'], 'artifact': row['artifact'], 'from': row['installed'], 'to': o['to'],
           'source': o['source'], 'version_change': bool(o.get('version_change')), 'cves': list(o.get('cves') or []),
           'old_jar': jar_name(row['artifact'], row['installed']), 'new_jar': jar_name(row['artifact'], o['to']),
           'url': url}
    out['provenance_url' if lw else 'sha1_url'] = (url.rsplit('.jar', 1)[0] + '.provenance.sigstore.json') if lw else url + '.sha1'
    return out


def render_playbook(event: dict, app: dict, changes: list[dict] | None = None, force_fail: bool = False) -> str:
    """The template. Also what the LLM is shown as the shape to follow, and the fallback when its
    draft does not pass check_playbook(). One play per app swaps every jar in its change list together: one
    backup, one restart, one health check. If anything fails, the rescue keeps the backup and reports what the
    rollback route needs (rollback_json); the App Patch v2 workflow then runs "App Patch v2 - Rollback"."""
    changes = changes or [change_for_event(event, app)]
    swaps = '\n'.join(f'      - {{old_jar: {c["old_jar"]}, new_jar: {c["new_jar"]}, url: "{c["url"]}"}}' for c in changes)
    what = '; '.join(f"{c['artifact']} {c['from']} -> {c['to']} ({'Lightwell' if c['source'] == 'lightwell' else 'upstream'})"
                     for c in changes)
    fixes = sorted({x for c in changes for x in c.get('cves') or []})
    return f"""---
# Generated by the Applications v2 agent for {app['app']}: {what}
# Fixes: {', '.join(fixes) or 'see the advisories'}
- name: Swap {', '.join(c['artifact'] for c in changes)} in {app['app']}
  hosts: "{{{{ target_hosts }}}}"
  become: true
  gather_facts: false
  vars:
    lib_dir: {app['path']}/lib
    backup_dir: {app['path']}/backup
    service: {app['service']}
    health_url: {app['health_url']}
    verify_url: {verify_url(app, force_fail)}
    swaps:
{swaps}
    jar_sha256s: "{{{{ verified_sha256s if verified_sha256s is mapping else (verified_sha256s | from_json) }}}}"
  tasks:
    - name: Swap the jars, restart once and verify
      block:
        - name: Check the jars being replaced are present
          ansible.builtin.stat:
            path: "{{{{ lib_dir }}}}/{{{{ item.old_jar }}}}"
          loop: "{{{{ swaps }}}}"
          register: old_stats

        - name: Download each new jar from Nexus, pinned to its verified checksum
          ansible.builtin.get_url:
            url: "{{{{ item.url }}}}"
            dest: "{{{{ lib_dir }}}}/{{{{ item.new_jar }}}}"
            checksum: "sha256:{{{{ jar_sha256s[item.new_jar] }}}}"
            mode: "0644"
          loop: "{{{{ swaps }}}}"

        - name: Back up the old jars
          ansible.builtin.copy:
            src: "{{{{ lib_dir }}}}/{{{{ item.item.old_jar }}}}"
            dest: "{{{{ backup_dir }}}}/{{{{ item.item.old_jar }}}}"
            remote_src: true
            mode: "0644"
          loop: "{{{{ old_stats.results }}}}"
          when: item.stat.exists

        - name: Remove the old jars
          ansible.builtin.file:
            path: "{{{{ lib_dir }}}}/{{{{ item.old_jar }}}}"
            state: absent
          loop: "{{{{ swaps }}}}"

        - name: Restart the service
          ansible.builtin.systemd_service:
            name: "{{{{ service }}}}"
            state: restarted

        - name: Verify the service is healthy
          ansible.builtin.uri:
            url: "{{{{ verify_url }}}}"
            status_code: 200
          register: health
          until: health.status == 200
          retries: 12
          delay: 5

        - name: Verify the new jars are the ones on disk
          ansible.builtin.stat:
            path: "{{{{ lib_dir }}}}/{{{{ item.new_jar }}}}"
            checksum_algorithm: sha256
          loop: "{{{{ swaps }}}}"
          register: new_stats

        - name: Verify the checksums match
          ansible.builtin.assert:
            that:
              - item.stat.exists
              - item.stat.checksum == jar_sha256s[item.item.new_jar]
          loop: "{{{{ new_stats.results }}}}"

        - name: Report patched
          ansible.builtin.set_stats:
            data:
              outcome: patched
              patched: true
              rolled_back: false
              version: "{{{{ swaps | map(attribute='new_jar') | join(', ') }}}}"
      # Nothing is restored here: the backup stays where it is and the App Patch v2 workflow takes its rollback
      # route (AAP job "App Patch v2 - Rollback") with what this reports.
      rescue:
        - name: Hand the failure to the rollback route
          ansible.builtin.set_stats:
            data:
              outcome: failed
              patched: false
              rolled_back: false
              failed_step: "{{{{ ansible_failed_task.name | default('unknown') }}}}"
              failed_reason: "{{{{ ansible_failed_result.msg | default('') | string | truncate(200) }}}}"
              rollback_json: "{{{{ {{'mode': 'swap', 'lib_dir': lib_dir, 'backup_dir': backup_dir, 'service': service,
                                  'health_url': health_url, 'restore': swaps}} | to_json }}}}"
"""


# Outside /health on purpose: HealthServer's only context is /health and the JDK server matches contexts by prefix,
# so /health-anything would still answer 200. Any other path is a 404.
FORCED_FAIL_PATH = '/forced-failure'


def force_fail_enabled() -> bool:
    """Test only (setting APPV2_FORCE_FAIL): every playbook's verify step asks a path the app does not serve, so the
    site fails after the swap and the workflow's rollback route runs. The rollback job keeps the real health_url."""
    return env('APPV2_FORCE_FAIL', 'false').lower() in ('1', 'true', 'yes', 'on')


def verify_url(app: dict, force_fail: bool = False) -> str:
    """What the playbook's verify step asks: the app's health URL, or, when forcing a failure, a path it does not
    serve (404)."""
    base = app['health_url']
    return base.rsplit('/health', 1)[0] + FORCED_FAIL_PATH if force_fail else base


def bundle_name(app_name: str, run_id: str) -> str:
    return f'{app_name}-bundle-{run_id}.tgz'


def bundle_url(app_name: str, run_id: str) -> str:
    """Where Rebuild from source puts the built app (pipelines-setup/pipeline.yaml, task package): Nexus maven-releases."""
    base = env('NEXUS_URL', 'https://nexus.example').rstrip('/')
    return f"{base}/repository/maven-releases/com/lab/appv2/{app_name}-bundle/{run_id}/{bundle_name(app_name, run_id)}"


def render_bundle_playbook(event: dict, app: dict, changes: list[dict], run_id: str, force_fail: bool = False) -> str:
    """Rebuild from source: deploy the app as Maven built it. The bundle (every resolved jar plus the app's own) is
    downloaded pinned to the checksum the pipeline reported, the current lib folder is backed up whole and replaced,
    the service restarts once, and the changed libraries' jars must be in the new folder. On failure the rescue keeps
    the backed-up folder and hands over to the workflow's rollback route."""
    what = '; '.join(f"{c['artifact']} {c['from']} -> {c['to']}" for c in changes)
    expect = '\n'.join(f'      - {c["new_jar"]}' for c in changes)
    name = bundle_name(app['app'], run_id)
    return f"""---
# Generated by the Applications v2 agent for {app['app']} (Rebuild from source): {what}
# The bundle is what mvn package resolved from the updated pom.xml, built and tested in a pod by OpenShift Pipelines.
- name: Deploy the rebuilt {app['app']}
  hosts: "{{{{ target_hosts }}}}"
  become: true
  gather_facts: false
  vars:
    app_dir: {app['path']}
    lib_dir: {app['path']}/lib
    backup_dir: {app['path']}/backup/lib-{run_id}
    staging_dir: {app['path']}/staging-{run_id}
    service: {app['service']}
    health_url: {app['health_url']}
    verify_url: {verify_url(app, force_fail)}
    bundle_name: {name}
    bundle_url: "{bundle_url(app['app'], run_id)}"
    expect_jars:
{expect}
    jar_sha256s: "{{{{ verified_sha256s if verified_sha256s is mapping else (verified_sha256s | from_json) }}}}"
  tasks:
    - name: Deploy the built app, restart once and verify
      block:
        - name: Download the bundle from Nexus, pinned to the checksum the pipeline verified
          ansible.builtin.get_url:
            url: "{{{{ bundle_url }}}}"
            dest: "/tmp/{{{{ bundle_name }}}}"
            checksum: "sha256:{{{{ jar_sha256s[bundle_name] }}}}"
            mode: "0600"

        - name: Unpack it into a staging folder
          ansible.builtin.file:
            path: "{{{{ staging_dir }}}}"
            state: directory
            mode: "0755"

        - name: Unpack the bundle
          ansible.builtin.unarchive:
            src: "/tmp/{{{{ bundle_name }}}}"
            dest: "{{{{ staging_dir }}}}"
            remote_src: true

        - name: Back up the current libraries, whole
          ansible.builtin.copy:
            src: "{{{{ lib_dir }}}}/"
            dest: "{{{{ backup_dir }}}}/"
            remote_src: true
            mode: preserve

        - name: Remove the current libraries
          ansible.builtin.file:
            path: "{{{{ lib_dir }}}}"
            state: absent

        - name: Put the built libraries in place
          ansible.builtin.copy:
            src: "{{{{ staging_dir }}}}/lib/"
            dest: "{{{{ lib_dir }}}}/"
            remote_src: true
            mode: preserve

        - name: Restart the service
          ansible.builtin.systemd_service:
            name: "{{{{ service }}}}"
            state: restarted

        - name: Verify the service is healthy
          ansible.builtin.uri:
            url: "{{{{ verify_url }}}}"
            status_code: 200
          register: health
          until: health.status == 200
          retries: 12
          delay: 5

        - name: Verify the changed libraries are the new jars
          ansible.builtin.stat:
            path: "{{{{ lib_dir }}}}/{{{{ item }}}}"
          loop: "{{{{ expect_jars }}}}"
          register: new_stats

        - name: Verify every one is there
          ansible.builtin.assert:
            that: item.stat.exists
          loop: "{{{{ new_stats.results }}}}"

        - name: Report patched
          ansible.builtin.set_stats:
            data:
              outcome: patched
              patched: true
              rolled_back: false
              version: "{{{{ expect_jars | join(', ') }}}}"
      # Nothing is restored here: the backed-up lib folder stays where it is and the App Patch v2 workflow takes
      # its rollback route (AAP job "App Patch v2 - Rollback") with what this reports.
      rescue:
        - name: Hand the failure to the rollback route
          ansible.builtin.set_stats:
            data:
              outcome: failed
              patched: false
              rolled_back: false
              failed_step: "{{{{ ansible_failed_task.name | default('unknown') }}}}"
              failed_reason: "{{{{ ansible_failed_result.msg | default('') | string | truncate(200) }}}}"
              rollback_json: "{{{{ {{'mode': 'source', 'lib_dir': lib_dir, 'backup_dir': backup_dir, 'service': service,
                                  'health_url': health_url, 'restore': []}} | to_json }}}}"
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
    rescue_ok, rescue_why = rescue_hands_over(text)
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
        {'id': 'rollback', 'label': 'Hands failure to the rollback route',
         'ok': rescue_ok, 'detail': rescue_why},
        {'id': 'report', 'label': 'Reports the outcome (patched / failed)',
         'ok': 'ansible.builtin.set_stats' in modules and 'outcome: patched' in text and 'patched:' in text, 'detail': ''},
    ]
    return checks


def rescue_hands_over(text: str) -> tuple[bool, str]:
    """The rescue must leave the server for the workflow's rollback route: keep the backup, change nothing, and report
    outcome: failed with the rollback_json the Rollback job reads. A rescue that restores or restarts on its own would
    race the rollback job, so it fails this check."""
    m = re.search(r'^(\s+)rescue:\s*$', text, re.M)
    if not m:
        return False, 'no rescue: block'
    rescue = text[m.end():]
    nxt = re.search(r'^\s{0,%d}\S' % len(m.group(1)), rescue, re.M)        # the end of the rescue list
    rescue = rescue[:nxt.start()] if nxt else rescue
    acting = [mod for mod in ('ansible.builtin.copy', 'ansible.builtin.file', 'ansible.builtin.systemd_service',
                              'ansible.builtin.get_url', 'ansible.builtin.unarchive') if mod in rescue]
    if acting:
        return False, 'the rescue changes the server itself (' + ', '.join(m_.split('.')[-1] for m_ in acting) + \
            '); the rollback route does that'
    if 'outcome: failed' not in rescue or 'rollback_json' not in rescue:
        return False, 'the rescue must report outcome: failed and rollback_json'
    return True, ''


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


def draft_playbook(event: dict, app: dict, changes: list[dict] | None = None) -> tuple[str, str, list[dict], str]:
    """(playbook, source, checks, note). In live mode the LLM writes the tasks and the system supplies everything
    it should not decide: the hosts, become, and the paths, jar names and checksum in vars. The checks then judge
    the tasks: allowed modules only, a pinned download, health and checksum verified, a rollback, the report. The
    template stands in when there is no LLM, in demo mode, or when the tasks fail a check, and the note says why."""
    template = render_playbook(event, app, changes)
    if H.demo_mode() or not H.llm:
        return template, 'template', check_playbook(template, template), ''
    _, example = _split_play(template)
    prompt = ('Write the tasks for an Ansible play, and nothing else: no prose, no code fences, no play header '
              'and no vars, which are supplied. Return a YAML list of tasks starting with "- name:". They must do '
              'what these example tasks do, using the same variables: for every entry in swaps (loop over it), '
              'download the new jar with its pinned sha256 from jar_sha256s, back up and remove the old jar; restart '
              'the service once; verify health and every checksum; report outcome: patched with set_stats; and in a '
              'rescue block change NOTHING on the server: only report outcome: failed and rollback_json with '
              'set_stats exactly as the example does (the workflow\'s rollback job restores the backup). Use only '
              'these modules: '
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
_IN_PROCESS = {'assessing': 'assess', 'generating': 'generate', 'dispatching': 'dispatch', 'cancelling': 'cancel'}


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
    for cache in ('_MINE_CACHE', '_LW_BUILDS', '_ESTATE_CACHE'):   # demo and live answers never mix
        globals()[cache].clear()
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
        return _RUN.get('status') in ('assessing', 'generating', 'dispatching', 'running', 'cancelling')


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
        # The sites are known now: show them at once. The three slow parts (the reasoning per site, the osv.dev
        # packages, the agent's note) are independent, so they run side by side and each fills in when it is done.
        imp['pending'] = [k for k, on in (('reasoning', bool(imp['targets'])),
                                          ('extra', osv_enabled() and bool(imp['targets'])),
                                          ('info', True)) if on]
        _set(impact=json.loads(json.dumps(imp)))

        def fill(**kw) -> None:
            with _LOCK:
                cur = _RUN.get('impact') or {}
                cur.update({k: v for k, v in kw.items() if k != 'done'})
                cur['pending'] = [p for p in cur.get('pending', []) if p != kw.get('done')]
            _persist()

        def do_reasoning() -> None:
            _trace('inventory', 'reasoning', f"past changes for {len(imp['targets'])} app/server pair(s)")
            H.demo_pause(1.0)
            notes, rsource = reasoning(imp['targets'])
            if rsource == 'rag+llm':
                _trace('reasoning', 'llm', 'one line per app and server')
            targets = [{**t, 'reasoning': notes.get(t['key'], '')} for t in imp['targets']]
            fill(targets=targets, reasoning_source=rsource, done='reasoning')

        def do_extra() -> None:
            _trace('inventory', 'osv', f"what else is open on {', '.join(imp['apps'])}?")
            H.demo_pause(1.0)
            extra = extras(ev, imp, load_bom())
            offered = [r for r in extra['rows'] if r['selectable']]
            _trace('osv', 'inventory', f"{len(extra['rows'])} open library(ies), {len(offered)} with a fix to offer"
                   + (f" ({extra['error']})" if extra.get('error') else ''))
            fill(extra=extra, done='extra')

        def do_info() -> None:
            if H.llm and not H.demo_mode() and imp['targets']:
                _trace('inventory', 'llm', 'note for the reviewer')
            info, source = helpful_info(ev, imp)
            _set(info=info, info_source=source)
            fill(done='info')

        jobs = [do_info] + ([do_reasoning] if 'reasoning' in imp['pending'] else []) \
            + ([do_extra] if 'extra' in imp['pending'] else [])
        with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
            for f in [pool.submit(j) for j in jobs]:
                f.result()
        imp = state()['impact']
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


def start_generate(targets: list[str] | None = None, extra: list[str] | None = None,
                   allow_major: bool = False, test_mode: str = 'swap') -> tuple[int, dict]:
    """Prepare the remediation for the selected sites (all of them when targets is None): a playbook for each app
    they run, swapping the Lightwell build and any osv.dev packages selected for that app (none when extra is
    None). The site selection carries to the run, which can narrow it but not widen it."""
    with _LOCK:
        if _RUN.get('status') != 'assessed':
            return 409, {'ok': False, 'error': 'assess an event first'}
        known = [t['key'] for t in _RUN['impact']['targets']]
        # By default only exact matches: a version change is something the operator ticks.
        chosen = ([t['key'] for t in _RUN['impact']['targets'] if not t.get('version_change')] if targets is None
                  else [k for k in known if k in set(targets)])
        if not chosen:
            return 400, {'ok': False, 'error': 'select at least one site'}
        _RUN['selected'] = chosen
        apps = {k.split('|', 1)[0] for k in chosen}
        if test_mode == 'source':
            repos = {b['app']: b.get('repo') for b in load_bom()}
            missing = sorted(a for a in apps if not repos.get(a))
            if missing:
                return 400, {'ok': False, 'error': f"no source repository for {', '.join(missing)}: use Swap libraries"}
        _RUN['test_mode'] = 'source' if test_mode == 'source' else 'swap'
        offered = {r['id']: len(r.get('options') or [1]) for r in ((_RUN['impact'].get('extra') or {}).get('rows') or [])
                   if r['selectable'] or (allow_major and r['kind'] == 'major')}
        picked = []
        for x in extra or []:                # "row id" for its default option, or "row id::option index"
            rid, _, opt = x.partition('::')
            if rid in offered and rid.split('|', 1)[0] in apps and (not opt or (opt.isdigit() and int(opt) < offered[rid])):
                picked.append(x)
        _RUN['extra_selected'] = picked
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
        selected = set(st.get('selected') or [t['key'] for t in imp['targets']])
        if len(selected) < len(imp['targets']):
            _trace('console', 'playbook', f"{len(selected)} of {len(imp['targets'])} site(s) selected")
        for app in imp['apps']:
            target = next((t for t in imp['targets'] if t['app'] == app and t['key'] in selected), None)
            if target is None:
                continue                     # none of its sites selected: nothing to prepare
            rows = {r['id']: r for r in ((imp.get('extra') or {}).get('rows') or [])}
            chosen = [(x.partition('::')[0], x.partition('::')[2]) for x in st.get('extra_selected') or []]
            extra_changes = [change_for_extra(rows[rid], int(opt) if opt else None)
                             for rid, opt in chosen if rid in rows and rows[rid]['app'] == app]
            # One change per library: an osv.dev choice on the fix's own library (an app on another version of it)
            # stands in for the fix there.
            same = {(c['group'], c['artifact']) for c in extra_changes}
            changes = ([] if (ev['group'], ev['artifact']) in same else [change_for_event(ev, target)]) + extra_changes
            _trace('intake', 'playbook', f'draft for {app}' + (f' ({len(changes)} jars)' if len(changes) > 1 else ''))
            if H.llm and not H.demo_mode():
                _trace('playbook', 'llm', f'draft for {app}')
            H.demo_pause(1.4)
            forced = force_fail_enabled()
            if st.get('test_mode') == 'source':
                # Rebuild from source deploys the built bundle: the checked template, pinned to the pipeline's checksum.
                text = render_bundle_playbook(ev, target, changes, st['run_id'], force_fail=forced)
                source, checks, note = 'template', check_playbook(text, text), 'Rebuild from source: the bundle-deploy template.'
            elif forced:
                text = render_playbook(ev, target, changes, force_fail=True)
                source, checks, note = 'template', check_playbook(text, text), ''
            else:
                text, source, checks, note = draft_playbook(ev, target, changes)
            if forced:
                note = ('TEST: forced failure (setting APPV2_FORCE_FAIL). The verify step asks ' + FORCED_FAIL_PATH
                        + ', which the app does not serve, so every site in this run fails after the swap and the '
                        'workflow takes its rollback route. ' + note).strip()
                _trace('playbook', 'intake', f'{app}: forced failure on (APPV2_FORCE_FAIL): testing the rollback route')
            ok = all(c['ok'] for c in checks)
            _trace('playbook', 'intake', f"{app}: {'checks passed' if ok else 'checks FAILED'} ({source})")
            playbooks.append({'app': app, 'filename': f"app-v2/{app}-{ev['artifact']}-{st['run_id']}.yml", 'changes': changes,
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


# The class each library's /health probe looks for, so /health can name the jar it is found in. Used by the sample
# app's deploy (aap-setup/create-app-v2-objects.py) and the test in a pod.
PROBE_CLASS = {
    'mina-core': 'org.apache.mina.core.session.IoSession',
    'zookeeper': 'org.apache.zookeeper.ZooKeeper',
    'spring-security-web': 'org.springframework.security.web.FilterChainProxy',
    'postgresql': 'org.postgresql.Driver',
    'log4j-core': 'org.apache.logging.log4j.core.LoggerContext',
    'commons-io': 'org.apache.commons.io.IOUtils',
    'httpclient5': 'org.apache.hc.client5.http.classic.HttpClient',
    'avro': 'org.apache.avro.Schema',
}

HOST_STEPS = ('commit', 'test', 'approval', 'sync', 'remediate', 'verify', 'rollback', 'notify')
SKIPPED_STEPS = {k: 'skipped' for k in HOST_STEPS}


def start_dispatch(targets: list[str] | None = None) -> tuple[int, dict]:
    """Run on the selected app/server pairs (all of them when targets is None). The rest are recorded as
    skipped, so the run and its history say what was left out and why."""
    with _LOCK:
        if _RUN.get('status') != 'generated':
            return 409, {'ok': False, 'error': 'generate the playbook first'}
        # Only sites prepared for: their app has a playbook.
        known = set(_RUN.get('selected') or [t['key'] for t in _RUN['impact']['targets']])
        chosen = known if targets is None else {k for k in targets if k in known}
        if not chosen:
            return 400, {'ok': False, 'error': 'select at least one app and server'}
        _RUN['status'] = 'dispatching'
        st = json.loads(json.dumps(_RUN))
    hosts = []
    for t in st['impact']['targets']:
        pb = next((p for p in st['playbooks'] if p['app'] == t['app']), {})
        if t['key'] in chosen:
            hosts.append({**t, 'playbook': pb['filename'], 'outcome': 'queued', 'steps': {}, 'execution_id': ''})
        else:
            hosts.append({**t, 'playbook': pb.get('filename', ''), 'outcome': 'skipped', 'steps': dict(SKIPPED_STEPS),
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
    for key in HOST_STEPS:
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
              provenance='verified', jar_sha256=jar_sha, steps={'commit': 'done', 'test': 'active'})
    _roll_stages()
    # The test in a pod, staged: one PipelineRun per app (the sites of an app run the same jars).
    _trace('ao', 'aap', 'test the change in a pod')
    _trace('aap', 'pipelines', f"{len({h['app'] for h in active})} PipelineRun(s): build the app with the change, start it, check /health")
    # The task strip, staged: fetch -> build -> health, each running then done, with the kind of log line each prints.
    apps = sorted({h['app'] for h in active})
    # The log lines name this run's own change, as the real tasks would.
    pb_changes = [c for p in st.get('playbooks') or [] if p.get('app') in apps for c in p.get('changes') or []] \
        or [change_for_event(st['event'], active[0])] if active else []
    first = pb_changes[0] if pb_changes else {'new_jar': 'the new jar', 'group': '', 'artifact': '', 'from': '', 'to': ''}
    lines = {'fetch': [f"{first['new_jar']}: sha256 (verified by the commit job)"]
                      + [f"{c['new_jar']}: sha256 (verified by the commit job)" for c in pb_changes[1:2]],
             'clone': ['Cloning into /workspace/source/repo ... done'],
             'update-pom': [f"pom.xml (version): {c['group']}:{c['artifact']} {c['from']} -> {c['to']}" for c in pb_changes[:2]]
                           or ['pom.xml updated'],
             'package': ['[INFO] BUILD SUCCESS', 'bundle uploaded to Nexus maven-releases'],
             'build': ['STEP 3/5: COPY lib/ /deployments/lib/', 'Pushing image to the internal registry'],
             'health': ["health: {'status': 'UP', ...}"]}
    order = PIPELINE_TASKS_SOURCE if st.get('test_mode') == 'source' else PIPELINE_TASKS
    t0 = now_iso()
    for i, task in enumerate(order):
        with _LOCK:
            sim = _RUN.setdefault('pipe_sim', {})
            for app in apps:
                cur = sim.setdefault(app, {'name': f'app-v2-{app}-{st["run_id"]}', 'state': 'running', 'console_url': '',
                                           'tasks': [{'task': t, 'state': 'pending'} for t in order]})
                cur['tasks'][i] = {'task': task, 'state': 'running', 'started': now_iso(), 'step': task, 'log': lines[task]}
        _persist()
        H.demo_pause(6)                     # about 2 s a task at the default DEMO_LATENCY: long enough to point at
        with _LOCK:
            for app in apps:
                cur = _RUN['pipe_sim'][app]
                cur['tasks'][i].update(state='succeeded', finished=now_iso(), log=[])
                if i == len(order) - 1:
                    cur['state'] = 'succeeded'
        _persist()
    del t0
    if state().get('cancelling'):
        return
    pbs = {p['app']: p for p in st.get('playbooks') or []}
    for h in active:
        changes = (pbs.get(h['app']) or {}).get('changes') or [change_for_event(st['event'], h)]
        _host(h['key'], test={
            'passed': True, 'image': f"image-registry.openshift-image-registry.svc:5000/agentic-patching/app-v2-{h['app']}:{st['run_id']}",
            'health': json.dumps({'status': 'UP', 'jars': {c['artifact']: c['new_jar'] for c in changes}}),
            **_osv_rescan(h['app'], changes), 'pipelinerun': f"app-v2-{h['app']}-{st['run_id']}", 'reason': '',
            'sbom_url': f"{gitea}/src/branch/main/{h['playbook'].replace('.yml', '.sbom.json')}",
            'mode': st.get('test_mode', 'swap'),
            'bundle_url': bundle_url(h['app'], st['run_id']) if st.get('test_mode') == 'source' else '',
            'branch_url': (f"{env('GITEA_URL', 'https://gitea.example')}/"
                           f"{next((b.get('repo', '') for b in load_bom() if b['app'] == h['app']), '')}/src/branch/fix/{st['run_id']}")
                          if st.get('test_mode') == 'source' else ''},
            steps={'test': 'done', 'approval': 'skipped' if h['env'] == 'qa' else 'waiting'},
            outcome='running' if h['env'] == 'qa' else 'awaiting_approval')
    _trace('pipelines', 'aap', 'the app came up on the new jars')
    _roll_stages()
    for h in [x for x in active if x['env'] == 'qa']:
        _run_host_sim(h)
    _set(status='awaiting_approval' if any(x['env'] != 'qa' for x in active) else 'running')
    _maybe_finish()


def _run_host_sim(h: dict, delay: float = 1.0) -> None:
    key = h['key']
    for step in ('sync', 'remediate', 'verify'):
        if state().get('cancelling'):
            return
        _host(key, steps={step: 'active'})
        if step == 'sync':
            _trace('ao', 'aap', f'{_label(h)}: sync and run')
        elif step == 'remediate':
            _trace('aap', 'servers', f'{_label(h)}: swap the jar, restart {h["service"]}')
        _roll_stages()
        H.demo_pause(delay)
        if step == 'verify' and h['key'] == DEMO_FAILING_KEY:
            # The playbook keeps the backup and reports outcome: failed; the workflow takes its rollback route.
            _host(key, steps={'verify': 'failed', 'rollback': 'active'})
            _trace('aap', 'ao', f'{_label(h)}: health check failed (outcome: failed)')
            _trace('ao', 'aap', f'{_label(h)}: rollback route: restore the backup')
            _roll_stages()
            H.demo_pause(delay)
            pb = next((p for p in state().get('playbooks') or [] if p['app'] == h['app']), {})
            olds = [c['old_jar'] for c in pb.get('changes') or []] or ['the original jar']
            _host(key, steps={'rollback': 'done'}, outcome='rolled_back',
                  detail=(f"Health check failed after the swap (HTTP 503 for 60s). Rolled back by the workflow "
                          f"(AAP: App Patch v2 - Rollback): {', '.join(olds)} back, healthy."))
            _notify_sim(h, 'rolled back')
            return
        _host(key, steps={step: 'done'})
    pb = next((p for p in state().get('playbooks') or [] if p['app'] == h['app']), {})
    jars = [c['new_jar'] for c in pb.get('changes') or []] or [jar_name(state()['event']['artifact'], state()['event']['version'])]
    _host(key, outcome='patched', detail=f"{h['service']} healthy on {', '.join(jars)}")
    _trace('aap', 'ao', f'{_label(h)}: patched and healthy')
    _notify_sim(h, 'patched')


def _notify_sim(h: dict, what: str) -> None:
    """Demo: the Mattermost card that ends the site's route."""
    _host(h['key'], steps={'notify': 'active'})
    _roll_stages()
    H.demo_pause(0.5)
    _trace('aap', 'mattermost', f'{_label(h)}: {what} card posted')
    _host(h['key'], steps={'notify': 'done'})
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


# ---------------------------------------------------------------------------- cancel a run

CANCELLABLE = ('dispatching', 'running', 'awaiting_approval')


def cancel_run() -> tuple[int, dict]:
    """Stop the run: cancel its AO executions, any App Patch v2 AAP job still running, and its PipelineRuns; then check
    every site the playbook may have reached and say plainly what, if anything, was left half done."""
    st = state()
    if st.get('status') not in CANCELLABLE:
        return 409, {'ok': False, 'error': f"nothing to cancel (the run is {st.get('status')})"}
    _set(cancelling=True, status='cancelling', cancel={'started_at': now_iso(), 'steps': [], 'sites': []})
    _trace('console', 'ao', 'cancel the run')
    threading.Thread(target=_cancel, args=(st,), daemon=True, name='appv2-cancel').start()
    return 200, {'ok': True}


def _cancel_step(what: str, ok: bool, detail: str = '') -> None:
    with _LOCK:
        _RUN.setdefault('cancel', {}).setdefault('steps', []).append({'what': what, 'ok': ok, 'detail': detail})
    _persist()


def _cancel(st: dict) -> None:
    active = [h for h in st.get('hosts') or [] if h['outcome'] in ('queued', 'running', 'awaiting_approval')]
    # Sites the playbook may have reached: its run step had started.
    reached = [h for h in active if (h.get('steps') or {}).get('sync') in ('active', 'done')
               or (h.get('steps') or {}).get('remediate') in ('active', 'done')]
    for h in active:
        _host(h['key'], outcome='cancelled', detail='Cancelled by the operator.',
              steps={k: 'skipped' for k, v in (h.get('steps') or {}).items() if v in ('active', 'waiting', 'pending', None)}
              | {k: 'skipped' for k in HOST_STEPS if k not in (h.get('steps') or {})})
    if st.get('simulated'):
        _cancel_step('Simulated executions stopped', True, f'{len(active)} site(s)')
        sites = [{'key': h['key'], 'site': h.get('site') or h['host'], 'host': h['host'], 'clean': True,
                  'state': 'untouched' if h not in reached else 'untouched (demo: no server was changed)', 'detail': ''}
                 for h in active]
        return _cancel_done(st, sites)
    # 1. AO executions.
    for h in active:
        ex = h.get('execution_id')
        if not ex:
            continue
        try:
            H.ao_call(f'/api/v1/executions/{ex}/cancel', 'POST', {})
            _cancel_step(f'AO execution for {_label(h)} cancelled', True, ex)
        except Exception as exc:
            _cancel_step(f'AO execution for {_label(h)} not cancelled', False, f'{ex}: {str(exc)[:200]}')
    # 2. AAP jobs AO had already launched: AO's cancel does not reach a job that is running.
    if H.aap_call:
        try:
            jobs = (H.aap_call('/jobs/?status__in=pending,waiting,running&order_by=-id&page_size=50') or {}).get('results') or []
            mine = [j for j in jobs if str(j.get('name', '')).startswith('App Patch v2') and str(j.get('created', '')) >= st.get('started_at', '')]
            for j in mine:
                H.aap_call(f"/jobs/{j['id']}/cancel/", 'POST', {})
            deadline = time.time() + 45
            left = list(mine)
            while left and time.time() < deadline:
                time.sleep(3)
                left = [j for j in left if (H.aap_call(f"/jobs/{j['id']}/") or {}).get('status') in ('pending', 'waiting', 'running')]
            for j in mine:
                gone = j not in left
                _cancel_step(f"AAP job {j['id']} ({j['name']}) {'cancelled' if gone else 'still running'}", gone,
                             '' if gone else 'cancel it in AAP; it may still change the host')
            if not mine:
                _cancel_step('No App Patch v2 AAP job was running', True)
        except Exception as exc:
            _cancel_step('AAP jobs not checked', False, str(exc)[:200])
    else:
        _cancel_step('AAP jobs not checked', False, 'no AAP access configured (AAP_BASE_URL, AAP_TOKEN)')
    # 3. PipelineRuns still running.
    ns = env('APPV2_PIPELINE_NAMESPACE', 'agentic-patching')
    for app in sorted({h['app'] for h in active}):
        name = pipeline_run_name(app, st['run_id'])
        try:
            pr = H.k8s_get(f'/apis/tekton.dev/v1/namespaces/{ns}/pipelineruns/{name}') if H.k8s_get else None
            cond = next((c for c in ((pr or {}).get('status') or {}).get('conditions') or [] if c.get('type') == 'Succeeded'), {})
            if pr and cond.get('status') not in ('True', 'False'):
                H.k8s_patch(f'/apis/tekton.dev/v1/namespaces/{ns}/pipelineruns/{name}', {'spec': {'status': 'Cancelled'}})
                _cancel_step(f'PipelineRun {name} cancelled', True)
        except Exception as exc:
            if '404' not in str(exc):
                _cancel_step(f'PipelineRun {name} not cancelled', False, str(exc)[:200])
    # 4. What the sites look like now.
    sites = [{'key': h['key'], 'site': h.get('site') or h['host'], 'host': h['host'], 'clean': True,
              'state': 'untouched: stopped before the playbook ran', 'detail': ''} for h in active if h not in reached]
    sites += _check_sites(st, reached)
    _cancel_done(st, sites)


def _check_sites(st: dict, hosts: list[dict]) -> list[dict]:
    """For each site the playbook may have reached: its lib folder, backup folder and service, read through an AAP
    ad-hoc command, against the run's change list. Clean is either untouched (old jars, empty backup) or fully
    patched (new jars, old ones in backup); anything else is reported with how to put it back."""
    if not hosts:
        return []
    pbs = {p['app']: p for p in st.get('playbooks') or []}
    out = []
    try:
        res = _adhoc_read([h['host'].split('.')[0] for h in hosts],
                          'for a in ' + ' '.join(sorted({h["app"] for h in hosts})) + '; do echo "== $a"; '
                          'ls /opt/apps/$a/lib; echo "-- backup"; ls /opt/apps/$a/backup; echo "-- service"; '
                          'systemctl is-active $a; done')
    except Exception as exc:
        return [{'key': h['key'], 'site': h.get('site') or h['host'], 'host': h['host'], 'clean': False,
                 'state': 'not checked', 'detail': f'could not read the host ({str(exc)[:160]}); check /opt/apps/{h["app"]} by hand'}
                for h in hosts]
    for h in hosts:
        text = res.get(h['host'].split('.')[0], '')
        block = text.split(f"== {h['app']}", 1)[-1].split('\n== ', 1)[0]
        lib = block.split('-- backup')[0].split()
        backup = block.split('-- backup', 1)[-1].split('-- service')[0].split()
        svc = block.split('-- service', 1)[-1].split()[:1]
        changes = (pbs.get(h['app']) or {}).get('changes') or []
        old = [c['old_jar'] for c in changes]
        new = [c['new_jar'] for c in changes]
        untouched = all(j in lib for j in old) and not any(j in lib for j in new) and not backup
        patched = all(j in lib for j in new) and not any(j in lib for j in old)
        up = svc == ['active']
        if (untouched or patched) and up:
            out.append({'key': h['key'], 'site': h.get('site') or h['host'], 'host': h['host'], 'clean': True,
                        'state': 'untouched' if untouched else 'patched before the cancel landed (left patched)', 'detail': ''})
            continue
        fix = (f"on {h['host']}: " + '; '.join(f"cp /opt/apps/{h['app']}/backup/{c['old_jar']} /opt/apps/{h['app']}/lib/ && rm -f /opt/apps/{h['app']}/lib/{c['new_jar']}"
                                                for c in changes) + f"; systemctl restart {h['app']}")
        out.append({'key': h['key'], 'site': h.get('site') or h['host'], 'host': h['host'], 'clean': False,
                    'state': 'half changed' if (lib or backup) else 'not readable',
                    'detail': f"lib: {', '.join(lib) or '—'}; backup: {', '.join(backup) or 'empty'}; service: {svc[0] if svc else 'unknown'}. "
                              f"To put it back: {fix}"})
    return out


def _adhoc_read(hosts: list[str], script: str) -> dict[str, str]:
    """{host: stdout} of a read-only shell command on the app servers, as an AAP ad-hoc command."""
    from urllib.parse import quote
    inv = ((H.aap_call(f"/inventories/?name={quote(env('TARGET_INVENTORY', 'lab-inventory'))}") or {}).get('results') or [{}])[0].get('id')
    cred = ((H.aap_call(f"/credentials/?name={quote(env('MACHINE_CREDENTIAL', 'lab-credential'))}") or {}).get('results') or [{}])[0].get('id')
    if not inv or not cred:
        raise RuntimeError('TARGET_INVENTORY / MACHINE_CREDENTIAL not found in AAP')
    job = H.aap_call('/ad_hoc_commands/', 'POST', {'inventory': inv, 'credential': cred, 'module_name': 'shell',
                                                   'module_args': script, 'limit': ','.join(hosts)})
    for _ in range(60):
        st = H.aap_call(f"/ad_hoc_commands/{job['id']}/") or {}
        if st.get('status') in ('successful', 'failed', 'error', 'canceled'):
            break
        time.sleep(3)
    out = {}
    for e in (H.aap_call(f"/ad_hoc_commands/{job['id']}/events/?page_size=200") or {}).get('results') or []:
        if e.get('event') in ('runner_on_ok', 'runner_on_failed'):
            out[e.get('host_name', '')] = ((e.get('event_data') or {}).get('res') or {}).get('stdout', '')
    return out


def _cancel_done(st: dict, sites: list[dict]) -> None:
    with _LOCK:
        c = _RUN.setdefault('cancel', {})
        c.update(sites=sites, clean=all(x['clean'] for x in sites) and all(s_['ok'] for s_ in c.get('steps', [])),
                 finished_at=now_iso())
        for k, v in (_RUN.get('stages') or {}).items():
            if v in ('active', 'pending', 'waiting'):
                _RUN['stages'][k] = 'skipped'
        _RUN['cancelling'] = False
        _RUN['status'] = 'cancelled'
        _RUN['finished_at'] = now_iso()
    _persist()
    bad = [x for x in sites if not x['clean']]
    _trace('console', 'console', 'run cancelled' + (f"; {len(bad)} site(s) need attention" if bad else '; every site clean'))
    outcomes = [h['outcome'] for h in state().get('hosts') or []]
    _set(summary={k: outcomes.count(k) for k in ('patched', 'rolled_back', 'rejected', 'failed', 'skipped', 'cancelled')})
    _record(state())


def _maybe_finish() -> None:
    st = state()
    if st.get('cancelling') or st.get('status') == 'cancelled':
        return
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
    pbs = {p['app']: p for p in st.get('playbooks') or []}
    for app in st['impact']['apps']:
        mine = [h for h in st['hosts'] if h['app'] == app and h['outcome'] != 'skipped']
        if not mine:
            continue                         # none of its sites was in this run: nothing to say about its BOM
        changes = (pbs.get(app) or {}).get('changes') or [{'group': ev['group'], 'artifact': ev['artifact'],
                                                          'to': ev['version'], 'from': upstream(ev['version'])}]
        if mine and all(h['outcome'] == 'patched' for h in mine):
            with _LOCK:
                for c in changes:
                    _BOM_UPDATES[f"{app}|{c['group']}:{c['artifact']}"] = c['to']
            bom.append({'app': app, 'version': changes[0]['to'], 'changed': True,
                        'also': [f"{c['artifact']} {c['to']}" for c in changes[1:]]})
            _trace('results', 'inventory', f"{app}: BOM now " + ', '.join(f"{c['artifact']} {c['to']}" for c in changes))
        else:
            bom.append({'app': app, 'version': changes[0]['from'], 'changed': False, 'also': []})
            _trace('results', 'inventory', f'{app}: BOM unchanged (not every selected site patched)')
    history = feed_history(st)
    _ESTATE_CACHE.clear()
    try:
        _estate_file().unlink()
    except OSError:
        pass
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
    # The event's CVEs and every other change the run carried (a zookeeper fix riding the same restart, say).
    fixed = list(dict.fromkeys(list(ev.get('cves') or [])
                               + [x for p in st.get('playbooks') or [] for c in p.get('changes') or [] for x in c.get('cves') or []]))
    doc.text(', '.join(fixed) or 'Not itemised by Lightwell.', size=9)
    doc.gap(8)
    changes = [(p['app'], c) for p in st.get('playbooks') or [] for c in p.get('changes') or []]
    if changes:
        doc.text('Change list', size=11, bold=True)
        doc.gap(2)
        doc.table(['App', 'Library', 'From', 'To', 'Source', 'Checked by'],
                  [[a, c['artifact'], c['from'], c['to'],
                    ('Lightwell' if c['source'] == 'lightwell' else 'Upstream (osv.dev)') + (', version change' if c.get('version_change') else ''),
                    'cosign provenance' if c['source'] == 'lightwell' else 'Maven Central sha1'] for a, c in changes],
                  [90, 90, 70, 100, 80, 69])
        doc.gap(8)
    tests = {h['app']: h['test'] for h in hosts if h.get('test')}
    if tests:
        doc.text('Test in a pod (OpenShift Pipelines)', size=11, bold=True)
        doc.gap(2)
        doc.table(['App', 'Result', 'osv.dev open after', 'PipelineRun'],
                  [[a, 'passed' if t.get('passed') else 'failed', str(t.get('osv_open', '')), t.get('pipelinerun', '')]
                   for a, t in tests.items()], [100, 60, 100, 239])
        doc.gap(8)
    doc.text('Per-site outcome', size=11, bold=True)
    doc.gap(2)
    doc.table(['Site', 'App', 'Domain', 'Env', 'Outcome', 'Detail'],
              [[h.get('site') or h['host'], h['app'], h.get('domain', ''), 'LAB' if h.get('env') == 'qa' else 'LIVE',
                h.get('outcome', '').replace('_', ' '), h.get('detail', '')] for h in hosts] or [['—'] * 6],
              [70, 90, 80, 32, 60, 167])
    doc.gap(10)
    _report_roi(doc, st)
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
    name = re.sub(r'[^A-Za-z0-9._-]', '_', f"{ev['artifact']}-{ev['version']}-{st.get('run_id', '')}") + '.pdf'
    path = doc.save(out / name)
    return {'file': path.name, 'bytes': path.stat().st_size, 'created_at': now_iso()}


def _fmt_min(m: float) -> str:
    if (m or 0) < 1:
        return 'under 1m'
    m = round(m)
    return f"{m // 60}h {m % 60}m" if m >= 60 else f"{m}m"


def _report_roi(doc, st: dict) -> None:
    """The run's Calculate ROI figures (agentic-patching.py roi_appv2), with the settings' assumptions as they are
    now. Left out when nothing was dispatched or the console gave no hook."""
    try:
        r = H.roi(st) if H.roi else None
    except Exception:
        r = None
    if not r:
        return
    cur, sv, m = r.get('currency', '$'), r['saved'], r['measured']
    money = lambda v: f"{cur}{v:,.0f}"
    doc.text('Return on investment (estimate)', size=11, bold=True)
    doc.gap(2)
    effort = f" · {sv['effort_x']}x less effort" if sv.get('effort_x') else ''
    doc.banner(f"{money(sv['cost'])} labour saved · {_fmt_min(sv['minutes'])} of engineer time{effort}",
               f"{m['patched']} of {m['sites']} site(s) patched, {m['gated']} live. Range {money(sv['cost_low'])} to "
               f"{money(sv['cost_high'])} at +/-{r.get('band_pct', 0):g}% on the manual baseline.", '#eef3ee')
    rows = [[k, 'By hand', _fmt_min(v), money(v / 60 * r.get('rate', 0))]
            for k, v in r['manual']['breakdown'].items() if v > 0]
    rows += [[k, 'With the console', _fmt_min(v), money(v / 60 * r.get('rate', 0))]
             for k, v in r['auto']['breakdown'].items() if v > 0]
    rows += [[k + ' (sites not patched)', 'With the console', _fmt_min(v), money(v / 60 * r.get('rate', 0))]
             for k, v in r['left']['breakdown'].items() if v > 0]
    rows += [['Total by hand', '', _fmt_min(r['manual']['minutes']), money(r['manual']['cost'])],
             ['Total with the console', '', _fmt_min(r['total_auto_minutes']), money(r['total_auto_cost'])]]
    doc.table(['Work', 'Who', 'Time', 'Cost'], rows, [230, 110, 70, 89])
    doc.gap(2)
    lead = r['auto'].get('lead_hours')
    doc.text((f"Fix arrival to run finished: {_fmt_min(lead * 60)}, against {r['manual']['lead_hours']:g} h assumed by "
              f"hand. " if lead is not None else '')
             + f"Rate {money(r.get('rate', 0))}/h. The manual side is the console's ROI assumptions (gear panel), "
               "not a measurement; sites the run did not patch are charged back at the manual rate.",
             size=8, color='#6a6e73')
    doc.gap(10)


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
    added, error = 0, ''
    for name, text in records:
        path = folder / name
        path.write_text(text)
        store = env('APP_VECTOR_DB_ID')
        if store and H.rag_add:
            try:
                H.rag_add(store, path)
                added += 1
            except Exception as exc:
                error = str(exc)
    out = {'records': len(records), 'where': f'{added} added to the app history store' if added else 'saved locally'}
    if error:
        out['error'] = error
    return out


# ---------------------------------------------------------------------------- Plan a fix (per app)
#
# Applications v1's "Plan a fix", for a deployed app: every Maven library in the app's BOM with open osv.dev
# advisories, and the change each would get from the sources allowed, in v1's order (scanner/remediate.py):
#   lightwell  a Lightwell build of the version in use (no version change)
#   another    a Lightwell build of a newer version on the same major line (a version change)
#   osv        the lowest upstream release that clears every advisory (a major upgrade only if allowed)
# The operator ticks the packages and can pick another allowed source per package; the result is a remediation plan
# (markdown, the shape of v1's), downloaded from the Change list of a fix's run.

PLAN_SOURCES = ('lightwell', 'another', 'osv')
SEVERITY_RANK = {'critical': 0, 'high': 1, 'moderate': 2, 'medium': 2, 'low': 3, 'unknown': 4}


def _worst(advisories: list[dict]) -> str:
    return min((a.get('severity') or 'unknown' for a in advisories), key=lambda x: SEVERITY_RANK.get(x, 9), default='unknown')


def _plan_change(group: str, artifact: str, frm: str, to: str, source: str, cves: list) -> dict:
    """A plan option as a change the playbook, commit job and pod test understand."""
    lw = source in ('lightwell', 'another')
    url = maven_url(group, artifact, to, env('NEXUS_REPOSITORY', 'lightwell-remediated') if lw
                    else env('NEXUS_CENTRAL_REPOSITORY', 'maven-central'))
    out = {'group': group, 'artifact': artifact, 'from': frm, 'to': to, 'source': 'lightwell' if lw else 'upstream',
           'plan_source': source, 'version_change': upstream(to) != upstream(frm), 'cves': list(cves),
           'old_jar': jar_name(artifact, frm), 'new_jar': jar_name(artifact, to), 'url': url}
    out['provenance_url' if lw else 'sha1_url'] = (url.rsplit('.jar', 1)[0] + '.provenance.sigstore.json') if lw else url + '.sha1'
    return out


def app_plan(app_name: str, sources: list[str] | None = None, allow_major: bool = False,
             select: list[dict] | None = None) -> dict | None:
    """The remediation plan for one app. sources: which of PLAN_SOURCES may be used (default: lightwell only, as v1).
    select: [{id, source}] the packages kept and the source chosen for each (default: every change, its first
    allowed source). None when the app is not in the BOM."""
    app = next((a for a in load_bom() if a['app'] == app_name), None)
    if app is None:
        return None
    sources = [x for x in (sources or ['lightwell']) if x in PLAN_SOURCES] or ['lightwell']
    deps = app.get('dependencies', [])
    maven = [d for d in deps if d.get('ecosystem', 'maven') == 'maven']
    other = [d for d in deps if d.get('ecosystem', 'maven') != 'maven']
    eco = {'pypi': 'pypi', 'npm': 'npm'}
    error = ''
    answers: dict = {}
    if H.osv_lookup:
        try:
            answers = H.osv_lookup([('maven', f"{d['group']}:{d['artifact']}", upstream(d['version'])) for d in maven]
                                   + [(eco.get(d.get('ecosystem'), d.get('ecosystem')), d.get('artifact') or d.get('name'),
                                       d['version']) for d in other])
        except Exception as exc:
            error = str(exc)
    else:
        error = 'osv.dev lookup not configured'
    lw = _lightwell_builds()
    rows, not_fixable = [], []
    for d in maven:
        coord, base = f"{d['group']}:{d['artifact']}", upstream(d['version'])
        advisories = answers.get(('Maven', coord, base)) or []
        build = lw.get((d['group'], d['artifact'], base))
        installed_lw = is_lightwell(d['version'])
        fixed = set((build or {}).get('cves') or []) if installed_lw else set()

        def ids(a):
            return {a.get('id'), a.get('cve')} | set(a.get('aliases') or [])
        open_ = [a for a in advisories if not (ids(a) & fixed)]
        same = build if (build and not installed_lw) else None
        if not open_ and not same:
            continue
        fixes = [a.get('suggested_fix') for a in open_ if a.get('suggested_fix')]
        fix_all = max(fixes, key=_vkey) if fixes else ''
        cands = []
        if same:
            cands.append({'source': 'lightwell', 'to': same['build'], 'cves': list(same['cves']),
                          'why': f"Lightwell build of {base}: fixes {', '.join(same['cves'])}; no version change."})
        else:
            alt = _lightwell_newer(d['group'], d['artifact'], base)
            if alt:
                cands.append({'source': 'another', 'to': alt['build'], 'cves': list(alt.get('cves') or []),
                              'why': f"Lightwell has no build of {base}; {alt['build']} is a version change. Check it covers "
                                     'your advisories.'})
        if fix_all:
            major = _major(fix_all) != _major(base)
            cands.append({'source': 'osv', 'to': fix_all, 'major': major,
                          'cves': [a.get('cve') or a.get('id') for a in open_],
                          'why': (f'Major upgrade to {fix_all}: a code change.' if major else
                                  f'The lowest upstream release that clears every osv.dev advisory.')})
        allowed = [c for c in cands if c['source'] in sources and not (c.get('major') and not allow_major)]
        row = {'id': f"{app_name}|{coord}", 'group': d['group'], 'artifact': d['artifact'], 'installed': d['version'],
               'issues': len(open_), 'worst': _worst(open_), 'unfixed': sum(1 for a in open_ if not a.get('suggested_fix')),
               'advisories': [{'id': a.get('cve') or a.get('id'), 'severity': a.get('severity', 'unknown'),
                               'fix': a.get('suggested_fix') or ''} for a in sorted(open_, key=lambda a: -(a.get('score') or 0))],
               'options': allowed, 'candidates': [c['source'] for c in cands]}
        if allowed:
            rows.append(row)
        else:
            hint = [c for c in cands if c not in allowed]
            row['why'] = ('No fixed version is listed and Lightwell has no build.' if not cands else
                          '; '.join((f"{c['to']} is a major upgrade (allow major upgrades)" if c.get('major') else
                                     f"{c['to']} needs the source {dict(lightwell='Lightwell', another='Lightwell with Another Build', osv='OSV')[c['source']]}")
                                    for c in hint) + '.')
            not_fixable.append(row)
    # The selection: which packages stay in, and the source chosen for each.
    chosen = {x.get('id'): x.get('source') for x in (select or []) if isinstance(x, dict)}
    changes, left_out = [], []
    for r in rows:
        if select is not None and r['id'] not in chosen:
            left_out.append(r)
            continue
        pick = next((o for o in r['options'] if o['source'] == chosen.get(r['id'])), r['options'][0])
        r['chosen'] = pick['source']
        r['to'], r['why'] = pick['to'], pick['why']
        r['change'] = _plan_change(r['group'], r['artifact'], r['installed'], pick['to'], pick['source'], pick['cves'])
        changes.append(r)
    not_covered = []
    for d in other:
        name = d.get('artifact') or d.get('name')
        hits = [v for k, v in answers.items() if k[1] == name and k[2] == d['version']]
        adv = hits[0] if hits else []
        not_covered.append({'name': name, 'version': d['version'], 'ecosystem': d.get('ecosystem'), 'issues': len(adv),
                            'worst': _worst(adv), 'fix': max([a.get('suggested_fix') for a in adv if a.get('suggested_fix')] or [''], key=lambda v: _vkey(v) if v else ())})
    by = {}
    for r in changes:
        by[r['chosen']] = by.get(r['chosen'], 0) + 1
    return {'ok': True, 'app': app_name, 'domain': app.get('domain', ''), 'generated_at': now_iso(),
            'sites': [{'site': s.get('site', s['host']), 'host': s['host'], 'env': s.get('env', 'prod')} for s in app.get('servers', [])],
            'sources': sources, 'allow_major': allow_major, 'osv_source': 'saved osv.dev answers' if H.demo_mode() else 'osv.dev',
            'lightwell_source': 'saved Lightwell data' if H.demo_mode() else 'the Lightwell Network API', 'error': error,
            'summary': {'vulnerable': len(rows) + len(not_fixable), 'issues': sum(r['issues'] for r in rows + not_fixable),
                        'lightwell': by.get('lightwell', 0), 'another': by.get('another', 0), 'osv': by.get('osv', 0),
                        'left_out': len(left_out), 'not_fixable': len(not_fixable), 'not_covered': len(not_covered)},
            'changes': changes, 'left_out': left_out, 'not_fixable': not_fixable, 'not_covered': not_covered}


def plan_markdown(plan: dict) -> str:
    """The plan as a document, in the shape of Applications v1's: Summary, Changes, Rollout, Repository setup, Not
    fixable from here, and a dry run of the change."""
    s, ch = plan['summary'], plan['changes']
    label = {'lightwell': 'Lightwell build', 'another': 'Lightwell with another build', 'osv': 'upstream release'}
    sites = ', '.join(f"{x['site']} ({x['host']}, {'LAB' if x['env'] == 'qa' else 'LIVE'})" for x in plan['sites']) or 'none'
    out = [f"# Remediation plan: {plan['app']}", '',
           f"{plan['domain']}. Sites: {sites}. Planned {plan['generated_at'][:10]} from the app BOM. Vulnerabilities are "
           f"from {plan['osv_source']}. Lightwell coverage is from {plan['lightwell_source']}. Sources allowed: "
           + ', '.join({'lightwell': 'Lightwell', 'another': 'Lightwell with Another Build', 'osv': 'OSV'}[x] for x in plan['sources'])
           + ('; major upgrades allowed.' if plan['allow_major'] else '; major upgrades not allowed.'), '',
           '## Summary', '',
           f"- {s['vulnerable']} vulnerable components, {s['issues']} issues",
           f"- {s['lightwell']} fixed with a Lightwell build of the version already in use",
           f"- {s['another']} fixed with a Lightwell build of another version (a version change)",
           f"- {s['osv']} need an upgrade to the version shown",
           f"- {s['not_fixable']} not fixable from here" + (f"; {s['left_out']} left out of this plan" if s['left_out'] else ''),
           f"- {s['not_covered']} non-Java libraries not covered by Lightwell", '']
    if ch:
        out += ['## Changes', '']
    for r in ch:
        c = r['change']
        out += [f"### {r['group']}:{r['artifact']} {r['installed']} -> {r['to']}", '',
                f"{r['issues']} issue{'s' if r['issues'] != 1 else ''}, worst {r['worst']}. {r['why']}"
                + (f" {r['unfixed']} advisor{'ies' if r['unfixed'] != 1 else 'y'} without a fixed version." if r['unfixed'] else ''), '',
                f"Jar swap ({label[r['chosen']]}, checked by {'cosign provenance' if c['source'] == 'lightwell' else 'Maven Central sha1'}):", '',
                '```', f"{c['old_jar']}  ->  {c['new_jar']}", f"from {c['url']}", '```', '']
    if ch:
        out += ['## Rollout', '',
                f"One playbook swaps all {len(ch)} jar{'s' if len(ch) != 1 else ''} together on each site: one backup, one restart, "
                'one health check, and every jar rolled back if anything fails. Before any site, the change is built and '
                'started in a pod (OpenShift Pipelines) and its /health checked. LAB sites go first, automatically; LIVE '
                'sites wait for approval.', '',
                '## Repository setup', '',
                'Nothing per host. Lightwell builds come from the Nexus proxy `lightwell-remediated` (packages.redhat.com, '
                'with the registry service account held in Nexus) and upstream releases from its `maven-central` proxy. Hosts '
                'never call packages.redhat.com.', '']
    if plan['left_out']:
        out += ['## Left out of this plan', '']
        out += [f"- {r['group']}:{r['artifact']} {r['installed']}: {r['issues']} issue(s), worst {r['worst']}; could go to "
                + ' or '.join(o['to'] for o in r['options']) + '.' for r in plan['left_out']] + ['']
    if plan['not_fixable'] or plan['not_covered']:
        out += ['## Not fixable from here', '']
        out += [f"- {r['group']}:{r['artifact']} {r['installed']}: {r['issues']} issue(s), worst {r['worst']}. {r['why']}"
                for r in plan['not_fixable']]
        out += [f"- {x['name']} {x['version']} ({x['ecosystem']}): {x['issues']} issue(s)"
                + (f", worst {x['worst']}" if x['issues'] else '') + '. Lightwell has no builds for this ecosystem here'
                + (f"; upstream fixes it in {x['fix']}." if x['fix'] else '.') for x in plan['not_covered']]
        out.append('')
    if ch:
        out += ['## Draft change (dry run)', '', 'Nothing has been run. This is what the App Patch v2 workflow would be '
                'sent, to review before anyone approves it.', '',
                f"Workflow: App Patch v2, one execution per site ({len(plan['sites'])}).", '',
                f"Playbook: app-v2/{plan['app']}-plan-<run>.yml, swapping:", '']
        out += [f"- {r['group']}:{r['artifact']} {r['installed']} -> {r['to']} ({label[r['chosen']]})" for r in ch]
        out += ['', 'Review the Lightwell items against your own advisory list before approving: coverage is only as '
                'complete as what Lightwell lists for each build.', '']
    return '\n'.join(out)


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
    notes, source, status = estate_reasoning(rows)
    for r in rows:
        r['priority'], r['note'] = notes.get(r['app'], ('LOW', ''))
    return {'ok': True, 'rows': rows, 'source': source, 'catalog_source': cat.get('source'), **status}


def _estate_rule(r: dict) -> tuple[str, str]:
    if not r['covered']:
        what = 'npm' if 'npm' in r['other'] else 'Python' if 'pypi' in r['other'] else 'this ecosystem'
        return 'LOW', f'No Lightwell build for {what} here; track upstream fixes.'
    if not r['fixes']:
        return 'LOW', 'No Lightwell fix for the versions this app runs.'
    cves = sum(len(f['cves']) for f in r['fixes'])
    return ('HIGH' if cves >= 2 else 'MEDIUM'), (f"{len(r['fixes'])} Lightwell fix(es), {cves} CVE(s), across "
                                                 f"{len(r['sites'])} site(s).")


_ESTATE_CACHE: dict[str, tuple[dict, str]] = {}


_ESTATE_BG: dict[str, Any] = {'thread': None, 'error': '', 'error_at': 0.0}


def _estate_failed(why: str) -> None:
    _ESTATE_BG.update(error=why, error_at=time.time())


def _estate_file() -> Path:
    return state_dir() / 'appv2-estate-reasoning.json'


def estate_reasoning(rows: list[dict]) -> tuple[dict, str, dict]:
    """(notes, source, status). Priority and note per app, never waiting on the lab: a cached answer (memory, or
    the state directory after a restart) when the facts match; otherwise the rule-based notes at once, while the app
    history and the LLM are asked in the background. status: {'pending': bool, 'lab_error': str}."""
    if H.demo_mode():
        return {r['app']: DEMO_ESTATE.get(r['app'], _estate_rule(r)) for r in rows}, 'staged', {}
    key = json.dumps([env('APP_VECTOR_DB_ID'), rows], sort_keys=True)
    if key not in _ESTATE_CACHE:
        try:
            saved = json.loads(_estate_file().read_text())
            if saved.get('key') == key:
                _ESTATE_CACHE[key] = ({k: tuple(v) for k, v in saved['notes'].items()}, saved['source'])
        except (OSError, ValueError, KeyError):
            pass
    if key in _ESTATE_CACHE:
        notes, source = _ESTATE_CACHE[key]
        return notes, source, {'pending': False, 'lab_error': ''}
    t = _ESTATE_BG.get('thread')
    # A failed attempt is reported for 30 seconds before the next try, so a lab that is down reads as down.
    recent_failure = _ESTATE_BG.get('error') and time.time() - _ESTATE_BG.get('error_at', 0) < 30
    if not (t and t.is_alive()) and not recent_failure:
        _ESTATE_BG['error'] = ''
        t = threading.Thread(target=_estate_background, args=(key, rows), daemon=True, name='appv2-estate-reasoning')
        _ESTATE_BG['thread'] = t
        t.start()
    return {r['app']: _estate_rule(r) for r in rows}, 'rules', \
        {'pending': not _ESTATE_BG.get('error'), 'lab_error': _ESTATE_BG.get('error', '')}


def _estate_background(key: str, rows: list[dict]) -> None:
    """The slow part, off the request: a 3-second check that the lab answers first, so a lab that is down is
    reported at once instead of after every search and the LLM call have timed out."""
    try:
        if H.lab_ping:
            H.lab_ping()
    except Exception as exc:
        _estate_failed(f'the lab did not answer ({str(exc)[:120]})')
        return
    try:
        out, source = _estate_reasoning_live(rows)
    except Exception as exc:
        _estate_failed(str(exc)[:160])
        return
    if source == 'rules':
        _estate_failed('no answer from the LLM; rule-based notes kept')
        return
    _ESTATE_CACHE.clear()
    _ESTATE_CACHE[key] = (out, source)
    try:
        _write_json(_estate_file(), {'key': key, 'source': source, 'notes': {k: list(v) for k, v in out.items()}})
    except OSError:
        pass


def _estate_reasoning_live(rows: list[dict]) -> tuple[dict, str]:
    store = env('APP_VECTOR_DB_ID')
    excerpts = {}
    if store and H.rag_search:
        found = _search_all(store, {r['app']: f"patch history of {r['app']}" for r in rows})
        for r in rows:
            hits = [h for h in found.get(r['app']) or [] if r['app'] in h]
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
        parsed = json.loads(re.search(r'[\[{].*[\]}]', H.llm(prompt), re.S).group(0))
        # Models vary the shape: a list of {"app": ...}, keys in another case, the note under another name.
        if isinstance(parsed, dict) and isinstance(parsed.get('apps'), list):
            parsed = parsed['apps']
        if isinstance(parsed, list):
            parsed = [{str(k).lower(): x for k, x in v.items()} for v in parsed if isinstance(v, dict)]
            parsed = {str(v.get('app', '')): v for v in parsed}
        parsed = {str(k).strip().lower(): v for k, v in parsed.items() if isinstance(v, dict)}
        for r in rows:
            v = {str(k).lower(): x for k, x in (parsed.get(r['app'].lower()) or {}).items()}
            pr = str(v.get('priority', '')).strip().upper()
            note = v.get('note') or v.get('reasoning') or v.get('impact') or ''
            if pr in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') and note:
                out[r['app']] = (pr, str(note).strip())
        return out, 'rag+llm' if excerpts else 'llm'
    except Exception:
        return out, 'rules'


# ---------------------------------------------------------------------------- run history

_DEMO_RUNS: list[dict] = []


def _summary_of(hosts: list[dict]) -> dict:
    outcomes = [h.get('outcome') for h in hosts]
    out = {k: outcomes.count(k) for k in ('patched', 'rolled_back', 'rejected', 'failed', 'skipped')}
    if 'cancelled' in outcomes:
        out['cancelled'] = outcomes.count('cancelled')
    return out


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
            (DEMO_EVENTS[2], '2026-11-03', {'inventory-service|lab': 'patched', 'inventory-service|core-dc-1': 'patched'}),
            (DEMO_EVENTS[1], '2026-10-28', {'inventory-service|lab': 'patched',
                                             'inventory-service|core-dc-1': 'rejected'})]):
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
    # The run on screen, unless it has already been recorded (a finished or cancelled run is in the history).
    recorded = {r.get('run_id') for r in out}
    if st.get('status') not in (None, 'idle', 'complete') and st.get('event') and st.get('run_id') not in recorded:
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


_MINE_CACHE: dict[str, Any] = {}


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
        # One /advisories call per library version the apps run: asked side by side, and kept for 10 minutes (the
        # estate, the osv.dev rows and the catalog all read it).
        key = json.dumps(sorted((g, a, sorted(v)) for (g, a), v in inst.items()))
        hit = _MINE_CACHE.get('v')
        if hit and hit[0] == key and time.time() - hit[1] < 600:
            found = hit[2]
        else:
            def ask(gav: tuple[str, str, str]) -> list[tuple[str, str, str, list]]:
                group, artifact, version = gav
                body = H.lightwell_get('/advisories', package_name=f'{group}:{artifact}', package_version=version, limit=100)
                builds: dict[str, set] = {}
                for adv in body.get('data') or []:
                    ids = {i for i in [adv.get('advisory_id', '')] + list(adv.get('aliases') or [])
                           if str(i).startswith('CVE-')}
                    for b in adv.get('fixed_versions') or []:
                        if is_lightwell(b) and upstream(b) == version:
                            builds.setdefault(b, set()).update(ids)
                return [(group, artifact, version, b, sorted(c)) for b, c in sorted(builds.items())]
            gavs = [(g, a, v) for (g, a), vs in sorted(inst.items()) for v in vs]
            with ThreadPoolExecutor(max_workers=min(8, len(gavs) or 1)) as pool:
                found = [x for part in pool.map(ask, gavs) for x in part]
            _MINE_CACHE['v'] = (key, time.time(), found)
        for group, artifact, version, b, cves in found:
            rows.append({'group': group, 'artifact': artifact, 'build': b, 'upstream': version,
                         'cves': cves, 'affects': affects(group, artifact, b)})
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


def source_changes(app_name: str, changes: list[dict]) -> list[dict]:
    """The pom.xml edits for Rebuild from source: this run's changes, plus every version already written back to the
    app's BOM by earlier runs. The repository's pom.xml starts from the BOM file as it was seeded; without the
    write-backs, a source build would put back versions the sites have already moved past."""
    out = [{'name': f"{c['group']}:{c['artifact']}", 'from': c['from'], 'to': c['to']} for c in changes]
    done = {x['name'] for x in out}
    try:
        base = json.loads((bom_dir() / f'{app_name}.json').read_text())
    except (OSError, ValueError):
        base = next((a for a in DEMO_BOM if a['app'] == app_name), {})
    for d in base.get('dependencies', []):
        if d.get('ecosystem', 'maven') != 'maven':
            continue
        name = f"{d['group']}:{d['artifact']}"
        cur = _BOM_UPDATES.get(f'{app_name}|{name}')
        if cur and cur != d['version'] and name not in done:
            out.append({'name': name, 'from': d['version'], 'to': cur})
        elif name in done:                   # this run's change starts from the seeded version too
            for x in out:
                if x['name'] == name and x['from'] != d['version']:
                    x['from'] = d['version']
    return out


def test_inputs(app_name: str, changes: list[dict]) -> dict:
    """What the test in a pod needs for one app: every jar it runs once the change is in (the changed ones from the
    change list, the rest from Nexus's Maven Central proxy, or Lightwell's for a build already written back), the
    /health probes and port, and the jar each changed library must then report."""
    bom = next((a for a in load_bom() if a['app'] == app_name), {})
    by = {(c['group'], c['artifact']): c for c in changes}
    lib = []
    for d in bom.get('dependencies', []):
        if d.get('ecosystem', 'maven') != 'maven':
            continue
        c = by.get((d['group'], d['artifact']))
        if c:
            lib.append({'group': d['group'], 'artifact': d['artifact'], 'version': c['to'], 'url': c['url'], 'changed': True})
        else:
            repo = env('NEXUS_REPOSITORY', 'lightwell-remediated') if is_lightwell(d['version']) \
                else env('NEXUS_CENTRAL_REPOSITORY', 'maven-central')
            lib.append({'group': d['group'], 'artifact': d['artifact'], 'version': d['version'],
                        'url': maven_url(d['group'], d['artifact'], d['version'], repo), 'changed': False})
    port = re.search(r':(\d+)', bom.get('health_url', '')) if bom.get('health_url') else None
    return {'lib_json': json.dumps(lib),
            'probes': ','.join(f"{x['artifact']}={PROBE_CLASS[x['artifact']]}" for x in lib if x['artifact'] in PROBE_CLASS),
            'port': port.group(1) if port else '8080',
            'expect_json': json.dumps({c['artifact']: c['new_jar'] for c in changes if c['artifact'] in PROBE_CLASS})}


PIPELINE_TASKS = ('fetch', 'build', 'health')
PIPELINE_TASKS_SOURCE = ('clone', 'update-pom', 'package', 'build', 'health')


def pipeline_run_name(app_name: str, run_id: str) -> str:
    """The PipelineRun the test job creates for this app and run (app_v2_test_pod.yml uses the same rule)."""
    name = re.sub(r'[^a-z0-9-]', '-', f'app-v2-{app_name}-{run_id}'.lower())[:63]
    return name.rstrip('-')


def _console_url(name: str, ns: str) -> str:
    base = env('OCP_CONSOLE_URL', '').rstrip('/')
    if not base:
        m = re.match(r'https://api\.([^:/]+)', env('APPV2_PIPELINE_API_URL', '') or env('OCP_API_URL', ''))
        base = f'https://console-openshift-console.apps.{m.group(1)}' if m else ''
    return f'{base}/k8s/ns/{ns}/tekton.dev~v1~PipelineRun/{name}' if base else ''


def pipeline_status(app_name: str) -> dict:
    """The test in a pod as it runs, for the console's task strip: the PipelineRun's tasks (fetch, build, health),
    each one's state, times and current step, and the last log lines of the step running or failed. Read only."""
    st = state()
    if H.demo_mode():
        return (st.get('pipe_sim') or {}).get(app_name) or {'state': 'pending', 'tasks': []}
    if not st.get('run_id') or not H.k8s_get:
        return {'state': 'unknown', 'tasks': [], 'error': 'no cluster access configured (APPV2_PIPELINE_TOKEN)'}
    ns = env('APPV2_PIPELINE_NAMESPACE', 'agentic-patching')
    name = pipeline_run_name(app_name, st['run_id'])
    out = {'name': name, 'console_url': _console_url(name, ns), 'tasks': []}
    try:
        pr = H.k8s_get(f'/apis/tekton.dev/v1/namespaces/{ns}/pipelineruns/{name}')
    except Exception as exc:
        if '404' in str(exc):
            order = PIPELINE_TASKS_SOURCE if st.get('test_mode') == 'source' else PIPELINE_TASKS
            return {**out, 'state': 'pending', 'tasks': [{'task': t, 'state': 'pending'} for t in order]}
        return {**out, 'state': 'unknown', 'error': str(exc)[:200]}

    def cond_state(obj: dict) -> tuple[str, str]:
        c = next((x for x in (obj.get('status') or {}).get('conditions') or [] if x.get('type') == 'Succeeded'), {})
        return ({'True': 'succeeded', 'False': 'failed'}.get(c.get('status'), 'running' if c else 'pending'),
                c.get('message', ''))
    out['state'], out['message'] = cond_state(pr)
    # The task names from the PipelineRun itself: app-v2-test (fetch, build, health) or app-v2-build (clone,
    # update-pom, package, build, health).
    names = [t.get('name') for t in ((pr.get('status') or {}).get('pipelineSpec') or {}).get('tasks') or [] if t.get('name')]
    tasks_order = names or (PIPELINE_TASKS_SOURCE if (pr.get('spec') or {}).get('pipelineRef', {}).get('name') == 'app-v2-build'
                            else PIPELINE_TASKS)
    try:
        trs = (H.k8s_get(f'/apis/tekton.dev/v1/namespaces/{ns}/taskruns?labelSelector='
                         f'tekton.dev%2FpipelineRun%3D{name}') or {}).get('items') or []
    except Exception:
        trs = []
    by = {(tr.get('metadata') or {}).get('labels', {}).get('tekton.dev/pipelineTask'): tr for tr in trs}
    for task in tasks_order:
        tr = by.get(task)
        if not tr:
            out['tasks'].append({'task': task, 'state': 'pending'})
            continue
        stt = tr.get('status') or {}
        state_, msg = cond_state(tr)
        steps = stt.get('steps') or []
        cur = next((x for x in steps if 'running' in x), None) or \
            next((x for x in steps if (x.get('terminated') or {}).get('exitCode', 0) != 0), None) or (steps[-1] if steps else None)
        row = {'task': task, 'state': state_, 'started': stt.get('startTime', ''), 'finished': stt.get('completionTime', ''),
               'step': (cur or {}).get('name', ''), 'message': msg[:200] if state_ == 'failed' else ''}
        if cur and stt.get('podName') and state_ in ('running', 'failed'):
            try:
                text = H.k8s_get(f"/api/v1/namespaces/{ns}/pods/{stt['podName']}/log?container={cur.get('container') or 'step-' + cur['name']}"
                                 f"&tailLines={3 if state_ == 'running' else 6}", text=True)
                row['log'] = [line[:200] for line in str(text).strip().splitlines()[-(3 if state_ == 'running' else 6):]]
            except Exception:
                row['log'] = []
        out['tasks'].append(row)
    return out


def _osv_rescan(app_name: str, changes: list[dict]) -> dict:
    """The pipeline's osv.dev re-query, for the demo: advisories osv.dev lists against the final jar set (Lightwell
    builds are asked by their upstream version, so this is an upper bound for them, exact for upstream jars)."""
    lib = json.loads(test_inputs(app_name, changes)['lib_json'])
    if not H.osv_lookup:
        return {'osv_open': 'unknown', 'osv_detail': ''}
    try:
        ans = H.osv_lookup([('maven', f"{x['group']}:{x['artifact']}", upstream(x['version'])) for x in lib])
    except Exception as exc:
        return {'osv_open': 'unknown', 'osv_detail': json.dumps({'error': str(exc)[:200]})}
    counts = {f"{x['artifact']} {x['version']}": len(ans.get(('Maven', f"{x['group']}:{x['artifact']}", upstream(x['version']))) or [])
              for x in lib}
    return {'osv_open': str(sum(counts.values())), 'osv_detail': json.dumps({k: v for k, v in counts.items() if v})}


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
                  'jar_url': (pb.get('changes') or [change_for_event(ev, h)])[0]['url'],
                  'provenance_url': (pb.get('changes') or [change_for_event(ev, h)])[0].get('provenance_url', ''),
                  'jars_json': json.dumps([{k: c[k] for k in ('new_jar', 'url', 'source', 'provenance_url', 'sha1_url')
                                            if k in c} for c in pb.get('changes') or [change_for_event(ev, h)]]),
                  **test_inputs(h['app'], pb.get('changes') or [change_for_event(ev, h)]),
                  'test_mode': st.get('test_mode', 'swap'),
                  'repo': next((b.get('repo', '') for b in load_bom() if b['app'] == h['app']), ''),
                  'changes_json': json.dumps(source_changes(h['app'], pb.get('changes') or [change_for_event(ev, h)])),
                  'nexus_url': env('NEXUS_URL', ''),
                  # For the Mattermost cards.
                  'site': h.get('site') or h['host'], 'domain': h.get('domain', ''),
                  'change_summary': '; '.join(f"{c['artifact']} {c['from']} -> {c['to']}"
                                              for c in pb.get('changes') or [change_for_event(ev, h)]),
                  'cves': ', '.join(sorted({x for c in pb.get('changes') or [change_for_event(ev, h)] for x in c.get('cves') or []}))}
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


STEP_OF = {NODE_COMMIT: 'commit', NODE_TEST: 'test', NODE_APPROVAL: 'approval', NODES_RUN[0]: 'sync', NODES_RUN[1]: 'sync'}
AO_STATE = {'completed': 'done', 'succeeded': 'done', 'failed': 'failed', 'running': 'active',
            'waiting': 'waiting', 'pending': 'waiting', 'skipped': 'skipped', 'cancelled': 'failed'}


def _follow_live(h: dict) -> None:
    """Poll one execution until it settles or stops at the approval gate."""
    key = h['key']
    exec_id = h.get('execution_id') or next((x['execution_id'] for x in state()['hosts'] if x['key'] == key), '')
    deadline = time.time() + int(env('AO_POLL_TIMEOUT', '1800'))   # the test in a pod adds minutes
    said: set[str] = set()                 # each hop traced once, for the architecture diagram

    def hop(name: str, src: str, dst: str, msg: str) -> None:
        if name not in said:
            said.add(name)
            _trace(src, dst, msg)

    while exec_id and time.time() < deadline:
        time.sleep(3)
        if state().get('cancelling') or next((x for x in state().get('hosts') or [] if x['key'] == key), {}).get('outcome') == 'cancelled':
            return                           # Cancel run owns this site now
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
        # The test job finishes either way; its test_outcome says how the test went (failed -> the test_failed card).
        if _out(acts.get(NODE_TEST)).get('test_outcome') == 'failed':
            steps['test'] = 'failed'
        rb_node = next((acts[n] for n in NODES_ROLLBACK if n in acts and acts[n].get('started_at')), None)
        if rb_node:
            steps['rollback'] = AO_STATE.get(str(rb_node.get('status', '')).lower(), 'active')
        nt = [acts[n] for n in NODES_NOTIFY if n in acts and acts[n].get('started_at')]
        if nt:
            steps['notify'] = AO_STATE.get(str(nt[0].get('status', '')).lower(), 'active')
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
        if steps.get('test') in ('active', 'done', 'failed'):
            hop('test', 'ao', 'aap', f'{_label(h)}: test the change in a pod')
            hop('pipelines', 'aap', 'pipelines', f'{_label(h)}: build, start, check /health (OpenShift Pipelines)')
        if steps.get('sync') in ('active', 'done'):
            hop('sync', 'ao', 'aap', f'{_label(h)}: sync and run')
            hop('servers', 'aap', 'servers', f'{_label(h)}: swap the jar, restart {h.get("service", "")}')
        if steps.get('rollback') in ('active', 'done', 'failed'):
            hop('rollback', 'ao', 'aap', f'{_label(h)}: rollback route: restore the backup')
        if steps.get('notify') in ('active', 'done'):
            hop('notify', 'aap', 'mattermost', f'{_label(h)}: Mattermost card')
        commit = _out(acts.get(NODE_COMMIT))
        test = _out(acts.get(NODE_TEST))
        extra = {}
        if test.get('pipelinerun'):
            # AO hands JSON-looking artifacts back already parsed; kept as JSON text here, as the demo stores them.
            def as_text(v):
                return v if isinstance(v, str) else json.dumps(v)
            extra['test'] = {'passed': test.get('test_passed') in (True, 'true', 'True'), 'image': test.get('test_image', ''),
                             'health': as_text(test.get('test_health', '')), 'osv_open': str(test.get('osv_open', '')),
                             'osv_detail': as_text(test.get('osv_detail', '')), 'pipelinerun': test.get('pipelinerun', ''),
                             'sbom_url': test.get('sbom_url', ''), 'reason': test.get('test_reason', ''),
                             'mode': test.get('test_mode', 'swap'), 'bundle_url': test.get('bundle_url', ''),
                             'branch_url': test.get('branch_url', '')}
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
            elif rb_node:
                rb = _out(rb_node)
                why = f"{verify.get('failed_step') or 'the run failed'}: {verify.get('failed_reason') or ''}".strip(': ')
                if steps.get('rollback') == 'done' and rb.get('rolled_back') in (True, 'true', 'True'):
                    outcome, detail = 'rolled_back', (f"{why}. Rolled back by the workflow (AAP: App Patch v2 - Rollback): "
                                                      f"{rb.get('restored') or 'the original jars'} back, healthy.")
                else:
                    outcome, detail = 'failed', (f"{why}. The rollback route did not finish: check the site and "
                                                 f"restore its backup by hand. {str(ex.get('error_details') or '')[:200]}")
            elif verify.get('rolled_back') in (True, 'true', 'True'):     # a playbook from before the rollback route
                outcome, detail = 'rolled_back', 'health check failed after the swap; the old jars were restored'
            elif steps.get('test') == 'failed':
                t = extra.get('test') or {}
                outcome, detail = 'failed', ('The test in a pod did not pass; no site was touched. '
                                             + (t.get('reason') or str(ex.get('error_details') or ''))[:300])
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
