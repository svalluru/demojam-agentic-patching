#!/usr/bin/env python3
"""Agentic CVE patching — common code, Supervisor, and agents 1 and 2.

Implements the left column of multi-agent/architecture.jpg:

    Common code (NOT an agent)     C1 get CVE list · C2 resolve affected hosts
            |  for each CVE
            v
    Supervisor Agent               owns control flow + per-CVE state
            |
            +--> 1 cve-gather-info-agent   RAG · scheduler · risk · patch plan
            +--> 2 Patching Agent          one AO workflow run per host

Agents 3 (Communication) and 4 (Results) are not implemented; the Supervisor
stops after dispatch and says so.

Design: fallbacks are allowed but never silent. Every external call either
succeeds or raises BackendUnavailable naming the service and the fix; the
caller may then substitute a stored default from fallbacks.py, but the
substitution is recorded in DEGRADED and travels with the report, because the
patch plan is what a human approves against. That is demo mode. MODE=live
uses real endpoints only and raises rather than substituting anything,
because a plan built partly from stored defaults is not something to approve
a production change against.

Usage
-----
    ./agentic-patching.py list                     # C1 — CVE list
    ./agentic-patching.py detail CVE-2026-12405    # C1+C2 — detail + hosts
    ./agentic-patching.py run CVE-2026-12405       # Supervisor -> Info agent
    ./agentic-patching.py run CVE-2026-12405 --host pay-app-07 --json
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent


def load_dotenv(path: Path) -> None:
    """Load KEY=value pairs. Real environment variables win."""
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_dotenv(ROOT / '.env')


def env(key: str, default: str = '') -> str:
    return os.environ.get(key, default).strip()


def env_bool(key: str, default: bool) -> bool:
    raw = env(key)
    if not raw:
        return default
    return raw.lower() not in {'0', 'false', 'no'}


RHSSO_TOKEN_URL = ('https://sso.redhat.com/auth/realms/redhat-external'
                   '/protocol/openid-connect/token')
INSIGHTS_API = env('INSIGHTS_REST_BASE_URL', 'https://console.redhat.com/api')
VULN_API = f'{INSIGHTS_API.rstrip("/")}/vulnerability/v1'

# Some machines lack the CA chain for sso.redhat.com in Python's trust store.
INSIGHTS_VERIFY_TLS = env_bool('INSIGHTS_VERIFY_TLS', True)

RISK_URL = env('RISK_URL')
RISK_VERIFY_TLS = env_bool('RISK_VERIFY_TLS', True)
REVIEW_THRESHOLD = float(env('REVIEW_THRESHOLD', '30'))

LLAMA_URL = env('LLAMA_STACK_URL')
VECTOR_DB_ID = env('VECTOR_DB_ID')
LLM_MODEL = env('DEFAULT_LLM_MODEL', 'vllm-inference/llama-scout-17b')

MAINTENANCE_WINDOW = env('MAINTENANCE_WINDOW')
DEFAULT_WINDOW = 'Sat 02:00-06:00 UTC'

HTTP_TIMEOUT = int(env('HTTP_TIMEOUT', '120'))

# Per-service budgets, deliberately far below HTTP_TIMEOUT. A stopped cluster
# leaves the Route resolving but nothing listening, so the socket hangs until
# it times out rather than refusing it outright — at the 120s default a
# two-host plan spent over a minute waiting on services already known down.
INSIGHTS_TIMEOUT = int(env('INSIGHTS_TIMEOUT', '15'))

# One page of affected systems. Anything past this is not assessed, and the
# plan says so rather than quietly planning for a subset.
AFFECTED_PAGE = int(env('AFFECTED_PAGE', '100'))
RISK_TIMEOUT = int(env('RISK_TIMEOUT', '8'))
RAG_TIMEOUT = int(env('RAG_TIMEOUT', '20'))     # live RAG does LLM summarisation
AO_TIMEOUT = int(env('AO_TIMEOUT', '10'))

# How many history lookups are in flight at once. Every review host is still
# looked up; this caps concurrency, not coverage. 8 keeps a 60-host CVE inside
# the timeout without burying a single-replica model server.
RAG_WORKERS = max(1, int(env('RAG_WORKERS', '8') or 8))

# Reachability budget, distinct from the read budgets above.
CONNECT_TIMEOUT = float(env('CONNECT_TIMEOUT', '3'))

# Offline mode answers instantly, which renders as "complete in 0s" and reads
# as a broken page rather than a fast one. A small pause per agent step makes
# the elapsed figure and the spinner behave the way the live flow does.
# DEMO_LATENCY=0 removes it.
DEMO_LATENCY = float(env('DEMO_LATENCY', '0.35'))


def demo_pause(factor: float = 1.0) -> None:
    if offline() and DEMO_LATENCY > 0:
        time.sleep(DEMO_LATENCY * factor)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


# --------------------------------------------------------------------------
# errors + http
# --------------------------------------------------------------------------

import communication
import fallbacks
import results as results_mod

# Degradations recorded during the current operation. The Supervisor clears
# this per run and copies it into the report, so a fabricated value can never
# reach an operator without a label attached.
DEGRADED: list[dict[str, str]] = []

# Guards DEGRADED and _DOWN. History lookups run on a thread pool, so when one
# backend is down every worker reaches degrade() with the same entry at the
# same moment — and "append unless already present" is a check-then-act race.
# Without this the page shows the same degraded step N times.
_DEGRADED_LOCK = threading.Lock()


# Services proven unreachable recently. Without this the cost of a dead
# backend scales with host count: the RAG store is queried once per review
# host and AO once per host, so an 8-host CVE paid eight full timeouts for one
# service that had already answered the first probe by hanging.
#
# service -> (error, retry_after). The TTL matters: the Patch runs page polls
# every few seconds, and a breaker with no expiry would keep reporting AO down
# long after it came back.
_DOWN: dict[str, tuple['BackendUnavailable', float]] = {}
CIRCUIT_TTL = int(env('CIRCUIT_TTL', '30'))


def degraded_reset() -> None:
    DEGRADED.clear()
    _DOWN.clear()


# The only mode switch. Everything the console used to expose separately —
# whether to touch the network, whether to fall back, whether to simulate a
# patch, whether to label substitutions — follows from this one answer,
# because the two useful configurations are the two ends:
#
#   demo   staged data throughout, no endpoint is contacted. Someone can show
#          the whole flow without standing up Insights, the risk model, the
#          RAG store or Ansible Orchestrator.
#   live   real endpoints only. No step falls back; an unreachable service
#          fails the run and says which one. A patch plan built partly from
#          stored defaults is not something to approve a production change
#          against, so the middle ground is gone deliberately.
def demo_mode() -> bool:
    return env('MODE', 'demo').strip().lower() != 'live'


def offline() -> bool:
    """Demo mode opens no sockets at all — see circuit()."""
    return demo_mode()


def label_sources() -> bool:
    """Whether the console marks substituted values on the page itself.

    Off by default, and that is a demo decision rather than an engineering
    one. A banner reading "running on fallback data" is exactly what a room
    watching a live demo fixates on, so the console is asked to present one
    face: every value renders the same whether it was measured or stood in
    for. Nothing is suppressed, only moved — /api/mode, /api/state, /api/roi
    and /api/runs carry `degraded`, `source`, `simulated` and `illustrative`
    unchanged, every substitution prints to the backend log through degrade()
    below, and the agent trace in the left-hand panel names the service that
    did not answer while the run is still on screen.

    Live mode never substitutes anything — it raises instead — so there is
    nothing there to label, and demo mode says so once in the banner rather
    than on every row. LABEL_SOURCES=1 still forces the marks back on for
    anyone who wants them while demoing.
    """
    return env('LABEL_SOURCES').lower() in {'1', 'true', 'yes'}


def unlabelled(text: str, neutral: str) -> str:
    """Swap operator-facing prose that names a failure for a neutral wording.

    The fallbacks write sentences meant to be read on the page — "the RAG
    store could not be reached", "Insights was unreachable, so this is
    placeholder text". Those are source labels in prose form, and they are
    the one kind the frontend's structural gating cannot catch, because by
    the time the page has them they are indistinguishable from content.

    Only the sentence changes. The `degraded`, `source` and `simulated`
    fields sitting beside it in the same payload are untouched, so /api/state
    and /api/runs still answer the question honestly, and the trace and the
    backend log still name the service. What goes is the wording that would
    announce it to a room reading over the operator's shoulder.
    """
    return text if label_sources() else neutral


def circuit(service: str) -> None:
    """Short-circuit a service known down, until its breaker expires.

    Re-raises the original failure so the caller's degrade() path and the
    operator-facing reason read the same whether it was the first host or
    the eighth.
    """
    # Every live call passes through here, so offline mode needs no other
    # hook. Raising before the preflight keeps it instant — pointing the URLs
    # at a dead host would still cost CONNECT_TIMEOUT per service.
    if offline():
        raise BackendUnavailable(service, 'demo mode',
                                 'set MODE=live to use the real service')
    with _DEGRADED_LOCK:
        entry = _DOWN.get(service)
        if not entry:
            return
        exc, retry_after = entry
        if time.time() >= retry_after:
            _DOWN.pop(service, None)   # let the next call probe it again
            return
    raise exc


def trip(service: str, exc: 'BackendUnavailable') -> None:
    with _DEGRADED_LOCK:
        _DOWN[service] = (exc, time.time() + CIRCUIT_TTL)


def degrade(step: str, service: str, cause: Any, fix: str) -> None:
    """Record that a step fell back. Raises instead when STRICT is set."""
    if fallbacks.strict():
        raise BackendUnavailable(service, cause, fix)
    entry = {'step': step, 'service': service,
             'reason': str(cause)[:300], 'fix': fix}
    with _DEGRADED_LOCK:
        if entry in DEGRADED:
            return
        DEGRADED.append(entry)
    # To the log every time, not only when the page is going to show it.
    # With LABEL_SOURCES off the page says nothing, so this line and the
    # agent trace are the whole record of what was substituted — and a
    # record that depends on a display setting is not a record.
    print(f'  DEGRADED {step}: {service} unavailable: '
          f'{str(cause)[:200]}\n           FIX: {fix}', file=sys.stderr)


class BackendUnavailable(RuntimeError):
    """A required external service could not be reached or refused the call.

    Carries the service name and a concrete fix so the operator does not have
    to read a traceback to find out what is missing.
    """

    def __init__(self, service: str, cause: Any, fix: str):
        self.service, self.cause, self.fix = service, cause, fix
        super().__init__(f'{service} unavailable: {cause}\n  FIX: {fix}')


def _ctx(verify: bool) -> ssl.SSLContext:
    c = ssl.create_default_context()
    if not verify:
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
    return c


def preflight(url: str, timeout: float | None = None) -> None:
    """Fail fast if nothing is listening, before spending the read budget.

    A stopped pod leaves its Route resolving with nothing behind it, so the
    socket hangs for the full timeout instead of refusing. The read budgets
    have to stay generous — live RAG summarisation genuinely takes ~20s — so
    the two cases are separated: reachability gets seconds, answering gets
    the full allowance.
    """
    # "Demo mode opens no sockets at all" is enforced here as well as in
    # circuit(), because circuit() is a thing each caller has to remember and
    # this is the one place every outbound request passes through. It was not
    # remembered: ao_login() returned a cached token before reaching its
    # circuit() call, so after a live session the operator could switch to
    # demo and watch dispatch block on a real TLS handshake to Ansible
    # Orchestrator. A guard that depends on eight call sites agreeing is not
    # a guarantee; this one cannot be bypassed by forgetting it.
    if offline():
        host = urllib.parse.urlparse(url).hostname or url
        raise BackendUnavailable(host, 'demo mode',
                                 'set MODE=live to use the real service')
    # Resolved per call, not captured as a default argument: the settings
    # panel rebinds CONNECT_TIMEOUT, and a default binds once at import.
    if timeout is None:
        timeout = CONNECT_TIMEOUT
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if not host:
        return
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    try:
        socket.create_connection((host, port), timeout=timeout).close()
    except OSError as exc:
        raise urllib.error.URLError(
            f'cannot connect to {host}:{port} within {timeout:g}s ({exc})') from exc


def http_json(url: str, *, method: str = 'GET', body: Any = None,
              headers: dict[str, str] | None = None, verify: bool = True,
              timeout: int | None = None) -> Any:
    preflight(url)
    req = urllib.request.Request(
        url, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={**({'Content-Type': 'application/json'} if body is not None else {}),
                 **(headers or {})},
    )
    with urllib.request.urlopen(req, timeout=timeout or HTTP_TIMEOUT,
                                context=_ctx(verify)) as r:
        raw = r.read().decode()
        return json.loads(raw) if raw.strip() else None


_token: dict[str, Any] = {}


def insights_token() -> str:
    """Client-credentials token for console.redhat.com, cached until expiry."""
    # Checked before the cache for the same reason as ao_login(): a cached
    # token must not be a way past the demo-mode guard.
    #
    # C1 and C2 each need a token, so without this a dead SSO is paid for
    # twice before the console has rendered anything.
    circuit('Red Hat SSO')
    if _token.get('value') and _token['expires'] > time.time() + 30:
        return _token['value']
    cid, secret = env('LIGHTSPEED_CLIENT_ID'), env('LIGHTSPEED_CLIENT_SECRET')
    if not cid or not secret:
        raise BackendUnavailable(
            'Insights', 'LIGHTSPEED_CLIENT_ID / LIGHTSPEED_CLIENT_SECRET not set',
            'add both to .env (Lightspeed service account)')
    data = urllib.parse.urlencode({
        'grant_type': 'client_credentials', 'client_id': cid,
        'client_secret': secret, 'scope': 'api.console',
    }).encode()
    try:
        preflight(RHSSO_TOKEN_URL)
        req = urllib.request.Request(
            RHSSO_TOKEN_URL, data=data, method='POST',
            headers={'Content-Type': 'application/x-www-form-urlencoded'})
        with urllib.request.urlopen(req, timeout=INSIGHTS_TIMEOUT,
                                    context=_ctx(INSIGHTS_VERIFY_TLS)) as r:
            payload = json.loads(r.read().decode())
    except Exception as exc:
        fix = ('set INSIGHTS_VERIFY_TLS=false — this machine cannot verify the '
               'sso.redhat.com chain' if 'CERTIFICATE_VERIFY_FAILED' in str(exc)
               else 'check LIGHTSPEED_CLIENT_ID / _SECRET and network egress')
        down = BackendUnavailable('Red Hat SSO', exc, fix)
        trip('Red Hat SSO', down)
        raise down from exc

    _token['value'] = payload['access_token']
    _token['expires'] = time.time() + int(payload.get('expires_in', 300))
    return _token['value']


def insights_get(path: str) -> Any:
    try:
        circuit('Insights')
        return http_json(f'{VULN_API}{path}',
                         headers={'Authorization': f'Bearer {insights_token()}'},
                         verify=INSIGHTS_VERIFY_TLS, timeout=INSIGHTS_TIMEOUT)
    except BackendUnavailable:
        raise
    except Exception as exc:
        down = BackendUnavailable(
            'Insights', exc, f'GET {path} failed — check credentials and egress')
        trip('Insights', down)
        raise down from exc


def inventory_get(path: str) -> Any:
    """Insights inventory, which is a sibling service to vulnerability.

    Separate from insights_get because VULN_API is baked into that one, and
    resolving a hostname to a uuid is the one thing vulnerability cannot do.
    """
    try:
        circuit('Insights')
        return http_json(f'{INSIGHTS_API.rstrip("/")}/inventory/v1{path}',
                         headers={'Authorization': f'Bearer {insights_token()}'},
                         verify=INSIGHTS_VERIFY_TLS, timeout=INSIGHTS_TIMEOUT)
    except BackendUnavailable:
        raise
    except Exception as exc:
        down = BackendUnavailable(
            'Insights', exc, f'GET inventory{path} failed — check credentials and egress')
        trip('Insights', down)
        raise down from exc


# ==========================================================================
# COMMON CODE  (C1 / C2)  — not an agent
#
# The console UI calls these directly to populate its CVE table, before any
# Supervisor exists. There is no decision-making here.
# ==========================================================================

def fetch_cve_list(limit: int = 20, offset: int = 0) -> dict[str, Any]:
    """C1 — a page of CVEs affecting registered systems."""
    params = urllib.parse.urlencode({
        'limit': limit, 'offset': offset, 'sort': '-public_date',
        'affecting_host_type': 'rpmdnf', 'advisory_available': 'true',
    })
    try:
        payload = insights_get(f'/vulnerabilities/cves?{params}')
    except BackendUnavailable as exc:
        degrade('C1 cve_list', exc.service, exc.cause, exc.fix)
        page = fallbacks.CVE_LIST[offset:offset + limit]
        return {'cves': [dict(c) for c in page], 'count': len(page),
                'limit': limit, 'offset': offset,
                'total_items': len(fallbacks.CVE_LIST),
                'has_more': offset + len(page) < len(fallbacks.CVE_LIST),
                'degraded': True, 'source': 'fallback'}
    rows = payload.get('data', []) if isinstance(payload, dict) else []
    meta = payload.get('meta', {}) if isinstance(payload, dict) else {}
    cves = []
    for item in rows:
        a = item.get('attributes', {})
        cvss = a.get('cvss3_score') or a.get('cvss2_score')
        cves.append({
            'id': item.get('id'),
            'cvss': float(cvss) if cvss is not None else None,
            'impact': a.get('impact', ''),
            'systems_affected': a.get('systems_affected'),
            'public_date': a.get('public_date', ''),
            'known_exploit': a.get('known_exploit', False),
            'description': a.get('description', ''),
        })
    return {'cves': cves, 'count': len(cves), 'limit': limit, 'offset': offset,
            'total_items': meta.get('total_items'),
            'has_more': offset + len(cves) < (meta.get('total_items') or 0)}


def _detail_host_first(cve_id: str, host_filter: str) -> dict[str, Any]:
    """C2 for a single named host, asked host-first instead of CVE-first.

    The CVE-first route cannot answer "is my host affected" in a large estate.
    /cves/{id}/affected_systems returns one page of AFFECTED_PAGE out of tens
    of thousands — for CVE-2026-73078 the host was genuinely affected and sat
    nowhere in the first hundred of ~12,000. Filtering that page then finds
    nothing, which used to mean "plan for all hundred" and now means "refuse":
    safe, but a filter that can never match is no use either.

    Asked this way both problems go away, and so does the slow endpoint: the
    per-system record carries cvss, impact, description and first_reported,
    and /cves/{id} — which takes ~30s cold and often 504s in a 98k-host org —
    is never called at all.
    """
    found = inventory_get(f'/hosts?hostname_or_id={urllib.parse.quote(host_filter)}')
    rows = (found or {}).get('results') or []
    exact = [r for r in rows
             if (r.get('display_name') or '') == host_filter
             or (r.get('display_name') or '').startswith(host_filter + '.')]
    chosen = (exact or rows)
    if not chosen:
        raise BackendUnavailable(
            'Host filter', f'HOSTS_FILTER={host_filter!r} is not registered in '
            f'this Insights organisation',
            'check insights-client --register ran on it, and that the console '
            'credentials point at the same org as the host')
    uuid = chosen[0].get('id')
    name = chosen[0].get('display_name') or host_filter

    # ?filter= is the only accepted spelling here; ?cve= and ?cve_id= are
    # rejected as "not in spec", which reads like a server fault.
    hit = insights_get(f'/systems/{uuid}/cves'
                       f'?limit=1&filter={urllib.parse.quote(cve_id)}')
    data = (hit or {}).get('data') or []
    if not data:
        raise BackendUnavailable(
            'Host filter', f'Insights does not report {name} as affected by {cve_id}',
            'the host may already be patched, or the CVE may not apply to its '
            'package set — pick a CVE from that host\'s own vulnerability list')

    a = (data[0].get('attributes') or {})
    cvss = a.get('cvss3_score') or a.get('cvss2_score')
    return {
        'cve_id': cve_id,
        'cvss': float(cvss) if cvss is not None else 0.0,
        'description': a.get('description', ''),
        'impact': a.get('impact', ''),
        'hosts': [{'host': name, 'system_uuid': uuid,
                   'age_days': _age_days(a.get('first_reported'))}],
        'count': 1,
        # Deliberately absent: this route never asks how many systems the CVE
        # affects org-wide, and guessing 1 would put a wrong number on the
        # plan. gather() only notes truncation when it has a real total.
        'total_affected': None,
    }


def fetch_cve_detail(cve_id: str, host_filter: str = '',
                     host_limit: int = 0) -> dict[str, Any]:
    """C1 + C2 — CVE metadata and the hosts it affects.

    host_filter / host_limit narrow the host set for demos and local testing.
    """
    # With a filter set, live mode asks about that host directly. Demo mode
    # keeps the list-then-filter path because its hosts are staged, not
    # registered anywhere an inventory lookup could find them.
    if host_filter and not offline():
        return _detail_host_first(cve_id, host_filter)
    try:
        detail = insights_get(f'/cves/{cve_id}')
        # advisory_available=true, to match the filter the CVE list counts
        # with. Without it this endpoint returns every affected system while
        # the list column shows only those with an advisory — 463 against 2
        # for CVE-2026-88812 — so the console offered to patch hundreds of
        # hosts it had just told the operator were two. It is also the right
        # set on its own terms: a host with no advisory has nothing to apply.
        # affecting_host_type is NOT accepted here; it 400s.
        systems = insights_get(f'/cves/{cve_id}/affected_systems'
                               f'?limit={AFFECTED_PAGE}&offset=0'
                               f'&advisory_available=true')
    except BackendUnavailable as exc:
        degrade('C2 cve_detail', exc.service, exc.cause, exc.fix)
        fb = fallbacks.cve_detail(cve_id)
        before = len(fb['hosts'])
        fb['hosts'] = _narrow(fb['hosts'], host_filter, host_limit)
        fb['count'] = len(fb['hosts'])
        fb['limited_from'] = (before if host_limit and len(fb['hosts']) < before
                              else None)
        # Matched against the placeholder rather than applied to whatever is
        # there: a CVE in CVE_LIST carries its real advisory text, and that
        # must survive. Only the stand-in gets swapped, because it names
        # Insights as unreachable — a source label in a content field.
        if fb.get('description') == fallbacks.CVE_DETAIL_DEFAULT['description']:
            fb['description'] = unlabelled(
                fb['description'], 'No advisory text on record for this CVE.')
        fb.update(degraded=True, source='fallback')
        return fb

    a = (detail.get('data') or {}).get('attributes', {}) if isinstance(detail, dict) else {}
    cvss = a.get('cvss3_score') or a.get('cvss2_score')
    rows = systems.get('data', []) if isinstance(systems, dict) else []

    hosts = []
    for s in rows:
        sa = s.get('attributes', {})
        hosts.append({
            'host': sa.get('display_name') or s.get('id'),
            'system_uuid': s.get('id'),
            'age_days': _age_days(sa.get('first_reported')),
        })

    before = len(hosts)
    hosts = _narrow(hosts, host_filter, host_limit)

    return {
        'cve_id': cve_id,
        'cvss': float(cvss) if cvss is not None else 0.0,
        'description': a.get('description', ''),
        'impact': a.get('impact', ''),
        'hosts': hosts,
        'count': len(hosts),
        'total_affected': (systems.get('meta') or {}).get('total_items'),
        # Set only when HOSTS_LIMIT actually dropped hosts. The cap is a
        # safety net, and a safety net that catches something silently is
        # indistinguishable from one that was never needed.
        'limited_from': before if host_limit and len(hosts) < before else None,
    }


def _narrow(hosts: list[dict], host_filter: str, host_limit: int) -> list[dict]:
    """Shared by the live and fallback paths so both honour --host/--limit.

    A filter that matches nothing raises. It used to keep every host and print
    a note to stderr, on the reasoning that showing something beats showing
    nothing — which is right for a display and wrong for a work queue. The
    plan this returns is what gets dispatched.

    What that cost: HOSTS_FILTER was set to a single lab host, the console was
    pointed at an estate of ~98,000 systems, and the CVE affected 11,913 of
    them. The host was not in the page that came back, the filter matched
    nothing, and the console planned to patch 100 unrelated production
    machines. Nothing was touched — the risk score sent them all to the
    approval gate — but the gate is a governance control that happened to be
    in the way, not a safety net, and it was the only thing in the way.

    "I asked for one host and got a hundred" must never be a note on stderr.
    """
    if host_filter:
        matched = [h for h in hosts if host_filter in (h.get('host') or '')]
        if not matched:
            # Naming what was there turns two different mistakes into one
            # readable message: a live filter left set while demo mode serves
            # staged hosts, and a live CVE whose affected list simply does not
            # include this host. Both look identical without the sample.
            sample = ', '.join(str(h.get('host')) for h in hosts[:3])
            more = f' (+{len(hosts) - 3} more)' if len(hosts) > 3 else ''
            raise BackendUnavailable(
                'Host filter',
                f'HOSTS_FILTER={host_filter!r} matched none of the '
                f'{len(hosts)} host(s) returned for this CVE — '
                f'got: {sample}{more}',
                'if those are staged demo hosts, clear HOSTS_FILTER or switch '
                'to live; otherwise the host is not affected by this CVE or '
                'sorts beyond the first page — pick a CVE from that host\'s '
                'own list, or raise AFFECTED_PAGE')
        hosts = matched
    if host_limit > 0:
        hosts = hosts[:host_limit]
    return hosts


def _age_days(first_reported: str | None) -> int:
    if not first_reported:
        return 90
    try:
        first = datetime.fromisoformat(first_reported.replace('Z', '+00:00'))
        return max(1, (datetime.now(timezone.utc) - first).days)
    except Exception:
        return 90


# ==========================================================================
# AGENT 1 — cve-gather-info-agent        ENRICH · ASSESS
#
#   1  RAG lookup — patch history per host     (Milvus via Llama Stack)
#   2  Scheduler — maintenance window
#   3  Assess risk score                       (XGBoost on OpenShift)
#   4  Produce the patch plan
#
# Returns cve-info to the Supervisor. Will also serve diagnose() once the
# self-healing loop exists.
# ==========================================================================

@dataclass
class HostAssessment:
    host: str
    system_uuid: str | None
    age_days: int
    risk_score: float
    decision: str                       # 'review' | 'ok'
    reason: str
    history: str = ''                   # RAG summary, review hosts only


@dataclass
class PatchPlan:
    cve_id: str
    cvss: float
    hosts_total: int
    hosts_review: int
    hosts_auto: int
    maintenance_window: str
    risk_source: str
    # 'rag', 'fallback', or 'skipped' when no host needed review and so no
    # lookup was made. The third case is why this is reported rather than
    # inferred from the degraded list: a step that was never called leaves no
    # degraded entry, and reading that absence as success would have the
    # console claim a service answered when it was never asked.
    history_source: str
    # The gate each score was actually compared against. Which of the two
    # thresholds applied depends on risk_source, so reporting it is the only
    # way the console can show why a host landed where it did.
    threshold: float
    verdict: str
    notes: list[str] = field(default_factory=list)
    # Every step that fell back, with the service and the fix. Carried into
    # the report so an operator approves with the gaps in front of them.
    degraded: list[dict] = field(default_factory=list)


class InfoAgent:
    """Step 1-4 of the architecture. Stateless; the Supervisor holds state."""

    name = 'cve-gather-info-agent'

    def __init__(self, trace=None):
        self._trace = trace or (lambda *a, **k: None)

    # -- step 3 ------------------------------------------------------------

    def risk_scores(self, cvss: float, hosts: list[dict]) -> tuple[list[float], str]:
        """Returns (scores, source). source is 'model' or 'heuristic'."""
        try:
            return self._risk_live(cvss, hosts), 'model'
        except BackendUnavailable as exc:
            degrade('3 risk_score', exc.service, exc.cause, exc.fix)
            demo_pause()
            self._trace('info', 'risk-model',
                        f'unreachable — heuristic for {len(hosts)} host(s)')
            return ([fallbacks.heuristic_risk(cvss, h['age_days'], len(hosts))
                     for h in hosts], 'heuristic')

    def _risk_live(self, cvss: float, hosts: list[dict]) -> list[float]:
        """One batched call, not one per host.

        The model accepts a list of instances. Calling it per host turned a
        59-host CVE into 59 sequential round trips (~15 minutes).
        """
        circuit('risk model')
        if not RISK_URL:
            raise BackendUnavailable(
                'risk model', 'RISK_URL not set',
                'set RISK_URL to the risk-score Route '
                '(and RISK_VERIFY_TLS=false for a cluster cert)')
        payload = {'instances': [
            {'cvss': cvss, 'age_days': h['age_days'],
             'affected_hosts': len(hosts), 'type': 'security'}
            for h in hosts
        ]}
        self._trace('info', 'risk-model', f'scoring {len(hosts)} host(s) in one call')
        try:
            result = http_json(RISK_URL, method='POST', body=payload,
                               verify=RISK_VERIFY_TLS, timeout=RISK_TIMEOUT)
        except Exception as exc:
            down = BackendUnavailable(
                'risk model', exc,
                'check RISK_URL is reachable; set RISK_VERIFY_TLS=false for '
                'sandbox/self-signed cluster certs')
            trip('risk model', down)
            raise down from exc

        for key in ('predictions', 'outputs', 'data'):
            values = (result or {}).get(key)
            if values:
                scores = [float(v['score'] if isinstance(v, dict) and 'score' in v else v)
                          for v in values]
                if len(scores) != len(hosts):
                    raise BackendUnavailable(
                        'risk model',
                        f'returned {len(scores)} scores for {len(hosts)} hosts',
                        'the model should return one prediction per instance')
                return scores
        raise BackendUnavailable('risk model',
                                 f'unexpected response: {json.dumps(result)[:200]}',
                                 'expected a predictions/outputs/data array')

    # -- step 2 ------------------------------------------------------------

    def maintenance_window(self) -> tuple[str, str]:
        """No scheduler service exists yet, so this is configuration.

        Returns (window, source). Never 'now' — an unscheduled production
        patch is exactly what the window is there to prevent.
        """
        if MAINTENANCE_WINDOW:
            return MAINTENANCE_WINDOW, 'config'
        return DEFAULT_WINDOW, 'default'

    # -- step 1 ------------------------------------------------------------

    def history(self, host: str) -> tuple[str, str]:
        """Returns (summary, source). source is 'rag' or 'fallback'."""
        try:
            return self._history_live(host), 'rag'
        except BackendUnavailable as exc:
            degrade('1 rag_history', exc.service, exc.cause, exc.fix)
            demo_pause(0.5)      # per host, so keep it shorter than the rest
            # The trace is where this lands now that the page may not show it.
            self._trace('info', 'rag', f'unreachable — stored history for {host}')
            # A known host gets stored prose that reads like real history. An
            # unknown one gets NO_HISTORY, which says the RAG store could not
            # be reached — true, and a source label in a content field.
            text = fallbacks.history(host)
            if text == fallbacks.NO_HISTORY:
                text = unlabelled(text, 'No patch history on record for this host.')
            return text, 'fallback'

    def _history_live(self, host: str) -> str:
        """RAG lookup for one host, summarised by the LLM."""
        circuit('Llama Stack (vector search)')
        if not LLAMA_URL or not VECTOR_DB_ID:
            raise BackendUnavailable(
                'RAG', 'LLAMA_STACK_URL or VECTOR_DB_ID not set',
                'deploy rag-setup/ then set both (ingest.py --ensure prints the id)')

        query = (f'patch history, past failures and remediation for host {host}')
        try:
            found = http_json(
                f'{LLAMA_URL}/v1/vector_stores/{VECTOR_DB_ID}/search',
                method='POST', body={'query': query, 'max_num_results': 5},
                verify=False, timeout=RAG_TIMEOUT)
        except Exception as exc:
            down = BackendUnavailable('Llama Stack (vector search)', exc,
                                      'check LLAMA_STACK_URL is reachable')
            trip('Llama Stack (vector search)', down)
            raise down from exc

        hits = (found or {}).get('data', [])
        if not hits:
            # An empty result with no error is the signature of a Llama Stack
            # restart dropping its vector-store registry — see rag-setup README.
            raise BackendUnavailable(
                'RAG', f'vector store {VECTOR_DB_ID} returned no results',
                'run from the repo root: ./rag-setup/ingest.py --route <route> '
                '--name patch_history --dir ./rag-setup/data --ensure')

        excerpt = '\n\n'.join(
            ' '.join(c.get('text', '') for c in (h.get('content') or [])
                     if isinstance(c, dict))
            for h in hits
        )[:6000]
        return self._summarise(host, excerpt)

    def _summarise(self, host: str, excerpt: str) -> str:
        prompt = (
            f'Summarise the patch history for host {host} in 2-3 sentences. '
            f'Focus only on what a reviewer needs: repeated failures, known '
            f'sensitivities, and remediations that worked. Do not mention '
            f'retrieval or chunks. Begin with the finding itself — no '
            f'preamble, and do not restate the question.\n\n{excerpt}'
        )
        try:
            result = http_json(
                f'{LLAMA_URL}/v1/responses', method='POST',
                body={'model': LLM_MODEL,
                      'input': [{'role': 'user', 'content': prompt}],
                      'stream': False},
                verify=False)
        except Exception as exc:
            raise BackendUnavailable('Llama Stack (LLM)', exc,
                                     f'check model {LLM_MODEL!r} is served') from exc

        for item in (result or {}).get('output', []):
            for content in item.get('content', []):
                if content.get('text', '').strip():
                    return strip_preamble(content['text'].strip())
        raise BackendUnavailable('Llama Stack (LLM)', 'empty response',
                                 f'check model {LLM_MODEL!r} is served')

    # -- steps 1-4 ---------------------------------------------------------

    def gather(self, detail: dict) -> dict[str, Any]:
        """Enrich and assess. Returns cve-info for the Supervisor."""
        cve_id, cvss, hosts = detail['cve_id'], detail['cvss'], detail['hosts']
        if not hosts:
            # Not a service failure — Insights answered, the answer was zero.
            raise BackendUnavailable(
                'No affected hosts', f'{cve_id} affects no registered systems',
                'pick a CVE from the list, or widen HOSTS_FILTER / HOSTS_LIMIT')

        self._trace('supervisor', 'info', f'gather {cve_id} ({len(hosts)} hosts)')

        # step 3 — risk, batched
        scores, risk_source = self.risk_scores(cvss, hosts)
        threshold = (REVIEW_THRESHOLD if risk_source == 'model'
                     else fallbacks.HEURISTIC_THRESHOLD)
        # The score and the gate are real properties of the run and always
        # shown. Which of the two produced the score is the source label, and
        # "(heuristic)" is the whole tell — it never means anything but "the
        # risk service did not answer". plan.risk_source still carries it in
        # the payload, and the trace names the service.
        src = f' ({risk_source})' if label_sources() else ''
        assessed = [
            HostAssessment(
                host=h['host'], system_uuid=h['system_uuid'], age_days=h['age_days'],
                risk_score=round(s, 2),
                decision='review' if s > threshold else 'ok',
                reason=(f'Risk {s:.1f} exceeds {threshold:.0f}{src} '
                        f'— requires review.' if s > threshold else
                        f'Risk {s:.1f} below {threshold:.0f}{src}.'),
            )
            for h, s in zip(hosts, scores)
        ]

        # step 1 — history, only for hosts a human will look at
        review = [a for a in assessed if a.decision == 'review']
        # Clamped here, not just at import: the settings panel rebinds
        # RAG_WORKERS straight from operator input, and max_workers=0 is a
        # ValueError out of ThreadPoolExecutor.
        workers = max(1, min(RAG_WORKERS, len(review)))
        self._trace('info', 'rag', f'history for {len(review)} review host(s)'
                    + (f', {workers} at a time' if workers > 1 else ''))
        # Not 'rag' until a lookup actually succeeds. With nothing to review
        # nothing below runs, and starting at 'rag' would report a store that
        # was never queried as the source of an answer.
        history_source = 'rag' if review else 'skipped'

        # One vector search plus one LLM summarisation per host, and the LLM
        # call is seconds. Sequentially that is the whole assessment: 61 hosts
        # timed out the run. Every review host still gets looked up — the pool
        # only changes how many are in flight, never how many are asked about.
        #
        # Bounded because the far side is one model server; unbounded fan-out
        # turns a slow assessment into a self-inflicted overload. Results are
        # written back through the future map, not by workers racing on a
        # shared list, so the plan is identical whatever order they land in.
        if review:
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=workers, thread_name_prefix='rag') as pool:
                futures = {pool.submit(self.history, a.host): a for a in review}
                try:
                    for fut in concurrent.futures.as_completed(futures):
                        a = futures[fut]
                        # Live mode is fail-closed: degrade() re-raises, so
                        # this propagates and aborts the gather, exactly as it
                        # did when the lookups were sequential.
                        a.history, src = fut.result()
                        if src != 'rag':
                            history_source = src
                except BaseException:
                    # Don't let the remaining lookups run to completion while
                    # the caller is already unwinding.
                    for f in futures:
                        f.cancel()
                    raise

        # step 2 — window
        window, window_source = self.maintenance_window()

        # step 4 — the patch plan
        notes = []
        # These three are source labels written as prose, so they follow
        # label_sources() like every other mark on the page. With it off the
        # plan reads the same whether the score behind it came from the model
        # or the heuristic — the record moves to degrade()'s log line, to the
        # agent trace, and to plan.risk_source / plan.history_source, which
        # stay in the payload either way.
        if label_sources():
            # Offline the banner above already says the whole page is stored
            # defaults, so repeating it per-step is noise. Live it is the
            # opposite: there is no banner, and a single step that quietly
            # fell back is exactly what the reviewer needs told.
            if not offline():
                if risk_source != 'model':
                    notes.append('Risk scores are heuristic, not model output — the risk '
                                 'service was unreachable. Treat them as indicative only.')
                if history_source != 'rag':
                    notes.append('Host history came from stored defaults, not the RAG '
                                 'store, so it may not reflect this estate.')
            if window_source == 'default':
                notes.append(f'No scheduler configured; using default window {window}.')
        # Not a source label either: how much of the estate this plan covers is
        # true whatever answered. Said plainly, because the difference between
        # "we planned for every affected host" and "we planned for the first
        # 100 of them" is not something to leave the operator to infer from two
        # numbers in a trace line.
        total = detail.get('total_affected')
        if total and total > len(hosts) and len(hosts) >= AFFECTED_PAGE:
            notes.append(f'Only the first {len(hosts)} of {total} affected host(s) '
                         f'were assessed — raise AFFECTED_PAGE to cover the rest.')
        # HOSTS_LIMIT is the backstop behind HOSTS_FILTER: if the filter ever
        # widens unexpectedly again, this caps the blast radius. It has to say
        # when it fired, because a plan silently cut from 100 hosts to 1 looks
        # exactly like a plan that was always 1 — and the difference is that
        # something went wrong upstream.
        capped = detail.get('limited_from')
        if capped:
            notes.append(f'HOSTS_LIMIT capped this plan at {len(hosts)} of '
                         f'{capped} host(s) that matched — check HOSTS_FILTER '
                         f'is selecting what you expect.')
        # Not a source label: true of this CVE against this gate whether the
        # scores were measured or substituted, and the reviewer needs it in
        # either case. So it is outside the block above.
        if len(review) == len(assessed):
            notes.append('Every host requires review — check the risk threshold '
                         'is discriminating at this CVSS.')

        plan = PatchPlan(
            cve_id=cve_id, cvss=cvss,
            hosts_total=len(assessed), hosts_review=len(review),
            hosts_auto=len(assessed) - len(review),
            maintenance_window=window, risk_source=risk_source,
            history_source=history_source,
            threshold=round(float(threshold), 2),
            verdict='review_required' if review else 'auto_approve_eligible',
            notes=notes,
            degraded=[dict(d) for d in DEGRADED],
        )
        self._trace('info', 'supervisor',
                    f'{len(review)}/{len(assessed)} need review — {plan.verdict}')
        return {'hosts': [asdict(a) for a in assessed], 'plan': asdict(plan)}


# ==========================================================================
# AGENT 2 — Patching Agent              APPROVE · BUILD · EXECUTE
#
# Steps 5-10 live inside the Ansible Orchestrator workflow "DemoJam Agentic
# Patching", not in this file. This agent is a client: it triggers that
# workflow once per affected host and reports what came back.
#
# The workflow routes on the `group` input:
#   auto_patch      -> case_0, unattended
#   approved_patch  -> case_1 -> approval gate -> fetch/commit -> schedule ->
#                      sync/deploy -> run remediation
# Anything else falls through to the default port.
#
# A host routed to approved_patch leaves the execution PAUSED awaiting a human
# in the AO console. That is a normal outcome, not a failure, and the agent
# returns rather than blocking on it.
# ==========================================================================

AO_URL = env('AO_URL').rstrip('/')
AO_USERNAME = env('AO_USERNAME')
AO_PASSWORD = env('AO_PASSWORD')
AO_WORKFLOW_NAME = env('AO_WORKFLOW_NAME', 'DemoJam Agentic Patching')
AO_TRIGGER_NODE = env('AO_TRIGGER_NODE', 'trigger_manual')
AO_POLL_TIMEOUT = int(env('AO_POLL_TIMEOUT', '900'))
LAB_TAG = env('LAB_TAG')


class SimStore:
    """Simulated executions, for when AO is unreachable.

    AO is normally the system of record, which is why real runs survive a
    console restart without any storage here. A simulated run has no record
    anywhere else, so it is kept on disk — otherwise an offline demo loses its
    Patch runs page the moment the backend is restarted.
    """

    def __init__(self, path: Path):
        self.path = path
        self.runs: dict[str, dict] = {}
        # Approving several hosts at once puts one writer per host on its own
        # server thread, and each one now writes repeatedly as its run steps
        # forward. Two interleaved write_text calls truncate the file.
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            self.runs = {r['execution_id']: r
                         for r in json.loads(self.path.read_text())}
        except Exception as exc:               # a corrupt file must not block startup
            print(f'  warning: could not read {self.path}: {exc}', file=sys.stderr)

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(list(self.runs.values()), indent=2))
        except Exception as exc:
            print(f'  warning: could not write {self.path}: {exc}', file=sys.stderr)

    def new_id(self) -> str:
        # Shaped like a real AO execution id. A 'sim-' prefix would be a
        # giveaway in the console's Exec column, and membership of this store
        # is a more reliable test than string-sniffing an id anyway.
        return str(uuid.uuid4())

    def put(self, run: dict) -> dict:
        run.setdefault('created_at', now_iso())
        if run.get('outcome') in ('patched', 'rejected', 'failed'):
            run['completed_at'] = now_iso()
        with self._lock:
            self.runs[run['execution_id']] = dict(run)
            self._save()
        return run

    def get(self, execution_id: str) -> dict | None:
        # A copy, because the console polls a run on one thread while the
        # thread stepping it forward is mutating it.
        run = self.runs.get(execution_id)
        return dict(run) if run else None

    def recent(self, limit: int = 40) -> list[dict]:
        return sorted(self.runs.values(),
                      key=lambda r: r.get('created_at', ''), reverse=True)[:limit]


SIM = SimStore(ROOT / 'runs' / 'simulated.json')
REPORTS_DIR = ROOT / 'reports'
# Inside the RAG data dir, so ingest.py's rglob still finds it, but in
# its own subdirectory: the ten curated records next to it are authored
# and reviewed, and every demo run would otherwise add noise to them.
RAG_DATA_DIR = ROOT / 'rag-setup' / 'data' / 'runs'
TRAINING_DIR = ROOT / 'risk_score' / 'training' / 'observed'


def is_sim(execution_id: str) -> bool:
    """True if this id belongs to the local simulator rather than to AO.

    Looked up rather than pattern-matched: the store is the authority on what
    it created, and uuid4 collision with a real AO id is not a real risk.
    """
    return SIM.get(execution_id) is not None


# How long a patch counts as "already done" for the same CVE. A host does
# not become vulnerable again on its own, so this is really about how stale
# a record has to be before it is worth re-checking rather than trusting.
# Minutes, not days, so the same knob serves both audiences: 10080 is the
# week a real estate wants, and a demo can drop it to 1 — or 0 — to assess
# the same CVE repeatedly. In days the smallest useful demo value was 0,
# which turns the guard off rather than shortening it.
PATCHED_WITHIN_MINUTES = int(env('PATCHED_WITHIN_MINUTES', '10080'))


def patched_window() -> int:
    """The window actually in force. Always 0 — off — in demo mode.

    A demo is the same CVE assessed over and over, and the guard is built to
    stop exactly that: after the first run every host is recently patched, so
    the second assessment finds nothing to do. Correct in an estate, useless
    on stage. Rather than ask anyone to remember to zero it before presenting,
    demo mode zeroes it, and the setting describes itself as live-only.
    """
    return 0 if demo_mode() else PATCHED_WITHIN_MINUTES


# "Here is a 2-3 sentence summary of the patch history for host X:" — the
# model restating the question before answering it. Harmless in a chat window,
# but this lands in a table cell clamped to two lines, so the preamble is most
# of what a reviewer sees and it is identical on every row. The prompt asks
# for no preamble; this is for when the model does it anyway.
#
# Deliberately narrow: an opener that announces a summary and ends in a colon,
# on one line, with no colon inside it. Anything else is left alone, because
# discarding a real first sentence costs more than leaving a clumsy one.
_PREAMBLE = re.compile(
    r'^\s*(?:sure[,!.]?\s*)?'
    r'here(?:\'s|’s| is| are)\b[^\n:]{0,200}'
    r'\bsummar(?:y|ies|ising|izing)\b[^\n:]{0,200}:[ \t]*\n*',
    re.IGNORECASE)


def strip_preamble(text: str) -> str:
    out = _PREAMBLE.sub('', text, count=1).strip()
    # If the answer was nothing but preamble, the preamble is the answer.
    return out or text


def human_window(minutes: int) -> str:
    """The window as an operator would say it, whatever unit it was set in."""
    if minutes <= 0:
        return 'no window — every host is re-assessed'
    if minutes < 60:
        return f'{minutes} minute(s)'
    if minutes < 1440:
        h = minutes / 60
        return f'{h:g} hour(s)'
    d = minutes / 1440
    return f'{d:g} day(s)'


def already_patched(cve_id: str, agent: 'PatchingAgent') -> dict[str, dict]:
    """host -> the run that patched it for this CVE, recently.

    Only runs we can prove reached 'patched' count. The execution list cannot
    tell an approved run from a rejected one — both complete — so a run that
    merely says 'completed' is resolved with run_detail before being trusted.
    Guessing the wrong way here would hide a host that was never patched,
    which is worse than patching one twice.
    """
    window = patched_window()
    if not cve_id or window <= 0:
        return {}                      # guard disabled: assess everything
    try:
        runs = agent.recent_runs(200)
    except BackendUnavailable:
        return {}                      # no history to go on; assess everything

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
    out: dict[str, dict] = {}
    for r in runs:
        if r.get('cve_id') != cve_id or not r.get('host'):
            continue
        if r.get('outcome') not in ('patched', 'completed'):
            continue
        when = r.get('completed_at') or r.get('created_at') or ''
        try:
            at = datetime.fromisoformat(str(when).replace('Z', '+00:00'))
        except ValueError:
            continue
        if at < cutoff or r['host'] in out:
            continue
        if r['outcome'] == 'completed':                 # ambiguous — resolve it
            try:
                if agent.run_detail(r['execution_id']).get('outcome') != 'patched':
                    continue
            except BackendUnavailable:
                continue
        out[r['host']] = {'at': when, 'execution_id': r.get('execution_id', '')}
    return out


def next_step(summary: dict) -> str:
    """What the console should say happens next, from the run's own counts.

    This used to be a literal set at three points, and the one at dispatch
    said 'all four agents complete' while hosts were still at the gate — on
    the same screen where agent 4 reported it had published nothing because
    nothing had settled.
    """
    waiting = summary.get('awaiting_approval') or 0
    running = summary.get('running') or 0
    if waiting:
        return (f'your approval on {waiting} host'
                f'{"" if waiting == 1 else "s"} at the gate')
    if running:
        return f'{running} host{"" if running == 1 else "s"} still patching'
    return 'nothing — all four agents are done with this CVE'


# Maps the Info agent's per-host decision onto the workflow's routing input.
GROUP_FOR_DECISION = {'review': 'approved_patch', 'ok': 'auto_patch'}

_ao_token: dict[str, Any] = {}


def ao_login() -> str:
    """Bearer token for AO, cached until shortly before it expires."""
    # Before the cache, not after. A token minted in live mode outlives the
    # switch to demo, and returning it here skipped the guard entirely and
    # let the caller open a real connection to AO.
    circuit('Ansible Orchestrator')
    if _ao_token.get('value') and _ao_token['expires'] > time.time() + 30:
        return _ao_token['value']
    if not (AO_URL and AO_USERNAME and AO_PASSWORD):
        raise BackendUnavailable(
            'Ansible Orchestrator', 'AO_URL / AO_USERNAME / AO_PASSWORD not set',
            'add them to .env')
    try:
        payload = http_json(f'{AO_URL}/api/v1/auth/login', method='POST',
                            body={'username': AO_USERNAME, 'password': AO_PASSWORD},
                            verify=False, timeout=AO_TIMEOUT)
    except Exception as exc:
        down = BackendUnavailable('Ansible Orchestrator', exc,
                                  f'check AO_URL is reachable: {AO_URL}')
        trip('Ansible Orchestrator', down)
        raise down from exc
    token = (payload or {}).get('access_token')
    if not token:
        raise BackendUnavailable('Ansible Orchestrator', 'no access_token in login response',
                                 'check AO_USERNAME / AO_PASSWORD')
    _ao_token['value'] = token
    _ao_token['expires'] = time.time() + int((payload or {}).get('expires_in', 900))
    return token


def ao_call(path: str, method: str = 'GET', body: Any = None,
            timeout: int | None = None) -> Any:
    try:
        return http_json(f'{AO_URL}{path}', method=method, body=body, verify=False,
                         headers={'Authorization': f'Bearer {ao_login()}'},
                         timeout=timeout or AO_TIMEOUT)
    except BackendUnavailable:
        raise
    except urllib.error.HTTPError as exc:
        detail = ''
        try:
            detail = json.loads(exc.read().decode()).get('detail', '')
        except Exception:
            pass
        raise BackendUnavailable('Ansible Orchestrator', detail or exc,
                                 f'{method} {path} was rejected') from exc
    except Exception as exc:
        # A transport-level failure means the whole service is down, not just
        # this path, so trip the breaker and spare the remaining hosts.
        down = BackendUnavailable('Ansible Orchestrator', exc,
                                  f'{method} {path} failed')
        trip('Ansible Orchestrator', down)
        raise down from exc


class PatchingAgent:
    name = 'patching-agent'

    def __init__(self, trace=None):
        self._trace = trace or (lambda *a, **k: None)
        self._workflow_id: str | None = None
        # Set by recent_runs() when AO could not be read, so the Patch runs
        # page can say the list is simulated-only rather than looking complete.
        self.runs_degraded: str = ''

    def workflow_id(self) -> str:
        """Resolve the workflow by name — its id differs per cluster."""
        if self._workflow_id:
            return self._workflow_id
        found = ao_call('/api/v1/workflows')
        for w in (found or {}).get('resources', []):
            if w.get('name') == AO_WORKFLOW_NAME:
                self._workflow_id = w['id']
                return self._workflow_id
        names = [w.get('name') for w in (found or {}).get('resources', [])]
        raise BackendUnavailable(
            'Ansible Orchestrator', f'workflow {AO_WORKFLOW_NAME!r} not found',
            f'set AO_WORKFLOW_NAME to one of: {", ".join(filter(None, names))}')

    def patch_host(self, cve_id: str, host: dict, scheduler_date_time: str = '') -> dict:
        """Trigger the AO workflow for one host and wait for it to settle."""
        group = GROUP_FOR_DECISION.get(host.get('decision'), 'auto_patch')
        # lab_tag is optional in the trigger schema but fetch_and_commit_prod
        # dereferences ${trigger.lab_tag} unconditionally — omitting it fails
        # the run at that node with 'Property "lab_tag" not found'. Always send
        # it, even empty. scheduler_date_time is referenced by no node, so it
        # is genuinely optional.
        inputs = {'host': host['host'], 'group': group, 'cve_id': cve_id,
                  'lab_tag': LAB_TAG}
        if scheduler_date_time:
            inputs['scheduler_date_time'] = scheduler_date_time

        self._trace('supervisor', 'patching', f'{host["host"]} -> AO ({group})')
        try:
            created = ao_call('/api/v1/executions', 'POST', {
                'workflow_id': self.workflow_id(),
                'trigger_node_id': AO_TRIGGER_NODE,
                'input_data': inputs,
            })
        except BackendUnavailable as exc:
            degrade('5-10 patching', exc.service, exc.cause, exc.fix)
            if not fallbacks.simulate_patch():
                self._trace('patching', 'supervisor',
                            f'{host["host"]}: not dispatched — {exc.cause}')
                return fallbacks.patch_unavailable(host['host'], group, str(exc.cause))
            # Simulated: nothing is patched. The run is registered in SIM, so
            # a later status read resolves it here instead of asking AO about
            # an execution that exists in no AO instance — and it carries
            # simulated: true, which is what the plan and the ROI page label
            # themselves from.
            demo_pause()
            run = SIM.put(fallbacks.patch_simulated(
                cve_id, host['host'], group, str(exc.cause), SIM.new_id()))
            self._trace('patching', 'supervisor',
                        f'{host["host"]}: SIMULATED {run["outcome"]} — AO unreachable')
            return run
        exec_id = (created or {}).get('id')
        if not exec_id:
            raise BackendUnavailable('Ansible Orchestrator', 'no execution id returned',
                                     'check the workflow trigger accepts these inputs')
        return self._await(exec_id, host['host'], group)

    def _await(self, exec_id: str, host: str, group: str) -> dict:
        """Poll until the execution settles. A pause for approval counts as settled."""
        deadline = time.time() + AO_POLL_TIMEOUT
        state: dict[str, Any] = {}
        while time.time() < deadline:
            state = ao_call(f'/api/v1/executions/{exec_id}') or {}
            status = state.get('status')
            if status in ('completed', 'succeeded', 'failed', 'error',
                          'cancelled', 'canceled'):
                break
            if state.get('approval_pending'):
                break
            time.sleep(3)

        status = state.get('status', 'unknown')
        pending = bool(state.get('approval_pending'))
        outcome = ('awaiting_approval' if pending
                   else 'patched' if status in ('completed', 'succeeded')
                   else 'timeout' if time.time() >= deadline
                   else 'failed')

        steps, matched_port, approval_activity = self._activities(exec_id)
        self._trace('patching', 'supervisor',
                    f'{host}: {outcome}' + (f' (port {matched_port})' if matched_port else ''))
        return {
            'host': host, 'group': group, 'execution_id': exec_id,
            'status': status, 'outcome': outcome,
            'approval_pending': pending,
            # Needed to signal the approval gate; see decide().
            'approval_activity_id': approval_activity,
            'matched_port': matched_port,
            'error': state.get('error_details'),
            'steps': steps,
            # AO's own clock, carried through rather than left for a later
            # read. The simulated path gets these from SimStore.put(), so
            # without them here anything timing-based — the ROI report in
            # particular — would work offline and quietly measure nothing
            # live, which is the worst of the two failure modes.
            'created_at': state.get('created_at'),
            'completed_at': state.get('completed_at'),
            'url': f'{AO_URL}/executions/{exec_id}',
        }

    @staticmethod
    def _activities(exec_id: str) -> tuple[list[dict], str, str]:
        """Per-node outcome, the switch port taken, and any waiting approval.

        The signal endpoint addresses an activity by temporal_activity_id (the
        workflow node id), not by the activity's own UUID.
        """
        try:
            found = ao_call(f'/api/v1/executions/{exec_id}/activities')
        except BackendUnavailable:
            return [], '', ''
        steps, port, approval = [], '', ''
        for a in (found or {}).get('resources', []):
            out = a.get('output_data') or {}
            if a.get('activity_name') == 'route_switch':
                port = out.get('matched_port', '')
            if a.get('node_type') == 'approval' and a.get('status') in ('waiting', 'pending'):
                approval = a.get('temporal_activity_id') or a.get('activity_name') or ''
            steps.append({'name': a.get('activity_name'),
                          'status': a.get('status'),
                          'error': a.get('error_details')})
        return steps, port, approval

    def recent_runs(self, limit: int = 40) -> list[dict]:
        """Past executions of the patch workflow, read back from AO.

        AO is the source of truth, so this also picks up runs triggered from
        the AO console and reflects status changes that happened after the
        console stopped polling.
        """
        # Simulated runs live only here, so they are always included — mixing
        # them in rather than replacing means a partial outage still shows the
        # real history alongside whatever was simulated during it.
        sim = [{**r, 'simulated': True} for r in SIM.recent(limit)]

        try:
            found = self._ao_runs(limit)
        except BackendUnavailable as exc:
            # Not degrade() — that list belongs to an assessment, and polling
            # this page must not append to the banner of an unrelated run.
            self.runs_degraded = f'{exc.service}: {exc.cause}'
            return sim
        return sorted(found + sim, key=lambda r: r.get('created_at') or '',
                      reverse=True)[:limit]

    def _ao_runs(self, limit: int) -> list[dict]:
        # Filter server-side. AO returns newest-first across every workflow and
        # the built-in Integration Health Check runs every few minutes, so a
        # client-side filter progressively loses patch runs as those pile up.
        found = ao_call(f'/api/v1/executions?limit={limit}'
                        f'&workflow_id={self.workflow_id()}')
        runs = []
        for e in (found or {}).get('resources', []):
            if e.get('workflow_name') != AO_WORKFLOW_NAME:
                continue
            inp = e.get('input_data') or {}
            status = e.get('status')
            # A cancelled or failed run can still carry approval_pending from
            # before it ended, so the terminal status has to win.
            terminal = status in ('completed', 'succeeded', 'failed', 'error',
                                  'cancelled', 'canceled')
            pending = bool(e.get('approval_pending')) and not terminal
            runs.append({
                'execution_id': e.get('id'),
                'cve_id': inp.get('cve_id'),
                'host': inp.get('host'),
                'group': inp.get('group'),
                'status': status,
                # A completed run on the approval branch stays 'completed'
                # rather than 'patched': the list alone cannot tell an approved
                # run from a rejected one, since both complete. Only the detail
                # view has the activity data to separate them.
                #
                # The unattended branch has no such ambiguity — there is no
                # gate anywhere downstream of it, so a run that completed ran
                # the remediation. Reporting that one as 'completed' too was
                # losing a fact the input data already settles, and it left
                # every live run looking unresolved to anything counting
                # outcomes.
                'outcome': ('awaiting_approval' if pending
                            else 'cancelled' if status in ('cancelled', 'canceled')
                            else 'failed' if status in ('failed', 'error')
                            else ('patched' if inp.get('group') == 'auto_patch'
                                  else 'completed')
                            if status in ('completed', 'succeeded')
                            else 'running'),
                'approval_pending': pending,
                'error': e.get('error_details'),
                'created_at': e.get('created_at'),
                'completed_at': e.get('completed_at'),
                'url': f'{AO_URL}/executions/{e.get("id")}',
            })
        return runs

    # Everything the workflow still has to do once the gate clears. route_switch
    # and the gate itself are already behind an approved run.
    _AFTER_GATE = tuple(n for n, _ in fallbacks.SIM_STEPS
                        if n not in ('route_switch', 'approval_gate'))

    def _decide_sim(self, execution_id: str, decision: str) -> dict:
        """Resolve a simulated approval gate. No signal is sent anywhere."""
        run = SIM.get(execution_id)
        if not run:
            raise BackendUnavailable(
                'simulated run', f'{execution_id} is not in the local store',
                'it was created before runs/simulated.json was last cleared')
        demo_pause(2)        # the real gate takes seconds to settle

        if decision != 'approved':
            # Rejecting stops the run at the gate, matching the real workflow:
            # the downstream nodes never leave pending.
            run.update({
                'status': 'completed', 'outcome': 'rejected',
                'approval_pending': False, 'approval_activity_id': '',
                'decision': decision,
                'steps': fallbacks.sim_steps('approval_gate', status='rejected'),
            })
            SIM.put(run)
            self._trace('patching', 'console',
                        f'{execution_id[:12]} -> SIMULATED rejected')
            return {**run, 'decision': decision}

        # Approved runs walk their remaining nodes one at a time, committing
        # each transition to the store before pausing. A real execution is
        # observable while it works, and the console draws its progress bar
        # from whatever the steps say — so jumping straight from 'waiting' to
        # 'completed' would leave that bar with nothing to read, and would have
        # the simulator misrepresent the one part of the run that takes time.
        run.update({'approval_pending': False, 'approval_activity_id': '',
                    'decision': decision})
        for node in self._AFTER_GATE:
            run.update({'status': 'running', 'outcome': 'running',
                        'steps': fallbacks.sim_steps(node, status='running')})
            SIM.put(run)
            demo_pause(3)

        run.update({'status': 'completed', 'outcome': 'patched',
                    'steps': fallbacks.sim_steps('run_cve_remediation')})
        SIM.put(run)
        self._trace('patching', 'console',
                    f'{execution_id[:12]} -> SIMULATED patched')
        return {**run, 'decision': decision}

    def run_detail(self, execution_id: str) -> dict:
        """Current state of one execution, including a pending approval id."""
        if is_sim(execution_id):
            run = SIM.get(execution_id)
            if not run:
                raise BackendUnavailable(
                    'simulated run', f'{execution_id} is not in the local store',
                    'it predates the current runs/simulated.json')
            return dict(run)
        state = ao_call(f'/api/v1/executions/{execution_id}') or {}
        steps, port, approval = self._activities(execution_id)
        inp = state.get('input_data') or {}
        status = state.get('status')
        terminal = status in ('completed', 'succeeded', 'failed', 'error',
                              'cancelled', 'canceled')
        pending = bool(state.get('approval_pending')) and not terminal
        # With activity data we can tell approved from rejected: a rejected
        # run completes with the downstream nodes never leaving 'pending'.
        ran = any(s.get('name') == 'fetch_and_commit_prod'
                  and s.get('status') in ('completed', 'running', 'failed')
                  for s in steps)
        any_failed = any(s.get('status') in ('failed', 'error') for s in steps)
        return {
            'execution_id': execution_id,
            'cve_id': inp.get('cve_id'), 'host': inp.get('host'),
            'group': inp.get('group'), 'status': status,
            'outcome': ('awaiting_approval' if pending
                        else 'cancelled' if status in ('cancelled', 'canceled')
                        else 'failed' if status in ('failed', 'error') or any_failed
                        else ('patched' if ran else 'rejected')
                        if status in ('completed', 'succeeded')
                        else 'running'),
            'approval_pending': pending,
            'approval_activity_id': approval,
            'matched_port': port, 'steps': steps,
            'error': state.get('error_details'),
            'created_at': state.get('created_at'),
            'completed_at': state.get('completed_at'),
        }

    def decide(self, execution_id: str, activity_id: str, decision: str) -> dict:
        """Approve or reject a paused approval gate, then report the new state.

        AO does not validate the decision value — it forwards whatever it is
        given and Temporal fails the run on anything unexpected — so this
        rejects bad input before it can poison the execution.
        """
        if decision not in ('approved', 'rejected'):
            raise BackendUnavailable(
                'Ansible Orchestrator', f'invalid decision {decision!r}',
                "decision must be 'approved' or 'rejected'")

        # Above the branch: the operator issued the decision whichever side
        # handles it, and logging it only on the live path left the simulated
        # one showing an answer with nothing having asked for it.
        self._trace('console', 'patching', f'{decision} {execution_id[:8]}/{activity_id}')

        if is_sim(execution_id):
            return self._decide_sim(execution_id, decision)

        ao_call(f'/api/v1/executions/{execution_id}/activities/{activity_id}/signal',
                'POST', {'signal_data': {'decision': decision}})

        # Keep polling until the execution actually settles, not merely until
        # the gate clears. Returning as soon as approval_pending drops reports
        # 'running' for a run that fails a second later, and nothing revisits
        # it. Bounded so the button does not hang.
        state: dict[str, Any] = {}
        deadline = time.time() + int(env('AO_DECIDE_WAIT', '90'))
        while time.time() < deadline:
            time.sleep(2)
            state = ao_call(f'/api/v1/executions/{execution_id}') or {}
            if state.get('status') in ('completed', 'succeeded', 'failed', 'error',
                                       'cancelled', 'canceled'):
                break
            if decision == 'rejected' and not state.get('approval_pending'):
                break

        steps, port, approval = self._activities(execution_id)
        status = state.get('status', 'unknown')
        terminal = status in ('completed', 'succeeded', 'failed', 'error',
                              'cancelled', 'canceled')
        pending = bool(state.get('approval_pending')) and not terminal
        # A node that has already failed dooms the run even if AO has not
        # finished marking it, so surface that rather than a stale 'running'.
        any_failed = any(s.get('status') in ('failed', 'error') for s in steps)
        outcome = ('awaiting_approval' if pending
                   else 'cancelled' if status in ('cancelled', 'canceled')
                   else 'failed' if status in ('failed', 'error') or any_failed
                   else 'rejected' if decision == 'rejected' and terminal
                   else 'patched' if status in ('completed', 'succeeded')
                   else 'running')
        self._trace('patching', 'console', f'{execution_id[:8]} -> {outcome}')
        return {
            'execution_id': execution_id, 'decision': decision,
            'status': status, 'outcome': outcome,
            'approval_pending': bool(state.get('approval_pending')),
            'approval_activity_id': approval,
            'matched_port': port, 'steps': steps,
            'error': state.get('error_details'),
            # The gate is where most of the exposure window is spent, so this
            # is the read that matters for timing: completed_at only exists
            # once the approved run finishes.
            'created_at': state.get('created_at'),
            'completed_at': state.get('completed_at'),
        }


# ==========================================================================
# SUPERVISOR
#
# Owns control flow and per-CVE state. Agents stay stateless so the counters
# and the stop decision live in one place.
# ==========================================================================

class Supervisor:
    name = 'supervisor'

    # Guards for the self-healing loop (agent 2 — not wired up yet).
    MAX_ATTEMPTS_PER_HOST = int(env('MAX_ATTEMPTS_PER_HOST', '2'))
    MAX_FAILED_PER_PHASE = int(env('MAX_FAILED_PER_PHASE', '2'))

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.events: list[dict] = []
        self.info = InfoAgent(trace=self.trace)
        self.patching = PatchingAgent(trace=self.trace)
        self.comms = communication.CommunicationAgent(REPORTS_DIR, trace=self.trace)
        self.results = results_mod.ResultsAgent(RAG_DATA_DIR, TRAINING_DIR,
                                                trace=self.trace)
        self.reset()

    def reset(self) -> None:
        self.attempts: dict[str, int] = {}
        self.tried_fixes: dict[str, set[str]] = {}
        self.phase_failures = 0
        self.state: dict[str, Any] = {}

    def trace(self, src: str, dst: str, message: str) -> None:
        self.events.append({'time': now_iso(), 'from': src, 'to': dst,
                            'message': message})
        if self.verbose:
            print(f'  {src:>10} -> {dst:<12} {message}', file=sys.stderr)

    def run(self, cve_id: str, host_filter: str = '', host_limit: int = 0) -> dict:
        self.reset()
        degraded_reset()
        started = time.monotonic()

        # --- common code (C1/C2) — not an agent --------------------------
        self.trace('console', 'insights', f'loading {cve_id}')
        detail = fetch_cve_detail(cve_id, host_filter=host_filter, host_limit=host_limit)
        self.trace('insights', 'supervisor',
                   f'CVSS {detail["cvss"]} · {detail["count"]} host(s)'
                   + (f' of {detail["total_affected"]}' if detail.get('total_affected') else ''))

        # Re-assessing a CVE should not offer up hosts that were patched for
        # it days ago. They are dropped from the plan rather than carried
        # through and skipped at dispatch, so the risk scoring, the RAG
        # lookups and the operator's review are all spent on work that is
        # actually outstanding. The count is kept so the plan can say what
        # was left out — silently shrinking the host list would be its own
        # kind of lie.
        done = already_patched(cve_id, self.patching)
        skipped = [h for h in detail['hosts'] if h['host'] in done]
        if skipped:
            detail['hosts'] = [h for h in detail['hosts'] if h['host'] not in done]
            detail['count'] = len(detail['hosts'])
            self.trace('supervisor', 'console',
                       f'{len(skipped)} host(s) already patched for {cve_id} '
                       f'within {human_window(patched_window())} '
                       f'— not re-assessed')

        # Everything already done. Agent 1 would raise "affects no registered
        # systems" here, which is the wrong story: the CVE does affect them,
        # they are just patched.
        if skipped and not detail['hosts']:
            self.state = {
                'cve_id': cve_id, 'cvss': detail['cvss'],
                'description': detail['description'],
                'hosts': [], 'plan': {
                    'cve_id': cve_id, 'cvss': detail['cvss'],
                    'hosts_total': 0, 'hosts_review': 0, 'hosts_auto': 0,
                    'verdict': 'nothing_to_do',
                    'maintenance_window': self.info.maintenance_window()[0],
                    'risk_source': 'n/a', 'threshold': REVIEW_THRESHOLD,
                    'notes': [f'All {len(skipped)} affected host(s) were patched '
                              f'for {cve_id} within the last '
                              f'{human_window(patched_window())}. '
                              f'Nothing to do.'],
                    'degraded': [dict(d) for d in DEGRADED],
                },
                'already_patched': [
                    {'host': h['host'], **done[h['host']]} for h in skipped],
                'events': self.events,
                'elapsed_s': round(time.monotonic() - started, 1),
                'degraded': [dict(d) for d in DEGRADED],
                'next': 'nothing — every affected host is already patched',
                'status': 'nothing_to_do',
            }
            self.trace('supervisor', 'console',
                       f'nothing to do — all {len(skipped)} host(s) already patched')
            return self.state

        # --- agent 1 ------------------------------------------------------
        info = self.info.gather(detail)

        self.state = {
            'cve_id': cve_id,
            'cvss': detail['cvss'],
            'description': detail['description'],
            'hosts': info['hosts'],
            'plan': info['plan'],
            'already_patched': [
                {'host': h['host'], **done[h['host']]} for h in skipped],
            'events': self.events,
            'elapsed_s': round(time.monotonic() - started, 1),
            'degraded': [dict(d) for d in DEGRADED],
            # The plan is a stopping point, not a completion: dispatch is
            # a separate, operator-initiated step. Named by what dispatch does
            # rather than by a button label, which differs per verdict.
            'next': 'Patching Agent — awaiting operator dispatch',
            'status': 'awaiting_patch_dispatch',
        }
        self.trace('supervisor', 'console', 'patch plan ready — awaiting operator review')
        return self.state

    # --- agent 2 ----------------------------------------------------------

    def patch(self, assessment: dict) -> dict:
        """Hand each assessed host to the Patching Agent, one AO run per host.

        Takes the plan from run() so the per-host decision determines which
        branch of the workflow that host takes.
        """
        cve_id = assessment['cve_id']
        hosts = assessment.get('hosts') or []
        if not hosts:
            raise BackendUnavailable('supervisor', f'no assessed hosts for {cve_id}',
                                     'run the assessment first')

        started = time.monotonic()
        self.events = list(assessment.get('events') or [])
        self.trace('console', 'supervisor', f'patch {cve_id} ({len(hosts)} host(s))')

        results, failures = [], 0
        for h in hosts:
            try:
                r = self.patching.patch_host(cve_id, h)
            except BackendUnavailable as exc:
                # One host failing to launch must not abandon the rest.
                r = {'host': h['host'], 'outcome': 'failed', 'status': 'launch_error',
                     'error': str(exc.cause), 'fix': exc.fix, 'steps': []}
                self.trace('patching', 'supervisor', f'{h["host"]}: launch failed — {exc.cause}')
            results.append(r)
            if r['outcome'] in ('failed', 'timeout'):
                failures += 1

        summary = {
            'patched': sum(1 for r in results if r['outcome'] == 'patched'),
            'unavailable': sum(1 for r in results if r['outcome'] == 'unavailable'),
            'awaiting_approval': sum(1 for r in results if r['outcome'] == 'awaiting_approval'),
            # A host dispatched into the unattended branch can still be working
            # when this returns, so the counts only add up with this included.
            'running': sum(1 for r in results if r['outcome'] == 'running'),
            'failed': failures,
        }
        self.state = {
            **assessment,
            'patch': {
                'cve_id': cve_id,
                'workflow': AO_WORKFLOW_NAME,
                'results': results,
                'summary': summary,
                'elapsed_s': round(time.monotonic() - started, 1),
            'degraded': [dict(d) for d in DEGRADED],
            },
            'events': self.events,
            'next': next_step(summary),
            'status': 'reported',
        }
        self.trace('supervisor', 'console',
                   f'patch dispatched — {summary["patched"]} patched, '
                   f'{summary["awaiting_approval"]} awaiting approval, '
                   f'{summary["failed"]} failed')

        # --- agent 3 ------------------------------------------------------
        # Reporting must not be able to lose a patch result. The dispatch
        # above has already happened; a failure to render a PDF is worth
        # surfacing but not worth discarding the run over.
        self.comms.simulated = any(r.get('simulated') for r in results)
        self.trace('supervisor', 'communication', f'report for {cve_id}')
        try:
            self.state['report'] = self.comms.report(self.state)
        except Exception as exc:
            self.trace('communication', 'supervisor', f'report failed — {exc}')
            self.state['report'] = {'error': str(exc)}

        # --- agent 4 ------------------------------------------------------
        # Publishing is the last thing and the least important: a run whose
        # outcome failed to reach the learning stores is still a completed
        # patch, so this can never raise past here.
        self.trace('supervisor', 'results', f'publish {cve_id}')
        try:
            self.state['published'] = self.results.publish(self.state)
        except Exception as exc:
            self.trace('results', 'supervisor', f'publish failed — {exc}')
            self.state['published'] = {'error': str(exc)}
        self.state['next'] = next_step(summary)
        return self.state


# ==========================================================================
# ROI — this run's measured effort against what the same work costs by hand
#
# Two kinds of number meet here, and the report keeps them apart all the way
# to the operator because they carry very different warranties:
#
#   measured   this run's own clock — how many hosts, how many needed
#              sign-off, how long the assessment took, how long each
#              execution ran. Real, with one caveat: a clock is only a
#              measurement of patching if something was patched. Offline it is
#              DEMO_LATENCY rather than work; live with AO unreachable it is
#              real time spent failing over. Either way `illustrative` is set,
#              `illustrative_reason` says which, and the console leads with it.
#   assumed    the manual baseline, from fallbacks.ROI_*. Not measurable from
#              here by any means: the manual run never happened, so there is
#              no clock to read it off. Every one of them is itemised in the
#              response with its value, so the page can show the arithmetic
#              instead of a number with a flourish.
#
# What is deliberately not claimed matters as much as what is. The automated
# side counts the operator's review time as a real cost, because it is one —
# a comparison that pretends the approval gate is free is a sales slide, not
# an estimate. Machine seconds count toward the exposure window but not
# toward money: an engineer-hour and a container-second do not convert, and
# pricing the compute would add a rounding error to a figure that labour
# already dominates.
#
# The exposure figure intentionally includes time a run spent parked at the
# gate waiting for a person. That wait is not automation working, but the
# host is exploitable throughout it, and exposure is measured from the host's
# point of view.
# ==========================================================================

def _parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return None


def _run_seconds(run: dict) -> float | None:
    """Wall clock of one execution, or None if it has not finished."""
    start, end = _parse_iso(run.get('created_at')), _parse_iso(run.get('completed_at'))
    if not (start and end):
        return None
    return max(0.0, (end - start).total_seconds())


# Every assumption the report rests on, in one list. The settings panel and
# the sliders on the ROI page both address them by key, and `assumptions` in
# the response is generated from this rather than written out twice — a
# baseline that can drift from the list of what it assumed is worse than no
# list at all.
ROI_INPUTS: tuple[tuple[str, str, str, str], ...] = (
    # key                 field          label                                   unit
    ('ROI_TRIAGE_MIN',    'triage',      'Triage per CVE',                       'min'),
    ('ROI_PREP_MIN',      'prep',        'Change prep per host',                 'min'),
    ('ROI_EXEC_MIN',      'execute',     'Execute & verify per host',            'min'),
    ('ROI_APPROVAL_MIN',  'approval',    'Approval paperwork per gated host',    'min'),
    ('ROI_REWORK_PCT',    'rework_pct',  'Manual attempts needing a redo',       '%'),
    ('ROI_REVIEW_MIN',    'review',      'Operator review per gated host',       'min'),
    ('ROI_HOURLY_RATE',   'rate',        'Fully-loaded hourly rate',             '/h'),
    ('ROI_LEAD_HOURS',    'lead_h',      'Manual time-to-remediation',           'h'),
    ('ROI_SLA_HOURS',     'sla_h',       'Remediation deadline (policy)',        'h'),
    ('ROI_BAND_PCT',      'band_pct',    'Uncertainty on the manual baseline',   '%'),
    ('ROI_PLATFORM_COST', 'platform',    'Platform build cost',                  ''),
)

# What a slider is allowed to send. Not cosmetic: these arrive over HTTP, and
# a negative prep time or a rate of 1e9 would produce a confident, absurd
# number rather than an error.
ROI_LIMITS: dict[str, tuple[float, float]] = {
    'ROI_TRIAGE_MIN': (0, 600), 'ROI_PREP_MIN': (0, 600),
    'ROI_EXEC_MIN': (0, 600), 'ROI_APPROVAL_MIN': (0, 600),
    'ROI_REVIEW_MIN': (0, 600), 'ROI_REWORK_PCT': (0, 100),
    'ROI_HOURLY_RATE': (0, 10000), 'ROI_LEAD_HOURS': (0, 8760),
    'ROI_SLA_HOURS': (0.01, 8760), 'ROI_BAND_PCT': (0, 100),
    'ROI_PLATFORM_COST': (0, 100_000_000),
}


# --------------------------------------------------------------------------
# Published figures — the one part of this page that is neither measured here
# nor assumed here
#
# Everything else in the report is this run's clock or this operator's
# sliders, which is a closed loop: the page sets the baseline and then scores
# itself against it. These are the outside check. They are named reports with
# a publisher, a year and a stated basis, so a reader can go and disagree with
# the source rather than with us.
#
# Static by necessity — the console makes no network calls at runtime, so
# there is no live feed to pull and nothing here refreshes itself. That makes
# the year on every entry load-bearing: these age, and a figure quoted without
# its vintage is the same unlabelled guess this codebase refuses everywhere
# else. Re-check them when a report's next edition lands.
#
# What is deliberately absent: any attempt to multiply the IBM breach cost by
# a probability and book the result as a saving. Nothing on this page claims a
# breach was avoided. The exposure window is stated in hours against a
# deadline, as it is everywhere else in this file, and the money column stays
# labour-only.
# --------------------------------------------------------------------------

ROI_SOURCES: dict[str, dict] = {
    'dbir26': {
        'publisher': 'Verizon',
        'short': 'Verizon DBIR',
        'name': '2026 Data Breach Investigations Report',
        'year': 2026,
        'basis': 'over 22,000 incidents; the vulnerability analysis covers more '
                 'than 13,000 organisations and 527 million vulnerability instances',
        'url': 'https://www.verizon.com/business/resources/reports/dbir/',
    },
    'mtrends26': {
        'publisher': 'Mandiant / Google Cloud',
        'short': 'M-Trends',
        'name': 'M-Trends 2026',
        'year': 2026,
        'basis': 'over 500,000 hours of incident response during 2025',
        'url': 'https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026',
    },
    'ibm26': {
        'publisher': 'IBM / Ponemon Institute',
        'short': 'IBM / Ponemon',
        'name': 'Cost of a Data Breach Report 2026',
        'year': 2026,
        'basis': '602 breached organisations, incidents between March 2025 and '
                 'February 2026',
        'url': 'https://www.ibm.com/reports/data-breach',
    },
    'bod2604': {
        'publisher': 'CISA',
        'short': 'CISA BOD 26-04',
        'name': 'BOD 26-04, Prioritizing Security Updates Based on Risk',
        'year': 2026,
        'basis': 'binding on US federal civilian agencies from 10 June 2026; '
                 'revokes BOD 22-01 and BOD 19-02',
        'url': 'https://www.cisa.gov/news-events/directives/'
               'bod-26-04-prioritizing-security-updates-based-risk',
    },
    'gartner_ir': {
        'publisher': 'Gartner',
        'short': 'Gartner',
        'name': 'Press release, 17 March 2026 — "AI Applications Will Drive 50% '
                'of Cybersecurity Incident Response Efforts by 2028"',
        'year': 2026,
        'basis': 'analyst prediction, not a measurement',
        'url': 'https://www.gartner.com/en/newsroom',
    },
    'gartner_agentic': {
        'publisher': 'Gartner',
        'short': 'Gartner',
        'name': 'Press release, 25 June 2025 — "Over 40% of Agentic AI Projects '
                'Will Be Canceled by End of 2027"',
        'year': 2025,
        'basis': 'analyst prediction, not a measurement',
        'url': 'https://www.gartner.com/en/newsroom',
    },
}

# Ordered: the problem, then how fast it moves, then what it costs, then what
# the deadline actually is. The page renders them in this order.
#
# Two carry a `feature`, which lifts them out of the grid and into a drawing
# of their own. Eight equal boxes is eight facts and no argument — a reader
# scans them and remembers none. The remediation clock and the day-7 ceiling
# are the two that actually make the case, so they get the room to make it and
# the other six support them. The page filters on this key rather than
# hard-coding which two are special, so moving the emphasis is a one-word edit
# here with nothing to change in the frontend.
ROI_BENCHMARKS: tuple[dict, ...] = (
    {'value': '31%', 'metric': 'of breaches start with vulnerability exploitation',
     'source': 'dbir26',
     'detail': 'The leading initial access vector for the first time in the '
               'report’s 19 years, ahead of credential abuse at 13%. '
               'M-Trends puts the same figure at 32% of intrusions, its top '
               'vector for the sixth year running.'},
    {'value': '43 days', 'metric': 'median time to fully remediate',
     'source': 'dbir26', 'feature': 'ruler',
     'detail': 'Up from 32 days the year before. Measured on known-exploited '
               'vulnerabilities — the ones already being used against '
               'somebody.'},
    {'value': '26%', 'metric': 'of KEV-listed vulnerabilities fully remediated',
     'source': 'dbir26',
     'detail': 'Down from 38%. The median organisation carried 16 of them, up '
               'from 11.'},
    {'value': '60–70%', 'metric': 'still open on day 7',
     'source': 'dbir26', 'feature': 'matrix',
     # The midpoint, only so the drawing has a number of dots to fill. The
     # published figure is the range, and the range is what the label says —
     # 65 appears nowhere on the page as a statistic.
     'share': 65,
     'detail': 'Of known-exploited vulnerabilities, a week after they were '
               'found. The figure does not move with organisational maturity, '
               'investment or tooling.',
     'quote': 'a possible theoretical ceiling for human remediation processes',
     'quote_note': 'The report’s own words. It is also the argument for '
                   'automating this work rather than staffing it: the three '
                   'levers an organisation normally pulls have already been '
                   'measured, and none of them move this number.'},
    {'value': '−7 days', 'metric': 'mean time-to-exploit',
     'source': 'mtrends26',
     'detail': 'Negative: on average exploitation now precedes the patch. It was '
               '−1 day in 2024 and 63 days in 2018. Attacker hand-off time '
               'inside an intrusion fell from 8 hours to 22 seconds.'},
    {'value': '3 days', 'metric': 'deadline for the worst class of vulnerability',
     'source': 'bod2604',
     'detail': 'Publicly exposed, in the KEV catalogue, automatable and granting '
               'total control: 3 days plus forensic triage. Lesser combinations '
               'get 3, 15, 30 or 180 days. Set the deadline slider above to '
               'whichever tier you are held to.'},
    {'value': '$1.93M', 'metric': 'lower breach cost with security AI and automation',
     'source': 'ibm26',
     'detail': '$4.00M against $5.93M for organisations using none, and a breach '
               'lifecycle 65 days shorter. Only 36% use them extensively; one in '
               'four have not adopted them at all.'},
    {'value': '$4.99M', 'metric': 'global average cost of a breach',
     'source': 'ibm26',
     'detail': 'A record, up 12% year on year. Quoted for scale only — '
               'nothing on this page claims a breach was avoided, so this figure '
               'is not in any total above.'},
)

# How the industry frames supervised agentic remediation, including the part
# that argues against it. The counterweight is not balance for its own sake:
# a customer who has read the Gartner cancellation note will trust a page that
# raises it first a good deal more than one that hopes they missed it.
ROI_STANCE: tuple[dict, ...] = (
    {'source': 'gartner_ir',
     'text': 'Gartner expects AI applications to drive half of all incident '
             'response effort by 2028, with people supervising and validating '
             'rather than executing. That is the shape of this console: the '
             'agents do the work, the approval gate is where the person is.'},
    {'source': 'gartner_ir',
     'text': 'By 2029 the same note expects 10% of organisations to run '
             'autonomous agents for network security operations with no human '
             'oversight at all, up from under 1% in 2026. This console is '
             'deliberately not that — every host scoring above the review '
             'threshold stops and waits for a person, and the time it spends '
             'waiting is counted against it in the figures above.'},
    {'source': 'gartner_agentic',
     'text': 'The counterweight, from the same analyst: more than 40% of agentic '
             'AI projects will be cancelled by the end of 2027, mostly for '
             'unclear business value and escalating cost. Which is why this page '
             'shows its arithmetic, names every assumption and lets you move '
             'them, rather than leading with a headline multiple.'},
)

# Hours, from the figures above, so the comparisons below are derived from the
# published numbers rather than restating them by hand.
_KEV_MEDIAN_H = 43 * 24           # DBIR 2026 median time to fully remediate
_BOD_FASTEST_H = 3 * 24           # BOD 26-04 Table 1, the top tier


def roi_industry(b: dict, exposure_h: float | None) -> dict:
    """The published figures, plus what they say about *these* sliders.

    The checks run the other way round from the rest of the page. Everywhere
    else the baseline is the yardstick and the run is scored against it; here
    the published median is the yardstick and the baseline is what gets
    scored. That is the useful direction for the one question this report
    cannot answer about itself — whether its manual baseline is fair.
    """
    lead_h, sla_h = b['lead_h'], b['sla_h']
    return {
        'sources': {k: dict(v, id=k) for k, v in ROI_SOURCES.items()},
        'benchmarks': list(ROI_BENCHMARKS),
        'stance': list(ROI_STANCE),
        'checks': {
            'kev_median_h': _KEV_MEDIAN_H,
            'bod_fastest_h': _BOD_FASTEST_H,
            # The manual baseline on this page against the published median.
            # Above 1 the baseline is the *generous* one: it credits the manual
            # path with being faster than the industry manages, and the saving
            # below is therefore understated rather than inflated. Below 1 it
            # is the other way, and the page says so instead of hiding it.
            'baseline_h': lead_h,
            'baseline_x': (round(_KEV_MEDIAN_H / lead_h, 1)
                           if lead_h > 0 else None),
            # Three states, not a boolean. Dragged to exactly the published
            # median — which the slider can now reach, and which is the most
            # defensible setting on the page — a boolean has to round that to
            # one side or the other, and it read as "slower than the industry"
            # for a baseline that was the industry.
            'baseline_rel': ('same' if abs(lead_h - _KEV_MEDIAN_H) < 1
                             else 'faster' if lead_h < _KEV_MEDIAN_H
                             else 'slower'),
            # The deadline slider against the strictest published one, and how
            # far past that deadline the published median actually lands.
            'sla_h': sla_h,
            'sla_vs_bod_h': round(sla_h - _BOD_FASTEST_H, 2),
            'median_over_bod_h': _KEV_MEDIAN_H - _BOD_FASTEST_H,
            # None until something finished, exactly as elsewhere. No ratio is
            # published against it for the same reason the exposure multiplier
            # is absent above: seconds over 43 days is a five-figure number
            # nobody can sanity-check.
            'exposure_h': round(exposure_h, 4) if exposure_h is not None else None,
        },
    }


def roi_baseline(overrides: dict | None = None) -> dict:
    """Resolve the assumptions: module defaults, then this request's sliders.

    Read through the module every time so a settings-panel change takes
    effect, and overlaid per call rather than assigned back — the sliders are
    one operator asking "what if", not a change to what anybody else sees, and
    this server is threaded.
    """
    b = {field: getattr(fallbacks, key) for key, field, _, _ in ROI_INPUTS}
    b['currency'] = fallbacks.ROI_CURRENCY
    for key, field, _, _ in ROI_INPUTS:
        if not overrides or key not in overrides:
            continue
        try:
            value = float(overrides[key])
        except (TypeError, ValueError):
            continue
        if value != value or value in (float('inf'), float('-inf')):
            continue        # NaN and the infinities both survive float()
        low, high = ROI_LIMITS[key]
        b[field] = min(max(value, low), high)
    return b


def roi_effort(cves: int, hosts: int, gated: int, b: dict) -> tuple[dict, dict]:
    """Manual and automated human minutes for a given shape of work.

    One function so the single run, the projection and the lifetime total
    cannot drift apart. Every caller is doing the same arithmetic on different
    counts, and three copies of it would eventually disagree.
    """
    per_host = b['prep'] + b['execute']
    manual = {
        'Triage & risk assessment': b['triage'] * cves,
        'Change prep & playbook': b['prep'] * hosts,
        'Approval paperwork': b['approval'] * gated,
        'Execute & verify': b['execute'] * hosts,
        # A share of the per-host work done twice. Its own line rather than a
        # multiplier folded into the others, so a reader who thinks their team
        # never has to redo one can see exactly what to subtract.
        'Rework after a failed attempt': per_host * hosts * b['rework_pct'] / 100.0,
    }
    # The only human minutes the automated path still spends. Hosts on the
    # unattended branch cost none of it, which is the whole point of the split.
    auto = {'Review & approve': b['review'] * gated}
    return manual, auto


def roi_history(runs: list[dict], b: dict) -> dict:
    """Lifetime total across every execution the run store knows about.

    A single run is a demo number. This is the one that answers "what has it
    actually done for us", and it needs no new assumptions — the same baseline
    applied to a larger count.

    Deliberately conservative about what counts. Only a run that reached
    `patched` is claimed as a saving: a rejected or failed run consumed the
    operator's review time and saved nothing, and a run still in flight has
    not saved anything yet either. AO's execution list cannot tell an approved
    run from a rejected one on the gated branch — both simply complete — so
    those are reported as `unresolved` and left out of the total rather than
    assumed to have gone well. Under-reporting a saving is recoverable;
    over-reporting one is the thing nobody forgives.

    Triage is counted once per distinct CVE, not once per time that CVE was
    dispatched. A CVE picked up again a month later really did cost someone a
    second read of the advisory, so this is an undercount — deliberately, and
    in the same direction as everything else here.
    """
    done = [r for r in runs if r.get('outcome') == 'patched']
    unresolved = [r for r in runs if r.get('outcome') == 'completed']
    pending = [r for r in runs
               if r.get('outcome') in ('awaiting_approval', 'running')]
    lost = [r for r in runs
            if r.get('outcome') in ('failed', 'rejected', 'cancelled', 'timeout',
                                    'unavailable')]

    cves = {r.get('cve_id') for r in done if r.get('cve_id')}
    hosts = len(done)
    gated = sum(1 for r in done if r.get('group') == 'approved_patch')
    manual, auto = roi_effort(len(cves), hosts, gated, b)
    manual_min, auto_min = sum(manual.values()), sum(auto.values())
    saved_min = manual_min - auto_min

    spans = [s for s in (_run_seconds(r) for r in done) if s is not None]
    # First dispatch to last completion. Says "across six weeks" rather than
    # leaving a lifetime total floating with no period attached to it.
    starts = [d for d in (_parse_iso(r.get('created_at')) for r in runs) if d]
    ends = [d for d in (_parse_iso(r.get('completed_at')) for r in runs) if d]
    days = ((max(ends) - min(starts)).total_seconds() / 86400.0
            if starts and ends and max(ends) > min(starts) else None)

    return {
        'runs': len(runs), 'counted': hosts, 'cves': len(cves), 'gated': gated,
        # Each is a reason a run is not in the total. Published so the page can
        # account for the difference instead of leaving a reader to wonder why
        # 40 runs produced a total for 23.
        'unresolved': len(unresolved), 'pending': len(pending), 'lost': len(lost),
        'minutes': round(saved_min, 1),
        'cost': round(saved_min / 60.0 * b['rate'], 2),
        'manual_minutes': round(manual_min, 1),
        'auto_minutes': round(auto_min, 1),
        'machine_hours': round(sum(spans) / 3600.0, 2) if spans else None,
        'span_days': round(days, 1) if days is not None else None,
    }


def roi_report(state: dict, overrides: dict | None = None,
               runs: list[dict] | None = None) -> dict:
    """Compare the dispatched run in `state` against the manual baseline."""
    patch = state.get('patch') or {}
    results = patch.get('results') or []
    if not results:
        raise BackendUnavailable(
            'roi', 'nothing has been dispatched yet',
            'assess a CVE and dispatch the plan first — this compares against '
            'what the run actually did, so it needs a run')

    b = roi_baseline(overrides)
    n = len(results)
    gated = sum(1 for r in results if r.get('group') == 'approved_patch')
    finished = [s for s in (_run_seconds(r) for r in results) if s is not None]
    done = sum(1 for r in results if r.get('outcome') == 'patched')

    # Measured. assess_s is the Supervisor's own stopwatch over agent 1,
    # dispatch_s is agent 2 handing every host to AO.
    assess_s = float(state.get('elapsed_s') or 0)
    dispatch_s = float(patch.get('elapsed_s') or 0)

    # Exposure runs on the host's clock, not the console's: from "we know"
    # to "this one is patched", including whatever time the run spent parked
    # at the gate waiting for a person. It is the slowest host rather than
    # the sum, since the estate does not queue behind one machine.
    #
    # None until something actually gets there. Quoting dispatch_s instead
    # would drop precisely the human wait that dominates this figure, and an
    # exposure window measured with the waiting taken out is not a small
    # overstatement — it is the entire claim, fabricated.
    exposure_s = assess_s + max(finished) if finished else None
    # The same hosts added up instead of overlapped. Both are measured, and
    # the difference between them is the part of the saving that comes from
    # concurrency rather than from speed: by hand these queue behind one
    # engineer, here they ran at once.
    serial_s = assess_s + sum(finished) if finished else None

    manual, auto = roi_effort(1, n, gated, b)
    manual_min, auto_min = sum(manual.values()), sum(auto.values())
    rate = b['rate']
    cost = lambda mins: round(mins / 60.0 * rate, 2)
    saved_min = manual_min - auto_min

    # How the two scale. The manual line climbs with every host; the
    # automated one climbs only with the hosts that stop for a person, and
    # the per-CVE triage is paid once by a machine instead of once by a
    # person. That divergence is the actual argument, and it is worth more
    # than the single-run number above it.
    ratio = gated / n if n else 0
    span = max(25, n * 5)
    step = max(1, round(span / 8))
    # n is forced into the series so the console can anchor the projection to
    # the run actually on screen rather than interpolating near it.
    curve = []
    for k in sorted(set(list(range(1, span + 1, step)) + [n, span])):
        m, a = roi_effort(1, k, round(k * ratio), b)
        curve.append({'hosts': k, 'manual': cost(sum(m.values())),
                      'auto': cost(sum(a.values()))})

    # How wrong the assumptions can be before the conclusion changes. This is
    # the honest answer to "I don't believe your baseline": not a defence of
    # the baseline, but the margin by which it could be wrong and still land
    # in the same place.
    #
    # Note what is absent — there is no break-even on the hourly rate, because
    # there cannot be one. The rate multiplies both sides equally, so it moves
    # the money and never the verdict. Offering a rate slider as though it
    # might change the answer would be theatre.
    per_host = (b['prep'] + b['execute']) * (1 + b['rework_pct'] / 100.0)
    headroom = auto_min - b['triage'] - b['approval'] * gated
    breakeven = {
        # Shrink the whole manual baseline by this much and the two paths cost
        # the same. Usually a number in the high nineties, which is the point.
        'shrink_pct': (round((1 - auto_min / manual_min) * 100, 1)
                       if manual_min else None),
        # Per-host handling time at which doing it by hand breaks even,
        # everything else held. Often negative — meaning no value of it works,
        # because the per-CVE triage alone already costs more than the whole
        # automated path. The page says so in words rather than printing a
        # negative number of minutes.
        'handling_min': (round(headroom / n, 2) if n and headroom > 0 else None),
        'handling_now': round(per_host, 2),
        'rate_independent': True,
    }

    # A point estimate quoted to the cent is making a promise seven guesses
    # cannot keep. The band is applied to the manual side only: the automated
    # side is mostly measured, and its one assumption is small enough that
    # widening it would imply a precision contest that is not the issue.
    band = b['band_pct'] / 100.0
    low_cost, high_cost = cost(manual_min * (1 - band)), cost(manual_min * (1 + band))

    exposure_h = exposure_s / 3600.0 if exposure_s is not None else None
    # Stated against a deadline the organisation already set, rather than
    # converted into money. See ROI_SLA_HOURS in fallbacks.py for why there is
    # no dollar figure on an exposure window anywhere in this file.
    sla = {
        'hours': b['sla_h'],
        'manual_within': b['lead_h'] <= b['sla_h'],
        'manual_over_h': round(max(0.0, b['lead_h'] - b['sla_h']), 2),
        'auto_within': (exposure_h <= b['sla_h']) if exposure_h is not None else None,
        'headroom_pct': (round(100 * (1 - exposure_h / b['sla_h']), 2)
                         if exposure_h is not None and b['sla_h'] else None),
        'hosts': n,
    }

    # The budget question. Marginal saving per host excludes the per-CVE
    # triage, because the next host does not come with another advisory to
    # read — amortising triage across hosts would flatter the figure on
    # exactly the estates where it matters least.
    marginal = (manual_min - b['triage'] - auto_min) / n if n else 0
    marginal_cost = marginal / 60.0 * rate
    lifetime = roi_history(runs, b) if runs else None
    recovered = (lifetime or {}).get('cost') or 0
    payback = {
        'platform_cost': b['platform'],
        'per_host': round(marginal_cost, 2),
        'hosts': (math.ceil(b['platform'] / marginal_cost)
                  if marginal_cost > 0 and b['platform'] > 0 else None),
        'recovered': round(recovered, 2),
        'recovered_pct': (round(min(100.0, recovered / b['platform'] * 100), 1)
                          if b['platform'] > 0 else None),
    }

    # Whether the measured half of this page describes patching. There are two
    # ways it does not, and they are different enough that the console has to
    # say which: offline, the clocks are DEMO_LATENCY rather than work; live
    # with AO unreachable, the clocks are real wall time, but what they timed
    # is this console failing over and the fallback standing in, not a host
    # being patched.
    #
    # Reading offline() alone was the one break in this file's labelling
    # chain. A live run with every backend down produced host results each
    # carrying simulated: true and an ROI page that quoted a saving with no
    # caveat anywhere on it — precisely the unlabelled guess the rest of this
    # codebase refuses to print.
    sim = sum(1 for r in results if r.get('simulated'))
    reason = 'offline' if offline() else ('simulated' if sim else None)

    return {
        'cve_id': state.get('cve_id'),
        # Set when the measured half did not come from patching anything.
        # The console leads with this; without it the page would be claiming a
        # timing it did not take.
        'illustrative': reason is not None,
        # Which of the two, because they need different words on the page.
        # None when the timings are a straight measurement.
        'illustrative_reason': reason,
        'measured': {
            'hosts': n, 'gated': gated, 'auto_branch': n - gated, 'patched': done,
            'assess_s': round(assess_s, 1),
            'dispatch_s': round(dispatch_s, 1),
            'exposure_s': round(exposure_s, 1) if exposure_s is not None else None,
            'serial_s': round(serial_s, 1) if serial_s is not None else None,
            'host_s': [round(s, 1) for s in finished],
            # How many hosts the timings actually cover. Live, a run that has
            # not finished has no completed_at to read, so the durations
            # describe a subset — and a page that quietly averaged over
            # whatever it happened to have would be the kind of silent
            # degradation this codebase labels everywhere else.
            'timed': len(finished),
            # How many of them nothing actually patched. A count rather than a
            # flag because a run can be mixed: the breaker re-probes every
            # CIRCUIT_TTL, so AO can come back partway through a host list and
            # the later hosts are then genuinely dispatched.
            'simulated': sim,
        },
        'manual': {'breakdown': manual, 'minutes': round(manual_min, 1),
                   'cost': cost(manual_min),
                   'cost_low': low_cost, 'cost_high': high_cost,
                   'lead_hours': b['lead_h']},
        'auto': {'breakdown': auto, 'minutes': round(auto_min, 1),
                 'cost': cost(auto_min),
                 'lead_hours': round(exposure_h, 4) if exposure_h is not None else None},
        'saved': {
            'minutes': round(saved_min, 1),
            'cost': cost(saved_min),
            'cost_low': round(low_cost - cost(auto_min), 2),
            'cost_high': round(high_cost - cost(auto_min), 2),
            # Guarded: every host on the unattended branch makes auto_min 0,
            # and that is the good case, not a divide-by-zero.
            'effort_x': round(manual_min / auto_min, 1) if auto_min else None,
            # No exposure multiplier is published on purpose. Seconds against
            # a three-day baseline divides out to five figures, which is a
            # number nobody can sanity-check and which rests entirely on the
            # assumed side. The two durations and the hours avoided say the
            # same thing and can be argued with.
            'exposure_hours': (round(b['lead_h'] - exposure_h, 2)
                               if exposure_h is not None else None),
        },
        'curve': curve,
        'breakeven': breakeven,
        'sla': sla,
        # Recomputed per request rather than attached once, because two of its
        # comparisons read the sliders: move the manual baseline and the
        # "against the published median" line has to move with it.
        'industry': roi_industry(b, exposure_h),
        'payback': payback,
        'lifetime': lifetime,
        'band_pct': b['band_pct'],
        'currency': b['currency'],
        'rate': rate,
        # Itemised from ROI_INPUTS so the page can show what it assumed rather
        # than asserting a total. Each carries its settings key and its limits,
        # which is what lets the sliders exist at all: 'change it and look
        # again' is a real offer and not a figure of speech.
        'assumptions': [
            {'key': key, 'label': label, 'value': b[field],
             'unit': b['currency'] if unit == '' else
                     b['currency'] + unit if unit == '/h' else unit,
             'min': ROI_LIMITS[key][0], 'max': ROI_LIMITS[key][1]}
            for key, field, label, unit in ROI_INPUTS
        ],
    }


# ==========================================================================
# SETTINGS — one registry describing every tunable this process reads
#
# Scope is deliberately "what this process reads", not "everything in
# .env.example". NAMESPACE, GIT_HUB_TOKEN, the AAP_* and VLLM_* keys belong to
# ao-setup/ and rag-setup/, which are separate shell scripts; offering them
# here would imply changing them does something, and it would not.
#
# Two things make this more than a dict of env vars:
#
#   - Most of these were read once at import into a module global, so writing
#     os.environ alone changes nothing. Each Setting names the global it feeds
#     (`binds`) and apply() rebinds it. Functions look up globals at call time,
#     so a rebind takes effect on the next call.
#   - Overrides live in this process only. Writing them back to .env would
#     mean rewriting a hand-maintained file full of comments and credentials,
#     so the panel says plainly that .env is the durable place.
# ==========================================================================

@dataclass(frozen=True)
class Setting:
    key: str
    group: str
    label: str
    kind: str                     # str | int | float | bool | choice
    default: str                  # the built-in default, as the env would give it
    help: str = ''
    choices: tuple[str, ...] = ()
    secret: bool = False          # never leaves the process; write-only
    readonly: bool = False        # shown for completeness, cannot take effect
    binds: str = ''               # module global to rebind, '' if read per call


SETTINGS: tuple[Setting, ...] = (
    # --- mode -------------------------------------------------------------
    # One switch, two ends. The middle ground — real endpoints with per-step
    # fallback — was four settings deep and produced the one outcome nobody
    # wants: a patch plan that looks measured but is partly stored defaults.
    Setting('MODE', 'Mode', 'Mode', 'choice', 'demo',
            'demo: every step runs on staged data and no endpoint is '
            'contacted, so the whole flow can be shown without Insights, the '
            'risk model, the RAG store or Ansible Orchestrator. '
            'live: real endpoints only, with no fallback anywhere — if a '
            'service cannot be reached the run fails and names it, because a '
            'patch plan is what a human approves a production change '
            'against.',
            choices=('demo', 'live')),

    # --- ROI --------------------------------------------------------------
    # The manual baseline is guesswork by construction, so every input to it
    # is exposed. Someone who disagrees with the comparison can change the
    # number they disagree with and press the button again, which is a more
    # useful answer than arguing about the total.
    Setting('ROI_TRIAGE_MIN', 'ROI baseline', 'Manual triage per CVE', 'float', '45',
            'Read the advisory, pull the affected host list, judge the '
            'exposure. Once per CVE, not per host.',
            binds='fallbacks.ROI_TRIAGE_MIN'),
    Setting('ROI_PREP_MIN', 'ROI baseline', 'Manual change prep per host', 'float', '15',
            'Adapt the playbook, raise the change record, book the window.',
            binds='fallbacks.ROI_PREP_MIN'),
    Setting('ROI_EXEC_MIN', 'ROI baseline', 'Manual execute & verify per host',
            'float', '10',
            'Run it, watch it, confirm the service came back.',
            binds='fallbacks.ROI_EXEC_MIN'),
    Setting('ROI_APPROVAL_MIN', 'ROI baseline', 'Manual approval per gated host',
            'float', '20',
            'Assembling the request and chasing the approver. On top of prep, '
            'and only for hosts that need sign-off.',
            binds='fallbacks.ROI_APPROVAL_MIN'),
    Setting('ROI_REVIEW_MIN', 'ROI baseline', 'Operator review per gated host',
            'float', '2',
            'What the automated path still costs a person: read the plan, '
            'judge the score, press Approve. Counted against the automation.',
            binds='fallbacks.ROI_REVIEW_MIN'),
    Setting('ROI_HOURLY_RATE', 'ROI baseline', 'Fully-loaded hourly rate', 'float', '85',
            'Fully loaded, not salary.', binds='fallbacks.ROI_HOURLY_RATE'),
    Setting('ROI_CURRENCY', 'ROI baseline', 'Currency symbol', 'str', '$',
            'Display only — no conversion is done.', binds='fallbacks.ROI_CURRENCY'),
    Setting('ROI_LEAD_HOURS', 'ROI baseline', 'Manual time-to-remediation', 'float', '72',
            'Elapsed hours from "this CVE is ours" to "this host is patched" '
            'by hand. Wall clock, not effort — mostly queueing and waiting '
            'for a window, which is why it dwarfs the labour figures.',
            binds='fallbacks.ROI_LEAD_HOURS'),
    Setting('ROI_REWORK_PCT', 'ROI baseline', 'Manual attempts needing a redo',
            'float', '12',
            'Share of hosts that have to be patched twice by hand — the patch '
            'does not take, the window is lost, the booking repeats. Manual '
            'side only: an automated run that fails never reaches patched, so '
            'it is dropped from the lifetime total rather than estimated.',
            binds='fallbacks.ROI_REWORK_PCT'),
    Setting('ROI_BAND_PCT', 'ROI baseline', 'Uncertainty on the baseline',
            'float', '30',
            'How wrong the manual baseline might be, either way. The page '
            'quotes a range beside the point figure, because an estimate '
            'built from seven guesses should not be given to the cent.',
            binds='fallbacks.ROI_BAND_PCT'),
    Setting('ROI_SLA_HOURS', 'ROI baseline', 'Remediation deadline (policy)',
            'float', '48',
            'The deadline this organisation holds itself to. Policy, not '
            'physics — set it to yours. Exposure is stated against this '
            'rather than converted into money.',
            binds='fallbacks.ROI_SLA_HOURS'),
    Setting('ROI_PLATFORM_COST', 'ROI baseline', 'Platform build cost', 'float',
            '25000',
            'One off: the build, the integration work, the cluster. The '
            'weakest assumption here, and the first question anyone with a '
            'budget asks. Set it to 0 to hide the payback card.',
            binds='fallbacks.ROI_PLATFORM_COST'),

    # --- triage -----------------------------------------------------------
    Setting('REVIEW_THRESHOLD', 'Triage', 'Review threshold', 'float', '30',
            'Risk score above which a host needs operator approval. This is '
            'the model\'s scale, so it is the gate for every live run. Demo '
            'runs score with a heuristic on a different scale and gate on a '
            'constant beside it in fallbacks.py.',
            binds='REVIEW_THRESHOLD'),
    Setting('PATCHED_WITHIN_MINUTES', 'Triage', 'Skip hosts patched within',
            'int', '10080',
            'Live mode only. A host patched for this CVE inside this window '
            'is left out of a re-assessment, so the plan only lists '
            'outstanding work. 10080 is seven days. Demo mode ignores this '
            'and always re-assesses every host, because a demo is the same '
            'CVE run repeatedly and the guard would empty the second run.',
            binds='PATCHED_WITHIN_MINUTES'),
    Setting('HOSTS_FILTER', 'Triage', 'Host filter', 'str', '',
            'Restrict an assessment to hosts whose name contains this.'),
    Setting('HOSTS_LIMIT', 'Triage', 'Host limit', 'int', '0',
            'Cap the number of hosts assessed. 0 means no cap.'),
    Setting('MAINTENANCE_WINDOW', 'Triage', 'Maintenance window', 'str', '',
            f'Reported in the patch plan. Empty uses {DEFAULT_WINDOW!r}.',
            binds='MAINTENANCE_WINDOW'),
    Setting('MAX_ATTEMPTS_PER_HOST', 'Triage', 'Max attempts per host', 'int', '2',
            'Supervisor guard for the self-healing loop (agent 2, not wired up yet).',
            binds='Supervisor.MAX_ATTEMPTS_PER_HOST'),
    Setting('MAX_FAILED_PER_PHASE', 'Triage', 'Max failures per phase', 'int', '2',
            'Supervisor guard for the self-healing loop (agent 2, not wired up yet).',
            binds='Supervisor.MAX_FAILED_PER_PHASE'),

    # --- timeouts ---------------------------------------------------------
    Setting('CONNECT_TIMEOUT', 'Timeouts', 'Connect (reachability)', 'float', '3',
            'TCP budget per service, separate from the read budgets. A stopped '
            'pod leaves its Route resolving with nothing behind it.',
            binds='CONNECT_TIMEOUT'),
    Setting('CIRCUIT_TTL', 'Timeouts', 'Circuit breaker TTL', 'int', '30',
            'How long a service stays tripped after failing, so a dead backend '
            'costs one probe per run rather than one per host.',
            binds='CIRCUIT_TTL'),
    Setting('INSIGHTS_TIMEOUT', 'Timeouts', 'Insights read', 'int', '15',
            '', binds='INSIGHTS_TIMEOUT'),
    Setting('RISK_TIMEOUT', 'Timeouts', 'Risk model read', 'int', '8',
            '', binds='RISK_TIMEOUT'),
    Setting('RAG_TIMEOUT', 'Timeouts', 'RAG read', 'int', '20',
            'Live RAG does LLM summarisation, so this one is generous.',
            binds='RAG_TIMEOUT'),
    Setting('RAG_WORKERS', 'Timeouts', 'RAG lookups in parallel', 'int', '8',
            'History lookups in flight at once. Every host that needs review '
            'is still looked up — this caps concurrency, not coverage. Raise '
            'it if assessments are slow and the model server has headroom; '
            'lower it to 1 for one-at-a-time behaviour.',
            binds='RAG_WORKERS'),
    Setting('AO_TIMEOUT', 'Timeouts', 'Ansible Orchestrator read', 'int', '10',
            '', binds='AO_TIMEOUT'),
    Setting('HTTP_TIMEOUT', 'Timeouts', 'Global HTTP ceiling', 'int', '120',
            'Upper bound; the per-service budgets above sit well below it.',
            binds='HTTP_TIMEOUT'),
    Setting('AO_POLL_TIMEOUT', 'Timeouts', 'AO poll', 'int', '900',
            'How long to follow a dispatched execution.', binds='AO_POLL_TIMEOUT'),
    Setting('AO_DECIDE_WAIT', 'Timeouts', 'AO settle after decision', 'int', '90',
            'Seconds to wait for a run to reach a terminal status after '
            'approve or reject.'),
    Setting('DEMO_LATENCY', 'Timeouts', 'Demo pause per step', 'float', '0.35',
            'Offline only. Answering instantly renders as "complete in 0s" and '
            'reads as broken. 0 disables.', binds='DEMO_LATENCY'),

    # --- insights ---------------------------------------------------------
    Setting('INSIGHTS_REST_BASE_URL', 'Insights', 'REST base URL', 'str',
            'https://console.redhat.com/api', '', binds='INSIGHTS_API'),
    Setting('INSIGHTS_VERIFY_TLS', 'Insights', 'Verify TLS', 'bool', 'true',
            'Turn off if this machine cannot verify the sso.redhat.com chain.',
            binds='INSIGHTS_VERIFY_TLS'),
    Setting('LIGHTSPEED_CLIENT_ID', 'Insights', 'Client ID', 'str', '',
            'Lightspeed service account.'),
    Setting('LIGHTSPEED_CLIENT_SECRET', 'Insights', 'Client secret', 'str', '',
            'Write-only. Leave blank to keep the current value.', secret=True),

    # --- risk model -------------------------------------------------------
    Setting('RISK_URL', 'Risk model', 'Predict URL', 'str', '',
            'KServe endpoint, .../v1/models/risk-score:predict. Unset falls '
            'back to the heuristic.', binds='RISK_URL'),
    Setting('RISK_VERIFY_TLS', 'Risk model', 'Verify TLS', 'bool', 'true',
            'Turn off for sandbox cluster certificates.', binds='RISK_VERIFY_TLS'),

    # --- RAG --------------------------------------------------------------
    Setting('LLAMA_STACK_URL', 'RAG', 'Llama Stack URL', 'str', '',
            '', binds='LLAMA_URL'),
    Setting('VECTOR_DB_ID', 'RAG', 'Vector store ID', 'str', '',
            'The vs_... that rag-setup/ingest.py --ensure prints. A Llama Stack '
            'restart empties the registry, so re-run ingest and re-set this.',
            binds='VECTOR_DB_ID'),
    Setting('DEFAULT_LLM_MODEL', 'RAG', 'Summarisation model', 'str',
            'vllm-inference/llama-scout-17b', '', binds='LLM_MODEL'),

    # --- Ansible Orchestrator --------------------------------------------
    Setting('AO_URL', 'Ansible Orchestrator', 'Base URL', 'str', '',
            '', binds='AO_URL'),
    Setting('AO_USERNAME', 'Ansible Orchestrator', 'Username', 'str', '',
            '', binds='AO_USERNAME'),
    Setting('AO_PASSWORD', 'Ansible Orchestrator', 'Password', 'str', '',
            'Write-only. Leave blank to keep the current value.',
            secret=True, binds='AO_PASSWORD'),
    Setting('AO_WORKFLOW_NAME', 'Ansible Orchestrator', 'Workflow name', 'str',
            'DemoJam Agentic Patching',
            'The workflow that owns steps 5-10.', binds='AO_WORKFLOW_NAME'),
    Setting('AO_TRIGGER_NODE', 'Ansible Orchestrator', 'Trigger node', 'str',
            'trigger_manual', '', binds='AO_TRIGGER_NODE'),
    Setting('LAB_TAG', 'Ansible Orchestrator', 'Lab tag', 'str', '',
            'Passed to the workflow as lab_tag.', binds='LAB_TAG'),

    # --- server -----------------------------------------------------------
    Setting('BACKEND_HOST', 'Server', 'Bind host', 'str', '127.0.0.1',
            'Set on the command line; the socket is already open.', readonly=True),
    Setting('BACKEND_PORT', 'Server', 'Bind port', 'int', '8787',
            'Set on the command line; the socket is already open.', readonly=True),
)

SETTINGS_BY_KEY = {s.key: s for s in SETTINGS}

# What each key resolved to at startup, before anything was changed here.
# Reverting restores this rather than the built-in default: if .env supplied a
# RISK_URL, "revert" should give it back, not blank it.
_BASELINE: dict[str, str] = {s.key: env(s.key, s.default) for s in SETTINGS}

# Keys changed through this panel since the process started.
_OVERRIDDEN: set[str] = set()


def _coerce(s: Setting, raw: str) -> Any:
    """Parse a form value the way the module-level constant was parsed."""
    raw = (raw or '').strip()
    if s.kind == 'bool':
        # Matches env_bool: anything not in the falsey set is true, and empty
        # means "use the default".
        return bool(s.default and s.default.lower() not in {'0', 'false', 'no'}) \
            if not raw else raw.lower() not in {'0', 'false', 'no'}
    if s.kind == 'int':
        return int(float(raw or s.default or '0'))
    if s.kind == 'float':
        return float(raw or s.default or '0')
    if s.kind == 'choice' and raw and raw not in s.choices:
        raise ValueError(f'{s.key} must be one of {", ".join(s.choices)}')
    return raw


def _rebind(s: Setting, raw: str) -> None:
    """Push a value into the live binding named by `binds`.

    Plain names are module globals here; dotted ones are an attribute on
    something in this module's namespace, such as a class attribute
    (Supervisor.MAX_ATTEMPTS_PER_HOST).
    """
    if not s.binds:
        return                      # read fresh from os.environ on every use
    value = _coerce(s, raw)
    if s.kind == 'str' and not raw:
        value = s.default
    if '.' in s.binds:
        owner, attr = s.binds.split('.', 1)
        setattr(globals()[owner], attr, value)
        return
    globals()[s.binds] = value
    # VULN_API is derived, so it has to follow its source.
    if s.binds == 'INSIGHTS_API':
        globals()['VULN_API'] = f'{str(value).rstrip("/")}/vulnerability/v1'


def settings_state() -> list[dict[str, Any]]:
    """Current value of every setting, with where it came from.

    `source` is the honest version of "modified": default means the built-in,
    env means .env or the environment set it before this process started, and
    override means it was changed here.
    """
    out = []
    for s in SETTINGS:
        value, default = env(s.key, s.default), s.default
        if s.kind == 'bool':
            # Normalise both sides to true/false here rather than leaving the
            # UI to reimplement env_bool's "empty means the default" rule.
            value = 'true' if _coerce(s, value) else 'false'
            default = 'true' if _coerce(s, s.default) else 'false'
        if s.key in _OVERRIDDEN:
            source = 'override'
        elif value != default:
            source = 'env'
        else:
            source = 'default'
        out.append({
            'key': s.key, 'group': s.group, 'label': s.label, 'kind': s.kind,
            'default': default, 'help': s.help, 'choices': list(s.choices),
            'secret': s.secret, 'readonly': s.readonly, 'source': source,
            # A secret's value never leaves the process — only whether one is set.
            'value': '' if s.secret else value,
            'is_set': bool(value) if s.secret else None,
        })
    return out


def settings_update(changes: dict[str, Any]) -> list[str]:
    """Validate everything, then apply. Returns the keys that changed.

    Validate-then-apply so a bad number in the last field cannot leave the
    first half of the form applied and the rest not.
    """
    staged: list[tuple[Setting, str]] = []
    for key, raw in changes.items():
        s = SETTINGS_BY_KEY.get(key)
        if s is None:
            raise ValueError(f'unknown setting {key!r}')
        if s.readonly:
            continue
        raw = '' if raw is None else str(raw).strip()
        # A blank secret means "leave it alone", so the form can be saved
        # without retyping credentials it was never shown.
        if s.secret and not raw:
            continue
        if raw == env(s.key, s.default):
            continue
        _coerce(s, raw)             # raises on a bad value, before anything moves
        staged.append((s, raw))

    for s, raw in staged:
        if raw:
            os.environ[s.key] = raw
        else:
            os.environ.pop(s.key, None)
        _rebind(s, raw)
        _OVERRIDDEN.add(s.key)
    changed = [s.key for s, _ in staged]
    if any(k in ('MODE', 'AO_URL', 'INSIGHTS_API') for k in changed):
        forget_credentials()
    return changed


def forget_credentials() -> None:
    """Drop cached tokens and breaker state. Called when the target changes.

    A bearer token is scoped to the endpoint that issued it and to the mode
    the console was in when it asked, so it must not survive a switch of
    either — and a breaker recording "AO is down" says nothing about the AO
    that is now configured.
    """
    _token.clear()
    _ao_token.clear()
    degraded_reset()


def settings_revert() -> list[str]:
    """Restore every setting to what it was when the process started."""
    reverted = []
    for key in sorted(_OVERRIDDEN):
        s = SETTINGS_BY_KEY[key]
        raw = _BASELINE[key]
        if raw:
            os.environ[key] = raw
        else:
            os.environ.pop(key, None)
        _rebind(s, raw)
        reverted.append(key)
    _OVERRIDDEN.clear()
    if reverted:
        forget_credentials()
    return reverted


# ==========================================================================
# HTTP server — what the console UI talks to
#
# frontend/server.py proxies /api/start and /api/state here, so the UI can
# drive the Supervisor. A run takes ~20s, which is longer than that proxy's
# read timeout, so /api/start returns immediately and the UI polls /api/state.
# ==========================================================================

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_RUN: dict[str, Any] = {'status': 'idle', 'events': []}
_RUN_LOCK = threading.Lock()


def _run_async(cve_id: str, host_filter: str, host_limit: int) -> None:
    sup = Supervisor(verbose=False)

    def trace(src: str, dst: str, message: str) -> None:
        Supervisor.trace(sup, src, dst, message)
        with _RUN_LOCK:
            _RUN['events'] = list(sup.events)

    sup.trace = trace            # stream the trace while the run is in flight
    sup.info = InfoAgent(trace=trace)
    try:
        state = sup.run(cve_id, host_filter=host_filter, host_limit=host_limit)
        with _RUN_LOCK:
            # 'complete' here means the background job finished, which is a
            # different axis from what the Supervisor concluded — the console
            # polls on it to know the assessment is done. Preserving the
            # Supervisor's own status instead left it on
            # 'awaiting_patch_dispatch' forever, so the plan never rendered
            # and Assess appeared to hang. What the run concluded is carried
            # by plan.verdict and already_patched, which is where the console
            # reads it from anyway.
            _RUN.update(state, status='complete', error=None)
    except BackendUnavailable as exc:
        with _RUN_LOCK:
            _RUN.update(status='failed', cve_id=cve_id, events=list(sup.events),
                        error={'service': exc.service, 'detail': str(exc.cause),
                               'fix': exc.fix})
    except Exception as exc:
        with _RUN_LOCK:
            _RUN.update(status='failed', cve_id=cve_id, events=list(sup.events),
                        error={'service': 'supervisor', 'detail': str(exc), 'fix': ''})


def _patch_async(assessment: dict) -> None:
    sup = Supervisor(verbose=False)

    def trace(src: str, dst: str, message: str) -> None:
        Supervisor.trace(sup, src, dst, message)
        with _RUN_LOCK:
            _RUN['events'] = list(sup.events)

    sup.trace = trace
    sup.patching = PatchingAgent(trace=trace)
    try:
        state = sup.patch(assessment)
        with _RUN_LOCK:
            _RUN.update(state, status='complete', phase='patching', error=None)
    except BackendUnavailable as exc:
        with _RUN_LOCK:
            _RUN.update(status='failed', phase='patching', events=list(sup.events),
                        error={'service': exc.service, 'detail': str(exc.cause),
                               'fix': exc.fix})
    except Exception as exc:
        with _RUN_LOCK:
            _RUN.update(status='failed', phase='patching', events=list(sup.events),
                        error={'service': 'patching', 'detail': str(exc), 'fix': ''})


def _rereport(state: dict) -> dict | None:
    """Re-run agent 3 once a decision has changed the picture.

    The diagram has the Communication Agent firing at pause, abandon and
    completion. The first report is written at dispatch, when hosts are still
    at the gate; without this the PDF would keep saying "awaiting approval"
    long after every host had been approved.
    """
    results = (state.get('patch') or {}).get('results') or []
    if not results:
        return None
    summary = {
        'patched': sum(1 for r in results if r.get('outcome') == 'patched'),
        'awaiting_approval': sum(1 for r in results
                                 if r.get('outcome') == 'awaiting_approval'),
        'rejected': sum(1 for r in results if r.get('outcome') == 'rejected'),
        'failed': sum(1 for r in results
                      if r.get('outcome') in ('failed', 'timeout')),
        'unavailable': sum(1 for r in results if r.get('outcome') == 'unavailable'),
    }
    state['patch'] = {**state['patch'], 'summary': summary}
    nxt = next_step(summary)
    with _RUN_LOCK:
        _RUN['patch'] = state['patch']
        _RUN['next'] = nxt

    # Only at the events the diagram names. Writing one per decision turned a
    # five-host run into six near-identical PDFs; the intermediate ones say
    # nothing the final one does not. The counts still move on every decision,
    # though — returning nothing here left "your approval on 5 hosts" on
    # screen after four of the five had been approved.
    if summary['awaiting_approval'] > 0:
        return {'next': nxt}

    agent = communication.CommunicationAgent(
        REPORTS_DIR, simulated=any(r.get('simulated') for r in results))
    try:
        report = agent.report(state)
    except Exception as exc:                 # never fail a decision over a PDF
        report = {'error': str(exc)}

    # Agent 4 runs at the same point: only now are the hosts settled, so only
    # now is there an outcome worth feeding back.
    try:
        published = results_mod.ResultsAgent(RAG_DATA_DIR, TRAINING_DIR).publish(state)
    except Exception as exc:
        published = {'error': str(exc)}

    with _RUN_LOCK:
        _RUN['report'] = report
        _RUN['published'] = published
        _RUN['next'] = next_step(summary)
    # Both, because the console keeps its own copy of the run: returning only
    # the report left the agent-4 panel showing "no settled hosts yet" beside
    # a report that said the remediation was complete.
    return {'report': report, 'published': published,
            'next': next_step(summary)}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, payload: Any) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path.rstrip('/') or '/'
        if path == '/healthz':
            self._send(200, {'ok': True})
        elif path == '/api/state':
            with _RUN_LOCK:
                self._send(200, dict(_RUN))
        elif path == '/api/reports':
            agent = communication.CommunicationAgent(REPORTS_DIR)
            self._send(200, {'ok': True, 'reports': agent.recent()})
        elif path == '/api/report':
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            name = (q.get('file') or [''])[0]
            # Resolve and confirm containment rather than trusting the name.
            # '..%2F' survives parse_qs, so a prefix check on the raw string
            # is not enough.
            try:
                target = (REPORTS_DIR / name).resolve()
                target.relative_to(REPORTS_DIR.resolve())
            except (ValueError, OSError):
                self._send(400, {'ok': False, 'error': 'invalid report name'})
                return
            if target.suffix != '.pdf' or not target.is_file():
                self._send(404, {'ok': False, 'error': 'report not found'})
                return
            body = target.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'application/pdf')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Content-Disposition',
                             f'inline; filename="{target.name}"')
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        elif path == '/api/mode':
            # Read once at page load to decide whether to show the top banner.
            # `offline` stays in the payload whatever label_sources says: it
            # is the truth about the run, and a client that wants it — or an
            # operator reading the API by hand — gets it either way. What the
            # flag decides is only whether the page draws it.
            self._send(200, {
                'ok': True,
                'mode': 'demo' if demo_mode() else 'live',
                # Kept so an existing client does not break, and because they
                # are still the truth about the run even though they are no
                # longer separately settable.
                'offline': offline(),
                'strict': fallbacks.strict(),
                'label_sources': label_sources(),
                'workflow': AO_WORKFLOW_NAME,
            })
        elif path == '/api/settings':
            self._send(200, {'ok': True, 'settings': settings_state(),
                             'persisted': False})
        elif path == '/api/cves':
            # C1 lives here, not in the frontend. The frontend used to call
            # Insights itself, which meant the CVE list was the one step with
            # no fallback — the console came up empty instead of degraded.
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            try:
                degraded_reset()
                payload = fetch_cve_list(
                    limit=min(int((q.get('limit') or ['20'])[0]), 50),
                    offset=max(0, int((q.get('offset') or ['0'])[0])))
                self._send(200, {'ok': True, **payload,
                                 'degraded_steps': [dict(d) for d in DEGRADED]})
            except BackendUnavailable as exc:
                self._send(502, {'ok': False, 'error': f'{exc.service}: {exc.cause}',
                                 'detail': exc.fix})
        elif path == '/api/roi':
            self._roi()
        elif path == '/api/runs':
            # Live from AO, so a run that failed after the console stopped
            # polling still shows its real status here.
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            agent = PatchingAgent()
            try:
                if q.get('execution_id'):
                    self._send(200, {'ok': True,
                                     'run': agent.run_detail(q['execution_id'][0])})
                else:
                    limit = int((q.get('limit') or ['40'])[0])
                    runs = agent.recent_runs(limit)
                    self._send(200, {'ok': True, 'runs': runs,
                                     'workflow': AO_WORKFLOW_NAME,
                                     'degraded': agent.runs_degraded})
            except BackendUnavailable as exc:
                self._send(502, {'ok': False, 'error': f'{exc.service}: {exc.cause}',
                                 'detail': exc.fix})
        else:
            self._send(404, {'ok': False, 'error': 'not found'})

    def _roi(self, overrides: dict | None = None) -> None:
        """The ROI report, for GET and for the sliders alike.

        Computed on demand rather than stored on the run: the baseline is
        settings-driven, so the answer has to track the assumptions as they
        are now, not as they were when the run was dispatched.
        """
        with _RUN_LOCK:
            snapshot = dict(_RUN)
        # The lifetime total wants the whole run store, which means AO. That
        # is a different backend from the one the rest of this report needs,
        # so it fails on its own terms: a lifetime figure we cannot read is a
        # missing card, not a failed button. The per-run comparison beside it
        # is unaffected and still answers the question that was asked.
        agent = PatchingAgent()
        try:
            runs = agent.recent_runs(200)
        except BackendUnavailable as exc:
            runs, agent.runs_degraded = [], f'{exc.service}: {exc.cause}'
        try:
            report = roi_report(snapshot, overrides, runs)
        except BackendUnavailable as exc:
            self._send(409, {'ok': False, 'error': str(exc.cause),
                             'detail': exc.fix})
            return
        if report.get('lifetime') and agent.runs_degraded and not offline():
            # Partial history still counts, but it has to say it is partial —
            # a lifetime total quietly missing every run AO could not return
            # is the understatement that gets discovered later.
            #
            # Not offline, though. There the simulator is the whole history,
            # not a degraded view of a real one, and the page already carries
            # a banner saying every value on it is stored. Repeating it here
            # would claim runs are missing when none are.
            report['lifetime']['degraded'] = agent.runs_degraded
        self._send(200, {'ok': True, 'roi': report})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path.rstrip('/') or '/'

        if path == '/api/roi':
            # Same report, with this operator's sliders applied for this
            # request only. Nothing is written: a what-if is one person
            # asking a question, not a change to what anyone else sees, and
            # this server answers several requests at once.
            length = int(self.headers.get('Content-Length', '0') or '0')
            try:
                payload = json.loads(self.rfile.read(length) or b'{}')
            except Exception:
                payload = {}
            self._roi(payload.get('overrides') or {})
            return

        if path == '/api/patch':
            # Agent 2. Needs a completed assessment to know each host's
            # decision, which is what selects the workflow branch.
            with _RUN_LOCK:
                snapshot = dict(_RUN)
            if snapshot.get('status') == 'running':
                self._send(409, {'ok': False, 'error': 'a run is already in flight'})
                return
            if not snapshot.get('hosts'):
                # Two very different reasons to have no hosts, and telling an
                # operator to assess a CVE they have just assessed is the
                # wrong one.
                skipped = snapshot.get('already_patched') or []
                self._send(409, {
                    'ok': False,
                    'error': ('Nothing to patch' if skipped
                              else 'No assessment available'),
                    'detail': (f'All {len(skipped)} affected host(s) were already '
                               f'patched for {snapshot.get("cve_id")} within the '
                               f'last {human_window(patched_window())}.' if skipped else
                               'Run "Assess CVE Impact" first — the Patching Agent '
                               'needs each host\'s decision to pick a workflow branch.')})
                return
            with _RUN_LOCK:
                _RUN.update(status='running', phase='patching', error=None)
            threading.Thread(target=_patch_async, args=(snapshot,),
                             daemon=True, name='patching').start()
            self._send(200, {'ok': True, 'cve': snapshot.get('cve_id'),
                             'status': 'running'})
            return

        if path == '/api/settings':
            # Overrides are process-local and take effect on the next call
            # that reads them — no restart, but nothing is written to .env.
            length = int(self.headers.get('Content-Length', '0') or '0')
            try:
                p = json.loads(self.rfile.read(length) or b'{}')
            except Exception:
                p = {}
            try:
                if p.get('revert'):
                    changed = settings_revert()
                else:
                    changed = settings_update(p.get('settings') or {})
            except (ValueError, TypeError) as exc:
                self._send(400, {'ok': False, 'error': str(exc)})
                return
            self._send(200, {'ok': True, 'changed': changed,
                             'settings': settings_state()})
            return

        if path == '/api/decide':
            # Approve / reject a paused gate. Synchronous: the caller is a
            # button click and wants the resulting state back.
            length = int(self.headers.get('Content-Length', '0') or '0')
            try:
                p = json.loads(self.rfile.read(length) or b'{}')
            except Exception:
                p = {}
            exec_id = (p.get('execution_id') or '').strip()
            act_id = (p.get('activity_id') or '').strip()
            decision = (p.get('decision') or '').strip()
            if not (exec_id and act_id and decision):
                self._send(400, {'ok': False,
                                 'error': 'execution_id, activity_id and decision are required'})
                return
            # Append to the run's own log rather than to a fresh Supervisor's.
            # Without this the trace stopped at dispatch: approving a host is
            # the single most consequential hop in the whole flow and it was
            # the one the console had no record of.
            def trace(src: str, dst: str, message: str) -> None:
                with _RUN_LOCK:
                    _RUN.setdefault('events', []).append(
                        {'time': now_iso(), 'from': src, 'to': dst,
                         'message': message})

            try:
                result = PatchingAgent(trace=trace).decide(exec_id, act_id, decision)
                with _RUN_LOCK:
                    # Keep the stored run in step with the new outcome. A null
                    # in the newer read does not overwrite a value we already
                    # have: AO can answer without created_at while the run is
                    # still settling, and losing the dispatch timestamp would
                    # take this host out of the ROI timings for good.
                    for r in ((_RUN.get('patch') or {}).get('results') or []):
                        if r.get('execution_id') == exec_id:
                            r.update({k: v for k, v in result.items()
                                      if v is not None or r.get(k) is None})
                    snapshot = dict(_RUN) if _RUN.get('patch') else None
                # Agents 3 and 4 run once the decision has settled the host.
                finished = _rereport(snapshot) if snapshot else None
                self._send(200, {'ok': True, **result,
                                 **(finished or {})})
            except BackendUnavailable as exc:
                self._send(502, {'ok': False, 'error': f'{exc.service}: {exc.cause}',
                                 'detail': exc.fix})
            return

        if path != '/api/start':
            self._send(404, {'ok': False, 'error': 'not found'})
            return
        length = int(self.headers.get('Content-Length', '0') or '0')
        try:
            payload = json.loads(self.rfile.read(length) or b'{}')
        except Exception:
            payload = {}
        cve = (payload.get('cve') or '').strip()
        if not cve:
            self._send(400, {'ok': False, 'error': 'missing cve'})
            return

        with _RUN_LOCK:
            if _RUN.get('status') == 'running':
                self._send(409, {'ok': False,
                                 'error': f'a run is already in flight for '
                                          f'{_RUN.get("cve_id")}'})
                return
            _RUN.clear()
            _RUN.update(status='running', cve_id=cve, events=[], error=None)

        threading.Thread(
            target=_run_async,
            args=(cve, env('HOSTS_FILTER'), int(env('HOSTS_LIMIT', '0') or 0)),
            daemon=True, name=f'supervisor-{cve}').start()
        self._send(200, {'ok': True, 'cve': cve, 'mode': 'supervisor',
                         'status': 'running'})

    def log_message(self, fmt, *args):
        pass                      # the agent trace is the useful log


def serve(host: str, port: int) -> None:
    print(f'  risk model : {RISK_URL or "(unset)"}')
    print(f'  llama stack: {LLAMA_URL or "(unset)"}')
    print(f'  vector db  : {VECTOR_DB_ID or "(unset)"}')
    hf, hl = env('HOSTS_FILTER'), env('HOSTS_LIMIT')
    if hf or hl:
        print(f'  host narrowing: filter={hf or "-"} limit={hl or "-"}')
    print(f'  listening on http://{host}:{port}')
    ThreadingHTTPServer((host, port), Handler).serve_forever()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _print_run(state: dict) -> None:
    plan = state['plan']
    print()
    print(f'  CVE          : {plan["cve_id"]}  (CVSS {plan["cvss"]})')
    print(f'  Hosts        : {plan["hosts_total"]}  '
          f'({plan["hosts_review"]} review, {plan["hosts_auto"]} auto)')
    print(f'  Risk source  : {plan["risk_source"]}  (gate {plan["threshold"]:g})')
    print(f'  Window       : {plan["maintenance_window"]}')
    print(f'  Verdict      : {plan["verdict"]}')
    print(f'  Elapsed      : {state["elapsed_s"]}s')
    for n in plan['notes']:
        print(f'  Note         : {n}')
    for d in (plan.get('degraded') or []):
        print(f'  DEGRADED     : {d["step"]} — {d["service"]} unreachable')
        print(f'                 fix: {d["fix"]}')
    print()
    for h in state['hosts']:
        print(f'   {h["host"][:44]:46} risk={h["risk_score"]:<7} {h["decision"]}')
        if h['history']:
            print(f'      history: {" ".join(h["history"].split())[:160]}')
    print()
    print(f'  Next: {state["next"]}')


def _print_patch(state: dict) -> None:
    p = state.get('patch') or {}
    s = p.get('summary') or {}
    print()
    print(f'  Patching Agent -> {p.get("workflow")}   ({p.get("elapsed_s")}s)')
    print(f'    patched={s.get("patched")}  awaiting_approval={s.get("awaiting_approval")}'
          f'  failed={s.get("failed")}')
    print()
    for r in p.get('results', []):
        print(f'   {r["host"][:40]:42} {r["outcome"]:18} '
              f'{r.get("matched_port") or "-":10} {r.get("execution_id","")[:8]}')
        if r.get('error'):
            print(f'      error: {str(r["error"])[:140]}')
    print()
    print(f'  Next: {state.get("next")}')


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    p_list = sub.add_parser('list', help='C1 — list CVEs')
    p_list.add_argument('--limit', type=int, default=20)
    p_list.add_argument('--offset', type=int, default=0)

    p_detail = sub.add_parser('detail', help='C1+C2 — CVE detail and hosts')
    p_detail.add_argument('cve')
    p_detail.add_argument('--host', default='', help='substring filter on hostname')
    p_detail.add_argument('--limit', type=int, default=0, help='cap host count')

    p_run = sub.add_parser('run', help='Supervisor -> cve-gather-info-agent')
    p_run.add_argument('cve')
    p_run.add_argument('--host', default='', help='substring filter on hostname')
    p_run.add_argument('--limit', type=int, default=0, help='cap host count')
    p_run.add_argument('--json', action='store_true', help='emit the full state as JSON')
    p_run.add_argument('--quiet', action='store_true', help='suppress the agent trace')

    p_patch = sub.add_parser('patch', help='Supervisor -> Patching Agent (AO workflow)')
    p_patch.add_argument('cve')
    p_patch.add_argument('--host', default='', help='substring filter on hostname')
    p_patch.add_argument('--limit', type=int, default=0, help='cap host count')
    p_patch.add_argument('--json', action='store_true')

    p_serve = sub.add_parser('serve', help='HTTP backend for the console UI')
    p_serve.add_argument('--host', default=env('BACKEND_HOST', '127.0.0.1'))
    p_serve.add_argument('--port', type=int, default=int(env('BACKEND_PORT', '8787')))

    args = ap.parse_args()

    try:
        if args.cmd == 'list':
            page = fetch_cve_list(args.limit, args.offset)
            print(f'  {page["count"]} of {page["total_items"]} CVEs')
            for c in page['cves']:
                print(f'   {c["id"]:<20} cvss={str(c["cvss"]):<5} '
                      f'systems={str(c["systems_affected"]):<6} {c["impact"]}')

        elif args.cmd == 'detail':
            d = fetch_cve_detail(args.cve, args.host, args.limit)
            print(f'  {d["cve_id"]}  CVSS {d["cvss"]}  {d["impact"]}')
            print(f'  {d["description"][:160]}')
            print(f'  hosts: {d["count"]}'
                  + (f' of {d["total_affected"]}' if d.get('total_affected') else ''))
            for h in d['hosts'][:20]:
                print(f'   {h["host"][:50]:52} age={h["age_days"]}d')

        elif args.cmd == 'run':
            sup = Supervisor(verbose=not args.quiet)
            state = sup.run(args.cve, host_filter=args.host, host_limit=args.limit)
            if args.json:
                print(json.dumps(state, indent=2))
            else:
                _print_run(state)

        elif args.cmd == 'patch':
            sup = Supervisor(verbose=True)
            assessment = sup.run(args.cve, host_filter=args.host, host_limit=args.limit)
            state = sup.patch(assessment)
            if args.json:
                print(json.dumps(state, indent=2))
            else:
                _print_run(state)
                _print_patch(state)

        elif args.cmd == 'serve':
            serve(args.host, args.port)

    except BackendUnavailable as exc:
        print(f'\nFAILED — {exc}', file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == '__main__':
    main()
