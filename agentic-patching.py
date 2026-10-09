#!/usr/bin/env python3
"""Agentic CVE patching — common code, Supervisor, and agents 1 and 2.

Implements the left column of multi-agent/architecture.jpg:

    Common code (NOT an agent)     C1 get CVE list · C2 resolve affected hosts
            |  for each CVE
            v
    Supervisor Agent               owns control flow + per-CVE state
            |
            +--> 1 cve-gather-info-agent   RAG · scheduler · risk · dry-run
            +--> 2 Patching Agent          one AO workflow run per host

Agents 3 (Communication) and 4 (Results) are not implemented; the Supervisor
stops after dispatch and says so.

Design: fallbacks are allowed but never silent. Every external call either
succeeds or raises BackendUnavailable naming the service and the fix; the
caller may then substitute a stored default from fallbacks.py, but the
substitution is recorded in DEGRADED and travels with the report, because the
dry-run is what a human approves against. STRICT=true disables all of it and
re-raises; OFFLINE=1 runs entirely on stored defaults and touches no network.
Remediation is the exception that is never faked silently — see
PatchingAgent.patch_host and FALLBACK_PATCH.

Usage
-----
    ./agentic-patching.py list                     # C1 — CVE list
    ./agentic-patching.py detail CVE-2026-12405    # C1+C2 — detail + hosts
    ./agentic-patching.py run CVE-2026-12405       # Supervisor -> Info agent
    ./agentic-patching.py run CVE-2026-12405 --host pay-app-07 --json
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
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
# two-host dry run spent over a minute waiting on services already known down.
INSIGHTS_TIMEOUT = int(env('INSIGHTS_TIMEOUT', '15'))
RISK_TIMEOUT = int(env('RISK_TIMEOUT', '8'))
RAG_TIMEOUT = int(env('RAG_TIMEOUT', '20'))     # live RAG does LLM summarisation
AO_TIMEOUT = int(env('AO_TIMEOUT', '10'))

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

import fallbacks

# Degradations recorded during the current operation. The Supervisor clears
# this per run and copies it into the report, so a fabricated value can never
# reach an operator without a label attached.
DEGRADED: list[dict[str, str]] = []


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


def offline() -> bool:
    """OFFLINE=1 runs the whole console on stored defaults, touching nothing."""
    return env('OFFLINE').lower() in {'1', 'true', 'yes'}


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
        raise BackendUnavailable(service, 'offline mode',
                                 'unset OFFLINE to use the real service')
    entry = _DOWN.get(service)
    if not entry:
        return
    exc, retry_after = entry
    if time.time() >= retry_after:
        del _DOWN[service]      # let the next call probe it again
        return
    raise exc


def trip(service: str, exc: 'BackendUnavailable') -> None:
    _DOWN[service] = (exc, time.time() + CIRCUIT_TTL)


def degrade(step: str, service: str, cause: Any, fix: str) -> None:
    """Record that a step fell back. Raises instead when STRICT is set."""
    if fallbacks.strict():
        raise BackendUnavailable(service, cause, fix)
    entry = {'step': step, 'service': service,
             'reason': str(cause)[:300], 'fix': fix}
    if entry not in DEGRADED:
        DEGRADED.append(entry)


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


def preflight(url: str, timeout: float = CONNECT_TIMEOUT) -> None:
    """Fail fast if nothing is listening, before spending the read budget.

    A stopped pod leaves its Route resolving with nothing behind it, so the
    socket hangs for the full timeout instead of refusing. The read budgets
    have to stay generous — live RAG summarisation genuinely takes ~20s — so
    the two cases are separated: reachability gets seconds, answering gets
    the full allowance.
    """
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
    if _token.get('value') and _token['expires'] > time.time() + 30:
        return _token['value']

    # C1 and C2 each need a token, so without this a dead SSO is paid for
    # twice before the console has rendered anything.
    circuit('Red Hat SSO')
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


def fetch_cve_detail(cve_id: str, host_filter: str = '',
                     host_limit: int = 0) -> dict[str, Any]:
    """C1 + C2 — CVE metadata and the hosts it affects.

    host_filter / host_limit narrow the host set for demos and local testing.
    """
    try:
        detail = insights_get(f'/cves/{cve_id}')
        systems = insights_get(f'/cves/{cve_id}/affected_systems?limit=100&offset=0')
    except BackendUnavailable as exc:
        degrade('C2 cve_detail', exc.service, exc.cause, exc.fix)
        fb = fallbacks.cve_detail(cve_id)
        fb['hosts'] = _narrow(fb['hosts'], host_filter, host_limit)
        fb['count'] = len(fb['hosts'])
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

    hosts = _narrow(hosts, host_filter, host_limit)

    return {
        'cve_id': cve_id,
        'cvss': float(cvss) if cvss is not None else 0.0,
        'description': a.get('description', ''),
        'impact': a.get('impact', ''),
        'hosts': hosts,
        'count': len(hosts),
        'total_affected': (systems.get('meta') or {}).get('total_items'),
    }


def _narrow(hosts: list[dict], host_filter: str, host_limit: int) -> list[dict]:
    """Shared by the live and fallback paths so both honour --host/--limit."""
    if host_filter:
        matched = [h for h in hosts if host_filter in (h.get('host') or '')]
        if matched:
            hosts = matched
        else:
            print(f'  note: --host {host_filter!r} matched nothing; keeping all '
                  f'{len(hosts)} hosts', file=sys.stderr)
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
#   4  Produce dry-run report
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
class DryRun:
    cve_id: str
    cvss: float
    hosts_total: int
    hosts_review: int
    hosts_auto: int
    maintenance_window: str
    risk_source: str
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
            return fallbacks.history(host), 'fallback'

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
                'run: rag-setup/ingest.py --route <route> --dir ./data --ensure')

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
            f'retrieval or chunks.\n\n{excerpt}'
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
                    return content['text'].strip()
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
        assessed = [
            HostAssessment(
                host=h['host'], system_uuid=h['system_uuid'], age_days=h['age_days'],
                risk_score=round(s, 2),
                decision='review' if s > threshold else 'ok',
                reason=(f'Risk {s:.1f} exceeds {threshold:.0f} ({risk_source}) '
                        f'— requires review.' if s > threshold else
                        f'Risk {s:.1f} below {threshold:.0f} ({risk_source}).'),
            )
            for h, s in zip(hosts, scores)
        ]

        # step 1 — history, only for hosts a human will look at
        review = [a for a in assessed if a.decision == 'review']
        self._trace('info', 'rag', f'history for {len(review)} review host(s)')
        history_source = 'rag'
        for a in review:
            a.history, src = self.history(a.host)
            if src != 'rag':
                history_source = src

        # step 2 — window
        window, window_source = self.maintenance_window()

        # step 4 — dry-run report
        notes = []
        # In offline mode the top banner already says the whole page is stored
        # defaults, so repeating it per-step is noise. In live mode it is the
        # opposite: there is no banner, and a single step that quietly fell
        # back is exactly what the reviewer needs told.
        if not offline():
            if risk_source != 'model':
                notes.append('Risk scores are heuristic, not model output — the risk '
                             'service was unreachable. Treat them as indicative only.')
            if history_source != 'rag':
                notes.append('Host history came from stored defaults, not the RAG '
                             'store, so it may not reflect this estate.')
        if window_source == 'default':
            notes.append(f'No scheduler configured; using default window {window}.')
        if len(review) == len(assessed):
            notes.append('Every host requires review — check the risk threshold '
                         'is discriminating at this CVSS.')

        dry_run = DryRun(
            cve_id=cve_id, cvss=cvss,
            hosts_total=len(assessed), hosts_review=len(review),
            hosts_auto=len(assessed) - len(review),
            maintenance_window=window, risk_source=risk_source,
            verdict='review_required' if review else 'auto_approve_eligible',
            notes=notes,
            degraded=[dict(d) for d in DEGRADED],
        )
        self._trace('info', 'supervisor',
                    f'{len(review)}/{len(assessed)} need review — {dry_run.verdict}')
        return {'hosts': [asdict(a) for a in assessed], 'dry_run': asdict(dry_run)}


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
        self.runs[run['execution_id']] = run
        self._save()
        return run

    def get(self, execution_id: str) -> dict | None:
        return self.runs.get(execution_id)

    def recent(self, limit: int = 40) -> list[dict]:
        return sorted(self.runs.values(),
                      key=lambda r: r.get('created_at', ''), reverse=True)[:limit]


SIM = SimStore(ROOT / 'runs' / 'simulated.json')


def is_sim(execution_id: str) -> bool:
    """True if this id belongs to the local simulator rather than to AO.

    Looked up rather than pattern-matched: the store is the authority on what
    it created, and uuid4 collision with a real AO id is not a real risk.
    """
    return SIM.get(execution_id) is not None


# Maps the Info agent's per-host decision onto the workflow's routing input.
GROUP_FOR_DECISION = {'review': 'approved_patch', 'ok': 'auto_patch'}

_ao_token: dict[str, Any] = {}


def ao_login() -> str:
    """Bearer token for AO, cached until shortly before it expires."""
    if _ao_token.get('value') and _ao_token['expires'] > time.time() + 30:
        return _ao_token['value']
    circuit('Ansible Orchestrator')
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
            # Simulated: nothing is patched. The run carries a sim- id that
            # exists in no AO instance, so a later status read cannot mistake
            # it for a real execution.
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
                # 'completed' not 'patched': the list alone cannot tell an
                # approved run from a rejected one — both complete. The detail
                # view has the activity data to distinguish them.
                'outcome': ('awaiting_approval' if pending
                            else 'completed' if status in ('completed', 'succeeded')
                            else 'cancelled' if status in ('cancelled', 'canceled')
                            else 'failed' if status in ('failed', 'error')
                            else 'running'),
                'approval_pending': pending,
                'error': e.get('error_details'),
                'created_at': e.get('created_at'),
                'completed_at': e.get('completed_at'),
                'url': f'{AO_URL}/executions/{e.get("id")}',
            })
        return runs

    def _decide_sim(self, execution_id: str, decision: str) -> dict:
        """Resolve a simulated approval gate. No signal is sent anywhere."""
        run = SIM.get(execution_id)
        if not run:
            raise BackendUnavailable(
                'simulated run', f'{execution_id} is not in the local store',
                'it was created before runs/simulated.json was last cleared')
        demo_pause(2)        # the real gate takes seconds to settle
        approved = decision == 'approved'
        run.update({
            'status': 'completed',
            'outcome': 'patched' if approved else 'rejected',
            'approval_pending': False,
            'approval_activity_id': '',
            'decision': decision,
            # Rejecting stops the run at the gate, matching the real workflow:
            # the downstream nodes never leave pending.
            'steps': (fallbacks.sim_steps('run_cve_remediation') if approved
                      else fallbacks.sim_steps('approval_gate', status='rejected')),
        })
        SIM.put(run)
        self._trace('patching', 'console',
                    f'{execution_id[:12]} -> SIMULATED {run["outcome"]}')
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

        if is_sim(execution_id):
            return self._decide_sim(execution_id, decision)

        self._trace('console', 'patching', f'{decision} {execution_id[:8]}/{activity_id}')
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

        # --- agent 1 ------------------------------------------------------
        info = self.info.gather(detail)

        self.state = {
            'cve_id': cve_id,
            'cvss': detail['cvss'],
            'description': detail['description'],
            'hosts': info['hosts'],
            'dry_run': info['dry_run'],
            'events': self.events,
            'elapsed_s': round(time.monotonic() - started, 1),
            'degraded': [dict(d) for d in DEGRADED],
            # The dry-run is a stopping point, not a completion: dispatch is
            # a separate, operator-initiated step.
            'next': 'Patching Agent — press Start Patch to dispatch',
            'status': 'awaiting_patch_dispatch',
        }
        self.trace('supervisor', 'console', 'dry-run ready — awaiting operator review')
        return self.state

    # --- agent 2 ----------------------------------------------------------

    def patch(self, assessment: dict) -> dict:
        """Hand each assessed host to the Patching Agent, one AO run per host.

        Takes the dry-run from run() so the per-host decision determines which
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
            'next': 'Communication Agent (not implemented)',
            'status': 'awaiting_communication_agent',
        }
        self.trace('supervisor', 'console',
                   f'patch dispatched — {summary["patched"]} patched, '
                   f'{summary["awaiting_approval"]} awaiting approval, '
                   f'{summary["failed"]} failed')
        return self.state


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
        elif path == '/api/mode':
            # Read once at page load to decide whether to show the top banner.
            self._send(200, {
                'ok': True,
                'offline': offline(),
                'strict': fallbacks.strict(),
                'simulate_patch': fallbacks.simulate_patch(),
                'workflow': AO_WORKFLOW_NAME,
            })
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

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path.rstrip('/') or '/'

        if path == '/api/patch':
            # Agent 2. Needs a completed assessment to know each host's
            # decision, which is what selects the workflow branch.
            with _RUN_LOCK:
                snapshot = dict(_RUN)
            if snapshot.get('status') == 'running':
                self._send(409, {'ok': False, 'error': 'a run is already in flight'})
                return
            if not snapshot.get('hosts'):
                self._send(409, {
                    'ok': False, 'error': 'No assessment available',
                    'detail': 'Run "Assess CVE Impact" first — the Patching Agent '
                              'needs each host\'s decision to pick a workflow branch.'})
                return
            with _RUN_LOCK:
                _RUN.update(status='running', phase='patching', error=None)
            threading.Thread(target=_patch_async, args=(snapshot,),
                             daemon=True, name='patching').start()
            self._send(200, {'ok': True, 'cve': snapshot.get('cve_id'),
                             'status': 'running'})
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
            try:
                result = PatchingAgent().decide(exec_id, act_id, decision)
                with _RUN_LOCK:
                    # Keep the stored run in step with the new outcome.
                    for r in ((_RUN.get('patch') or {}).get('results') or []):
                        if r.get('execution_id') == exec_id:
                            r.update(result)
                self._send(200, {'ok': True, **result})
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
    dr = state['dry_run']
    print()
    print(f'  CVE          : {dr["cve_id"]}  (CVSS {dr["cvss"]})')
    print(f'  Hosts        : {dr["hosts_total"]}  '
          f'({dr["hosts_review"]} review, {dr["hosts_auto"]} auto)')
    print(f'  Risk source  : {dr["risk_source"]}')
    print(f'  Window       : {dr["maintenance_window"]}')
    print(f'  Verdict      : {dr["verdict"]}')
    print(f'  Elapsed      : {state["elapsed_s"]}s')
    for n in dr['notes']:
        print(f'  Note         : {n}')
    for d in (dr.get('degraded') or []):
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
