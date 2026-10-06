#!/usr/bin/env python3
import json
import logging
import os
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)

WORKSPACE = Path(os.environ.get('WORKSPACE', str(Path(__file__).resolve().parent)))
STATE_DIR = WORKSPACE / 'cve_console'
STATE_FILE = STATE_DIR / 'state.json'
DOTENV_FILE = STATE_DIR / '.env'
FLOW_SCRIPT = WORKSPACE / 'cve_flow.py'
FLOW_LOG = WORKSPACE / 'cve_console.log'
FLOW_PID = WORKSPACE / 'cve_console.pid'
load_dotenv(DOTENV_FILE)

LOG = logging.getLogger('cve_console')
_FLOW_LOG_GUARD = threading.Lock()


def setup_console_logging() -> None:
    level_name = os.environ.get(
        'CVE_CONSOLE_LOG_LEVEL',
        os.environ.get('CVE_FLOW_LOG_LEVEL', 'INFO'),
    ).upper()
    level = getattr(logging, level_name, logging.INFO)
    if not LOG.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter(
                '%(asctime)s [cve-console] %(levelname)s %(message)s',
                datefmt='%Y-%m-%dT%H:%M:%S',
            )
        )
        LOG.addHandler(handler)
    LOG.setLevel(level)
    LOG.propagate = False


def _start_flow_output_relay(proc: subprocess.Popen) -> None:
    """Copy patch-flow stdout/stderr to the log file and pod stderr."""

    def _relay() -> None:
        stream = proc.stdout
        if stream is None:
            return
        try:
            with open(FLOW_LOG, 'a', encoding='utf-8') as log_f:
                for line in stream:
                    log_f.write(line)
                    log_f.flush()
                    sys.stderr.write(line)
                    sys.stderr.flush()
        finally:
            stream.close()

    threading.Thread(
        target=_relay,
        daemon=True,
        name=f'flow-relay-{proc.pid}',
    ).start()


setup_console_logging()

from cve_flow import (
    FLOW_STAGE_LABELS,
    aap_job_template_ui_url,
    aap_playbook_job_ui_url,
    aap_workflow_job_ui_url,
    aap_workflow_template_ui_url,
    fetch_insights_cves_list,
    invoke_tool,
)

HOST = os.environ.get('CVE_CONSOLE_HOST', '127.0.0.1')
PORT = int(os.environ.get('CVE_CONSOLE_PORT', '8787'))
POLL_SECONDS = int(os.environ.get('CVE_CONSOLE_POLL_SECONDS', '30'))
AAP_VERIFY_TLS = os.environ.get('AAP_VERIFY_TLS', 'false').lower() in {'1', 'true', 'yes'}
LLAMA_URL = os.environ.get('LLAMA_STACK_URL', 'http://127.0.0.1:8321')
CVE_LIST_PAGE_SIZE = int(os.environ.get('CVE_CONSOLE_CVE_LIST_PAGE_SIZE', '20'))
CVE_LIST_SOURCE = os.environ.get('CVE_CONSOLE_CVE_LIST_SOURCE', 'direct_mcp').strip().lower()
# 0 = keep cached pages for the lifetime of the console process (until Refresh).
CVE_LIST_CACHE_SECONDS = int(os.environ.get('CVE_CONSOLE_CVE_LIST_CACHE_SECONDS', '0'))
CVE_LIST_CACHE: dict[str, object] = {'pages': {}}
CVE_LIST_CACHE_GUARD = threading.Lock()
CVE_LIST_PAGE_LOCKS: dict[str, threading.Lock] = {}
CVE_LIST_PAGE_LOCKS_GUARD = threading.Lock()
_API_STATE_LOCK = threading.Lock()
_FLOW_STATE_CACHE: dict[str, object] = {'expires_at': 0.0, 'payload': None}
_FLOW_STATE_CACHE_SECONDS = float(os.environ.get('CVE_CONSOLE_FLOW_STATE_CACHE_SECONDS', '3'))


DEFAULT_STATE = {
    'workflow': {
        'name': 'CVE-2020-25681 remediation workflow',
        'cve': 'CVE-2020-25681',
        'status': 'review_pending',
        'last_updated': None,
        'polling': 'local_only',
    },
    'summary': {
        'mode': 'hybrid',
        'job_template_url': 'https://aap-aap.apps.cluster-pmh55.pmh55.sandbox1954.opentlc.com/api/controller/v2/job_templates/48/',
        'workflow_template_url': 'https://aap-aap.apps.cluster-pmh55.pmh55.sandbox1954.opentlc.com/api/controller/v2/workflow_job_templates/49/',
        'playbook_path': 'playbooks/generated/CVE-2020-25681-hybrid-20260403-165722.yml',
        'review_reason': 'Risk threshold exceeded (>30) for one or more affected hosts.',
        'approval_state': 'pending_review',
        'last_job_status': 'unknown',
        'last_workflow_status': 'unknown',
    },
    'stream': [
        {
            'time': '2026-04-03T16:57:22Z',
            'event': 'playbook_generated',
            'message': 'Hybrid remediation playbook generated and pushed to GitHub.',
        },
        {
            'time': '2026-04-03T16:57:22Z',
            'event': 'job_template_created',
            'message': 'AAP Job Template 48 created for remediation run.',
        },
        {
            'time': '2026-04-03T16:57:22Z',
            'event': 'workflow_template_created',
            'message': 'Approval-gated Workflow Job Template 49 created.',
        },
        {
            'time': '2026-04-03T16:57:22Z',
            'event': 'awaiting_review',
            'message': 'Workflow is ready for review before remediation execution.',
        },
    ],
    'hosts': [
        {
            'host': 'placeholder-host-1',
            'risk_score': 42,
            'decision': 'review',
            'reason': 'Kernel package update requires explicit approval.',
        }
    ],
    'aap': {
        'enabled': False,
        'base_url': None,
        'workflow_template_id': 49,
        'job_template_id': 48,
        'workflow_jobs_endpoint': None,
        'job_launch_endpoint': None,
        'last_poll': None,
        'last_error': 'AAP credentials not configured.',
        'latest_workflow_job': None,
        'latest_job': None,
    },
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def deep_copy_default_state() -> dict:
    return json.loads(json.dumps(DEFAULT_STATE))


def load_state() -> dict:
    if not STATE_FILE.exists():
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        state = deep_copy_default_state()
        state['workflow']['last_updated'] = now_iso()
        persist_state(state)
        return state
    state = json.loads(STATE_FILE.read_text())
    changed = ensure_state_shape(state)
    if changed:
        persist_state(state)
    return state


def ensure_state_shape(state: dict) -> bool:
    changed = False
    default = deep_copy_default_state()
    for section, value in default.items():
        if section not in state:
            state[section] = value
            changed = True
    for key, value in default['workflow'].items():
        if key not in state['workflow']:
            state['workflow'][key] = value
            changed = True
    for key, value in default['summary'].items():
        if key not in state['summary']:
            state['summary'][key] = value
            changed = True
    for key, value in default['aap'].items():
        if key not in state['aap']:
            state['aap'][key] = value
            changed = True
    if 'hosts' not in state or not isinstance(state['hosts'], list):
        state['hosts'] = default['hosts']
        changed = True
    if 'stream' not in state or not isinstance(state['stream'], list):
        state['stream'] = default['stream']
        changed = True
    return changed


def persist_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def add_stream_event(state: dict, event: str, message: str) -> None:
    if any(item.get('event') == event and item.get('message') == message for item in state['stream'][-10:]):
        return
    ts = now_iso()
    state['stream'].append({'time': ts, 'event': event, 'message': message})
    state['stream'] = state['stream'][-100:]
    LOG.info('event=%s %s', event, message)


def parse_template_id(url: str | None) -> int | None:
    if not url:
        return None
    parts = [p for p in url.strip('/').split('/') if p]
    for part in reversed(parts):
        if part.isdigit():
            return int(part)
    return None


def get_ssl_context():
    if AAP_VERIFY_TLS:
        return None
    return ssl._create_unverified_context()


def fetch_json(url: str, token: str) -> dict:
    req = urllib.request.Request(url)
    req.add_header('Authorization', f'Bearer {token}')
    req.add_header('Accept', 'application/json')
    with urllib.request.urlopen(req, timeout=10, context=get_ssl_context()) as resp:
        return json.loads(resp.read().decode())


def post_json(url: str, token: str, payload: dict | None = None, method: str = 'POST') -> dict:
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header('Authorization', f'Bearer {token}')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Accept', 'application/json')
    with urllib.request.urlopen(req, timeout=30, context=get_ssl_context()) as resp:
        body = resp.read().decode()
        return json.loads(body) if body else {}


def http_error_detail(exc: urllib.error.HTTPError) -> str:
    try:
        body = exc.read().decode()
        if body:
            payload = json.loads(body)
            if isinstance(payload, dict):
                return str(payload.get('detail') or payload.get('error') or payload)
            return body
    except Exception:
        pass
    return exc.reason or str(exc)


def post_approval_action(url: str, token: str) -> dict:
    """AAP approve/deny expects an empty POST body (no JSON comment field)."""
    last_error: Exception | None = None
    for data in (None, b''):
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Authorization', f'Bearer {token}')
        req.add_header('Accept', 'application/json')
        try:
            with urllib.request.urlopen(req, timeout=30, context=get_ssl_context()) as resp:
                body = resp.read().decode()
                if not body:
                    return {'status': resp.status, 'url': url}
                return json.loads(body)
        except urllib.error.HTTPError as exc:
            last_error = RuntimeError(f'HTTP {exc.code}: {http_error_detail(exc)} (url={url})')
            if exc.code not in {400, 415}:
                raise last_error from exc
        except Exception as exc:
            last_error = exc
    if last_error:
        raise last_error
    raise RuntimeError(f'Could not POST approval action to {url}')


def aap_credentials() -> tuple[str, str]:
    token = os.environ.get('AAP_TOKEN') or os.environ.get('CONTROLLER_OAUTH_TOKEN') or os.environ.get('AWX_TOKEN')
    base_url = os.environ.get('AAP_BASE_URL') or os.environ.get('AAP_URL') or os.environ.get('CONTROLLER_HOST') or os.environ.get('AWX_HOST')
    base_url = normalize_aap_base_url(base_url)
    if not token or not base_url:
        raise RuntimeError('AAP credentials not configured (AAP_TOKEN and AAP_BASE_URL required)')
    return base_url, token


def normalize_aap_base_url(base_url: str | None) -> str | None:
    if not base_url:
        return None
    base = base_url.strip().rstrip('/')
    if '/api/controller/' in base:
        base = base.split('/api/controller/')[0]
    elif base.endswith('/api/v2'):
        base = base[:-len('/api/v2')]
    return base.rstrip('/')


def normalize_run_template_urls(run: dict, base_url: str | None) -> bool:
    base = normalize_aap_base_url(base_url)
    if not base:
        return False
    summary = run.setdefault('summary', {})
    aap = run.get('aap') or {}
    changed = False
    jt_id = parse_template_id(summary.get('job_template_url')) or aap.get('job_template_id')
    wf_id = parse_template_id(summary.get('workflow_template_url')) or aap.get('workflow_template_id')
    if jt_id:
        normalized = aap_job_template_ui_url(jt_id, base)
        if summary.get('job_template_url') != normalized:
            summary['job_template_url'] = normalized
            changed = True
    if wf_id:
        normalized = aap_workflow_template_ui_url(wf_id, base)
        if summary.get('workflow_template_url') != normalized:
            summary['workflow_template_url'] = normalized
            changed = True
    return changed


def aap_api_prefixes() -> list[str]:
    return ['/api/controller/v2', '/api/v2']


def fetch_json_optional(url: str, token: str) -> dict | None:
    try:
        return fetch_json(url, token)
    except urllib.error.HTTPError as exc:
        if exc.code in {400, 404}:
            return None
        raise


def absolute_aap_url(base_url: str, path: str | None) -> str | None:
    if not path:
        return None
    if path.startswith('http'):
        return path
    return f'{normalize_aap_base_url(base_url) or base_url}{path}'


def fetch_aap_object(base_url: str, token: str, path: str | None) -> dict | None:
    url = absolute_aap_url(base_url, path)
    if not url:
        return None
    return fetch_json_optional(url, token)


def is_pending_status(status: str | None) -> bool:
    return (status or '').lower() in {'pending', 'waiting', 'new'}


def is_workflow_approval_node(node: dict) -> bool:
    identifier = (node.get('identifier') or '').lower()
    if identifier == 'approval_review':
        return True
    job = (node.get('summary_fields') or {}).get('job') or {}
    job_type = (job.get('type') or node.get('unified_job_type') or '').lower()
    return 'workflow_approval' in job_type


def discover_workflow_approval_targets(base_url: str, token: str, workflow_job_id: int) -> list[dict]:
    """Mirror awx.awx.workflow_approval: find nodes via workflow_jobs/{id}/workflow_nodes/."""
    base_url = normalize_aap_base_url(base_url) or base_url
    targets: list[dict] = []
    for prefix in aap_api_prefixes():
        list_url = f'{base_url}{prefix}/workflow_jobs/{workflow_job_id}/workflow_nodes/'
        payload = fetch_json_optional(list_url, token)
        if not payload:
            continue
        for node in payload.get('results', []) or []:
            if not is_workflow_approval_node(node):
                continue
            node_detail = node
            node_path = node.get('url')
            if node_path:
                fetched = fetch_aap_object(base_url, token, node_path)
                if fetched:
                    node_detail = fetched
            job = (node_detail.get('summary_fields') or {}).get('job') or {}
            status = job.get('status') or node_detail.get('status')
            if status and not is_pending_status(status):
                continue
            related = node_detail.get('related') or {}
            job_path = related.get('job')
            approval_id = job.get('id')
            if not job_path and approval_id:
                job_path = f'{prefix}/workflow_approvals/{approval_id}/'
            if not job_path and not approval_id:
                continue
            target = {
                'id': approval_id,
                'name': job.get('name') or node_detail.get('identifier') or 'approval_review',
                'status': status or 'pending',
                'job_path': job_path,
                'related': related,
                'node_id': node_detail.get('id'),
            }
            if approval_id:
                enriched = enrich_workflow_approval(base_url, token, target)
                target['related'] = enriched.get('related') or target['related']
                target['id'] = enriched.get('id') or target['id']
            targets.append(target)
        if targets:
            return targets
    return []


def list_global_pending_workflow_approvals(base_url: str, token: str, workflow_job_id: int) -> list[dict]:
    base_url = normalize_aap_base_url(base_url) or base_url
    matches: list[dict] = []
    for prefix in aap_api_prefixes():
        list_url = f'{base_url}{prefix}/workflow_approvals/?status=pending&order_by=-id&page_size=50'
        payload = fetch_json_optional(list_url, token)
        if not payload:
            continue
        for item in payload.get('results', []) or []:
            related = item.get('related') or {}
            source = related.get('source_workflow_job') or ''
            if str(workflow_job_id) not in source:
                continue
            if not is_pending_status(item.get('status')):
                continue
            matches.append(enrich_workflow_approval(base_url, token, item))
        if matches:
            return matches
    return []


def list_pending_workflow_approvals(base_url: str, token: str, workflow_job_id: int) -> list[dict]:
    base_url = normalize_aap_base_url(base_url) or base_url
    for prefix in aap_api_prefixes():
        list_url = (
            f'{base_url}{prefix}/workflow_approvals/'
            f'?source_workflow_job={workflow_job_id}&status=pending&order_by=-id&page_size=20'
        )
        payload = fetch_json_optional(list_url, token)
        if not payload:
            continue
        pending = [
            enrich_workflow_approval(base_url, token, item)
            for item in (payload.get('results', []) or [])
            if is_pending_status(item.get('status'))
        ]
        if pending:
            return pending
    pending = discover_workflow_approval_targets(base_url, token, workflow_job_id)
    if pending:
        return pending
    return list_global_pending_workflow_approvals(base_url, token, workflow_job_id)


def enrich_workflow_approval(base_url: str, token: str, approval: dict) -> dict:
    related = approval.get('related') or {}
    if related.get('approve') or related.get('deny'):
        return approval
    approval_id = approval.get('id')
    if not approval_id:
        return approval
    for prefix in aap_api_prefixes():
        detail = fetch_json_optional(f'{normalize_aap_base_url(base_url) or base_url}{prefix}/workflow_approvals/{approval_id}/', token)
        if detail:
            approval['related'] = detail.get('related') or {}
            approval['status'] = detail.get('status') or approval.get('status')
            approval['name'] = detail.get('name') or approval.get('name')
            approval['id'] = detail.get('id') or approval.get('id')
            return approval
    return approval


def approval_action_candidates(base_url: str, approval: dict, action: str) -> list[str]:
    base_url = normalize_aap_base_url(base_url) or base_url
    urls: list[str] = []
    related = approval.get('related') or {}
    rel_action = related.get(action)
    if rel_action:
        urls.append(absolute_aap_url(base_url, rel_action) or rel_action)
    job_path = approval.get('job_path') or related.get('job')
    if job_path:
        job_url = absolute_aap_url(base_url, job_path) or job_path
        urls.append(f'{job_url}{action}')
        urls.append(f'{job_url.rstrip("/")}/{action}/')
    approval_id = approval.get('id')
    if approval_id:
        for prefix in aap_api_prefixes():
            urls.append(f'{base_url}{prefix}/workflow_approvals/{approval_id}/{action}/')
            urls.append(f'{base_url}{prefix}/workflow_approvals/{approval_id}/{action}')
    deduped: list[str] = []
    seen: set[str] = set()
    for url in urls:
        if url and url not in seen:
            seen.add(url)
            deduped.append(url)
    return deduped


def workflow_likely_awaiting_approval(run: dict, wf_status: str) -> bool:
    if wf_status not in {'running', 'waiting', 'pending', 'new'}:
        return False
    if (run.get('aap') or {}).get('latest_job'):
        return False
    return bool((run.get('summary') or {}).get('workflow_template_url'))


def store_pending_approvals(run: dict, base_url: str, token: str, workflow_job_id: int) -> list[dict]:
    try:
        pending = list_pending_workflow_approvals(base_url, token, int(workflow_job_id))
        run.setdefault('aap', {})['pending_approvals'] = [
            {
                'id': item.get('id'),
                'name': item.get('name'),
                'status': item.get('status'),
                'url': absolute_aap_url(base_url, item.get('url')),
                'job_path': item.get('job_path'),
            }
            for item in pending
        ]
    except Exception as exc:
        run.setdefault('aap', {})['pending_approvals'] = []
        run['aap']['approval_lookup_error'] = str(exc)
    return run['aap']['pending_approvals']


def act_on_workflow_approvals(
    base_url: str,
    token: str,
    workflow_job_id: int,
    action: str,
    comment: str = '',
) -> list[dict]:
    del comment  # AAP approve/deny endpoints do not accept a JSON comment body.
    if action not in {'approve', 'deny'}:
        raise ValueError(f'Unsupported approval action: {action}')
    pending = list_pending_workflow_approvals(base_url, token, workflow_job_id)
    if not pending:
        raise RuntimeError(
            f'No pending workflow approvals found for workflow job {workflow_job_id}. '
            'Check AAP Approvals page or verify the token has workflow approve permission.'
        )
    results: list[dict] = []
    errors: list[str] = []
    for approval in pending:
        acted = False
        candidates = approval_action_candidates(base_url, approval, action)
        if not candidates:
            errors.append(f'no action URLs for approval target {approval!r}')
            continue
        for candidate in candidates:
            try:
                results.append(post_approval_action(candidate, token))
                acted = True
                break
            except RuntimeError as exc:
                errors.append(f'{candidate}: {exc}')
        if not acted:
            label = approval.get('name') or approval.get('id') or 'approval'
            raise RuntimeError(
                f'Could not {action} {label} on workflow job {workflow_job_id}. '
                + (errors[-1] if errors else 'No AAP endpoint accepted the request.')
            )
    if not results:
        raise RuntimeError(f'Could not {action} any workflow approvals for workflow job {workflow_job_id}')
    return results


def workflow_approval_action(workflow_job_id: int, action: str, comment: str = '') -> dict:
    base_url, token = aap_credentials()
    acted = act_on_workflow_approvals(base_url, token, workflow_job_id, action, comment)
    state = load_state()
    label = 'Approved' if action == 'approve' else 'Denied'
    add_stream_event(
        state,
        f'workflow_{action}d',
        f'{label} workflow job {workflow_job_id} via CVE console.',
    )
    if action == 'approve':
        state.setdefault('summary', {})['approval_state'] = 'approved_in_progress'
    else:
        state.setdefault('summary', {})['approval_state'] = 'denied'
    persist_state(state)
    state = refresh_aap_state(state)
    return {
        'ok': True,
        'action': action,
        'workflow_job_id': workflow_job_id,
        'approvals_acted': len(acted),
    }


def infer_aap_config(state: dict) -> bool:
    token = os.environ.get('AAP_TOKEN') or os.environ.get('CONTROLLER_OAUTH_TOKEN') or os.environ.get('AWX_TOKEN')
    base_url = normalize_aap_base_url(
        os.environ.get('AAP_BASE_URL') or os.environ.get('AAP_URL') or os.environ.get('CONTROLLER_HOST') or os.environ.get('AWX_HOST')
    )
    changed = False
    if not base_url:
        wf_url = state['summary'].get('workflow_template_url')
        if wf_url and '/api/controller/' in wf_url:
            base_url = normalize_aap_base_url(wf_url.split('/api/controller/')[0])
        elif wf_url and wf_url.startswith('http'):
            base_url = normalize_aap_base_url(wf_url.split('/#/')[0])
    if base_url and state['aap'].get('base_url') != base_url:
        state['aap']['base_url'] = base_url
        changed = True
    if state['aap'].get('workflow_template_id') is None:
        wf_id = parse_template_id(state['summary'].get('workflow_template_url'))
        if wf_id is not None:
            state['aap']['workflow_template_id'] = wf_id
            changed = True
    if state['aap'].get('job_template_id') is None:
        jt_id = parse_template_id(state['summary'].get('job_template_url'))
        if jt_id is not None:
            state['aap']['job_template_id'] = jt_id
            changed = True
    state['aap']['enabled'] = bool(token and state['aap'].get('base_url'))
    if state['aap']['base_url'] and state['aap'].get('workflow_template_id'):
        state['aap']['workflow_jobs_endpoint'] = f"{state['aap']['base_url']}/api/controller/v2/workflow_jobs/?workflow_job_template={state['aap']['workflow_template_id']}&order_by=-id&page_size=1"
    if state['aap']['base_url'] and state['aap'].get('job_template_id'):
        state['aap']['job_launch_endpoint'] = f"{state['aap']['base_url']}/api/controller/v2/job_templates/{state['aap']['job_template_id']}/launch/"
    if not token:
        state['aap']['last_error'] = 'AAP token not configured. Set AAP_TOKEN (or CONTROLLER_OAUTH_TOKEN/AWX_TOKEN) to enable live polling.'
    elif not state['aap'].get('base_url'):
        state['aap']['last_error'] = 'AAP base URL not configured. Set AAP_BASE_URL (or CONTROLLER_HOST/AWX_HOST) to enable live polling.'
    return changed


def invoke_insights_get_cves(limit: int, offset: int) -> dict | None:
    try:
        return fetch_insights_cves_list(limit, offset, source=CVE_LIST_SOURCE)
    except Exception as exc:
        raise RuntimeError(f'Insights CVE list failed ({CVE_LIST_SOURCE}): {exc}') from exc


def _cve_cache_entry_valid(cached: dict, now: float) -> bool:
    expires_at = cached.get('expires_at')
    if expires_at is None:
        return True
    if CVE_LIST_CACHE_SECONDS <= 0:
        return True
    return float(expires_at) > now


def _get_cve_page_lock(cache_key: str) -> threading.Lock:
    with CVE_LIST_PAGE_LOCKS_GUARD:
        lock = CVE_LIST_PAGE_LOCKS.get(cache_key)
        if lock is None:
            lock = threading.Lock()
            CVE_LIST_PAGE_LOCKS[cache_key] = lock
        return lock


def _read_cve_page_cache(cache_key: str) -> dict | None:
    now = time.time()
    with CVE_LIST_CACHE_GUARD:
        pages = CVE_LIST_CACHE.get('pages')
        if not isinstance(pages, dict):
            return None
        cached = pages.get(cache_key)
        if not isinstance(cached, dict):
            return None
        if not _cve_cache_entry_valid(cached, now):
            return None
        payload = cached.get('payload')
        if not isinstance(payload, dict):
            return None
        result = dict(payload)
        result['cached'] = True
        return result


def _write_cve_page_cache(cache_key: str, payload: dict) -> None:
    now = time.time()
    expires_at = None if CVE_LIST_CACHE_SECONDS <= 0 else now + CVE_LIST_CACHE_SECONDS
    stored = dict(payload)
    stored['cached'] = False
    with CVE_LIST_CACHE_GUARD:
        pages = CVE_LIST_CACHE.setdefault('pages', {})
        if isinstance(pages, dict):
            pages[cache_key] = {'payload': stored, 'expires_at': expires_at}


def clear_cve_page_cache() -> None:
    with CVE_LIST_CACHE_GUARD:
        CVE_LIST_CACHE['pages'] = {}


def _parse_cve_item(item: dict) -> dict | None:
    cve_id = item.get('id') or item.get('cve') or item.get('synopsis')
    if not cve_id:
        return None
    attrs = item.get('attributes', {}) if isinstance(item, dict) else {}
    desc = attrs.get('description') or ''
    affected = attrs.get('systems_affected')
    if affected is None:
        affected = attrs.get('affected_systems')
    cvss = attrs.get('cvss3_score') or attrs.get('cvss2_score')
    suffix = f' | affected: {affected}' if affected is not None else ''
    return {
        'id': cve_id,
        'label': f"{cve_id}{suffix} — {desc[:120]}".strip(),
        'description': desc,
        'systems_affected': affected,
        'cvss': cvss,
        'public_date': attrs.get('public_date') or attrs.get('publish_date'),
    }


def fetch_cve_page(limit: int | None = None, offset: int = 0, use_cache: bool = True) -> dict:
    page_size = CVE_LIST_PAGE_SIZE if limit is None else max(1, min(limit, 50))
    offset = max(0, offset)
    cache_key = f'{page_size}:{offset}'

    if use_cache:
        cached = _read_cve_page_cache(cache_key)
        if cached is not None:
            LOG.info(
                'CVE list cache hit limit=%d offset=%d count=%d',
                page_size,
                offset,
                cached.get('count', 0),
            )
            return cached

    page_lock = _get_cve_page_lock(cache_key)
    with page_lock:
        if use_cache:
            cached = _read_cve_page_cache(cache_key)
            if cached is not None:
                return cached

        try:
            data = invoke_insights_get_cves(limit=page_size, offset=offset)
            rows = data.get('data', []) if isinstance(data, dict) else (data or [])
            if not isinstance(rows, list):
                rows = []
            options = [parsed for item in rows if isinstance(item, dict) and (parsed := _parse_cve_item(item))]
            payload = {
                'ok': True,
                'cves': options,
                'count': len(options),
                'limit': page_size,
                'offset': offset,
                'has_more': len(rows) >= page_size,
                'cached': False,
                'source': CVE_LIST_SOURCE,
                'error': None,
            }
        except Exception as exc:
            return {
                'ok': False,
                'cves': [],
                'count': 0,
                'limit': page_size,
                'offset': offset,
                'has_more': False,
                'cached': False,
                'error': str(exc),
            }

        if use_cache and payload['ok']:
            _write_cve_page_cache(cache_key, payload)
        if payload['ok']:
            LOG.info(
                'CVE list fetched limit=%d offset=%d count=%d has_more=%s',
                page_size,
                offset,
                payload['count'],
                payload['has_more'],
            )
        else:
            LOG.error(
                'CVE list fetch failed limit=%d offset=%d error=%s',
                page_size,
                offset,
                payload.get('error'),
            )
        return payload


def fetch_cve_catalog(max_pages: int | None = None, use_cache: bool = True) -> dict:
    """Backward-compatible wrapper — returns a single page only."""
    return fetch_cve_page(limit=CVE_LIST_PAGE_SIZE, offset=0, use_cache=use_cache)


def fetch_cve_options() -> list[dict]:
    result = fetch_cve_catalog()
    if not result.get('ok'):
        return []
    return result.get('cves', [])  # type: ignore[return-value]


def _process_running(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _flow_process_pid(state: dict | None = None) -> int | None:
    active = (state or {}).get('active_flow') or {}
    pid = active.get('pid')
    if pid:
        return int(pid)
    if FLOW_PID.exists():
        try:
            return int(FLOW_PID.read_text().strip())
        except (ValueError, OSError):
            return None
    return None


def _flow_process_active(state: dict | None = None) -> bool:
    pid = _flow_process_pid(state)
    return _process_running(pid)


def _tail_text_lines(path: Path, max_lines: int = 300, max_bytes: int = 65536) -> list[str]:
    if not path.exists():
        return []
    try:
        size = path.stat().st_size
        read_size = min(size, max_bytes)
        with open(path, 'rb') as fh:
            if read_size < size:
                fh.seek(-read_size, os.SEEK_END)
            data = fh.read(read_size)
        text = data.decode('utf-8', errors='replace')
        return text.splitlines()[-max_lines:]
    except OSError:
        return []


def _known_flow_stage(step: str) -> str | None:
    if step in FLOW_STAGE_LABELS:
        return FLOW_STAGE_LABELS[step]
    return None


def _is_flow_in_progress_run(run: dict) -> bool:
    wf = run.get('workflow', {})
    summary = run.get('summary', {})
    return (
        wf.get('status') in {'starting', 'in_progress'}
        or summary.get('approval_state') == 'flow_in_progress'
    )


def _read_flow_progress_from_log() -> tuple[str | None, str | None]:
    lines = _tail_text_lines(FLOW_LOG, max_lines=300)
    for line in reversed(lines):
        marker = ' STEP '
        idx = line.find(marker)
        if idx < 0:
            continue
        rest = line[idx + len(marker):].strip()
        if not rest:
            continue
        step = rest.split('(')[0].strip().split()[0]
        label = _known_flow_stage(step)
        if label:
            return step, label
    return None, None


def sync_active_flow_status(state: dict) -> bool:
    """Update in-memory state for a finished/failed flow. Returns True if state changed."""
    active = state.get('active_flow')
    pid = _flow_process_pid(state)
    if pid and _process_running(pid):
        return False

    triggered_at = (active or {}).get('triggered_at')
    run: dict | None = None
    run_idx: int | None = None
    for i, item in enumerate(state.get('runs', [])):
        if triggered_at and item.get('triggered_at') == triggered_at:
            run = item
            run_idx = i
            break
    if run is None:
        for i, item in enumerate(state.get('runs', [])):
            if _is_flow_in_progress_run(item):
                run = item
                run_idx = i
                triggered_at = item.get('triggered_at')
                break
    if run is None:
        if active:
            state.pop('active_flow', None)
            return True
        return False

    if not _is_flow_in_progress_run(run):
        if active:
            state.pop('active_flow', None)
            return True
        return False

    # Flow process exited while run still marked in-progress — reload state.json first.
    fresh = load_state()
    fresh_run = None
    for item in fresh.get('runs', []):
        if triggered_at and item.get('triggered_at') == triggered_at:
            fresh_run = item
            break
    if fresh_run and not _is_flow_in_progress_run(fresh_run):
        state.clear()
        state.update(fresh)
        return True

    failed = any('workflow failed' in line.lower() for line in _tail_text_lines(FLOW_LOG, max_lines=80))
    ts = now_iso()
    run.setdefault('workflow', {})['status'] = 'failed'
    run['workflow']['last_updated'] = ts
    run.setdefault('summary', {})['approval_state'] = 'flow_failed'
    err = run['summary'].get('workflow_error') or (
        'Patch flow process exited before completion (possible OOM or timeout). Check pod logs.'
    )
    run['summary']['workflow_error'] = err
    run['summary'].pop('flow_stage', None)
    run['summary'].pop('flow_message', None)
    LOG.error('flow failed cve=%s error=%s', run.get('workflow', {}).get('cve'), err)
    if run_idx is not None:
        state.setdefault('runs', [])[run_idx] = run
    state['workflow'] = dict(run.get('workflow', {}))
    state['summary'] = {**state.get('summary', {}), **run.get('summary', {})}
    state.pop('active_flow', None)
    try:
        FLOW_PID.unlink(missing_ok=True)
    except OSError:
        pass
    return True


def refresh_aap_state_during_flow() -> dict:
    """Lightweight state read while patch-flow subprocess is running."""
    now = time.time()
    cached = _FLOW_STATE_CACHE.get('payload')
    if cached and float(_FLOW_STATE_CACHE.get('expires_at') or 0) > now:
        return json.loads(json.dumps(cached))  # type: ignore[arg-type]

    state = load_state()
    state.setdefault('workflow', {})['polling'] = 'flow_in_progress'
    state['workflow']['last_updated'] = now_iso()
    _FLOW_STATE_CACHE['payload'] = state
    _FLOW_STATE_CACHE['expires_at'] = now + _FLOW_STATE_CACHE_SECONDS
    return state


FALLBACK_CVES = [
    {'id': 'CVE-2024-21626', 'label': 'CVE-2024-21626 | affected: 37 — runc container breakout via fd leak', 'description': 'runc container breakout via fd leak', 'systems_affected': 37, 'cvss': 8.6, 'public_date': '2024-01-31'},
    {'id': 'CVE-2024-3094',  'label': 'CVE-2024-3094 | affected: 37 — XZ Utils backdoor (liblzma)', 'description': 'XZ Utils backdoor (liblzma)', 'systems_affected': 37, 'cvss': 10.0, 'public_date': '2024-03-29'},
    {'id': 'CVE-2024-6387',  'label': 'CVE-2024-6387 | affected: 37 — OpenSSH regreSSHion RCE', 'description': 'OpenSSH regreSSHion RCE', 'systems_affected': 37, 'cvss': 8.1, 'public_date': '2024-07-01'},
    {'id': 'CVE-2023-44487', 'label': 'CVE-2023-44487 | affected: 37 — HTTP/2 Rapid Reset DDoS', 'description': 'HTTP/2 Rapid Reset DDoS attack vector', 'systems_affected': 37, 'cvss': 7.5, 'public_date': '2023-10-10'},
    {'id': 'CVE-2024-1086',  'label': 'CVE-2024-1086 | affected: 37 — Linux kernel nf_tables use-after-free LPE', 'description': 'Linux kernel nf_tables use-after-free local privilege escalation', 'systems_affected': 37, 'cvss': 7.8, 'public_date': '2024-01-31'},
    {'id': 'CVE-2023-38545', 'label': 'CVE-2023-38545 | affected: 37 — curl SOCKS5 heap overflow', 'description': 'curl SOCKS5 heap buffer overflow', 'systems_affected': 37, 'cvss': 9.8, 'public_date': '2023-10-11'},
    {'id': 'CVE-2024-4577',  'label': 'CVE-2024-4577 | affected: 37 — PHP CGI argument injection RCE', 'description': 'PHP CGI argument injection RCE', 'systems_affected': 37, 'cvss': 9.8, 'public_date': '2024-06-09'},
    {'id': 'CVE-2023-4911',  'label': 'CVE-2023-4911 | affected: 37 — glibc Looney Tunables buffer overflow', 'description': 'glibc ld.so Looney Tunables buffer overflow', 'systems_affected': 37, 'cvss': 7.8, 'public_date': '2023-10-03'},
    {'id': 'CVE-2024-0132',  'label': 'CVE-2024-0132 | affected: 37 — NVIDIA Container Toolkit escape', 'description': 'NVIDIA Container Toolkit container escape', 'systems_affected': 37, 'cvss': 9.0, 'public_date': '2024-09-26'},
    {'id': 'CVE-2026-31337', 'label': 'CVE-2026-31337 | affected: 37 — RHEL kernel networking buffer overflow', 'description': 'Critical buffer overflow in RHEL kernel networking subsystem', 'systems_affected': 37, 'cvss': 9.8, 'public_date': '2026-03-15'},
]

EMPTY_STATE = {
    'workflow': {'name': '', 'cve': '', 'status': 'idle', 'last_updated': None, 'polling': 'local_only'},
    'summary': {'approval_state': 'idle', 'last_workflow_status': 'not_started', 'last_job_status': 'not_started'},
    'hosts': [], 'stream': [],
    'aap': {'enabled': False, 'base_url': None, 'latest_workflow_job': None, 'latest_job': None},
    'runs': [],
}

SETTINGS_KEYS = [
    'LLAMA_STACK_URL', 'RISK_URL', 'VECTOR_DB_ID', 'DEFAULT_LLM_MODEL',
    'INSIGHTS_MCP_ENDPOINT', 'INSIGHTS_TOOLGROUP',
    'AAP_BASE_URL', 'AAP_TOKEN', 'AAP_VERIFY_TLS',
    'GITHUB_MCP_ENDPOINT', 'GITHUB_TOKEN',
    'GITHUB_REPO_OWNER', 'GITHUB_REPO_NAME', 'GITHUB_REPO_BRANCH',
    'PLAYBOOK_PUSH_METHOD',
    'CVE_CONSOLE_HOST', 'CVE_CONSOLE_PORT', 'CVE_CONSOLE_POLL_SECONDS',
    'CVE_FLOW_LOG_LEVEL',
    'ROI_LABOR_RATE', 'ROI_MANUAL_MIN_PER_HOST', 'ROI_AI_MIN_PER_HOST',
    'ROI_EXPOSURE_MANUAL_FACTOR', 'ROI_EXPOSURE_AI_FACTOR',
    'ROI_DIM_ENGINEERING_PCT', 'ROI_DIM_EXPOSURE_PCT', 'ROI_DIM_REUSE_PCT', 'ROI_DIM_RECOVERY_PCT',
]
SECRET_KEYS = {'AAP_TOKEN', 'GITHUB_TOKEN', 'LIGHTSPEED_CLIENT_SECRET'}


def read_env_file() -> dict:
    vals: dict[str, str] = {}
    if DOTENV_FILE.exists():
        for raw in DOTENV_FILE.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, v = line.split('=', 1)
            vals[k.strip()] = v.strip().strip('"').strip("'")
    return vals


def write_env_file(updates: dict) -> None:
    existing = read_env_file()
    existing.update(updates)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    lines = [f'{k}={v}' for k, v in sorted(existing.items()) if v]
    DOTENV_FILE.write_text('\n'.join(lines) + '\n')


# The Supervisor holds per-CVE state (attempts, tried_fixes, phase_failures)
# across the approval gate, so the same instance must serve both the initial
# run and the post-approval resume.
_SUPERVISOR = None
_SUPERVISOR_LOCK = threading.Lock()


def get_supervisor(fresh: bool = False):
    global _SUPERVISOR
    with _SUPERVISOR_LOCK:
        if _SUPERVISOR is None or fresh:
            import agents
            _SUPERVISOR = agents.build_system(state_file=STATE_FILE)
        return _SUPERVISOR


def start_unified_flow(cve_id: str) -> dict:
    LOG.info('TRIGGER supervisor flow cve=%s', cve_id)
    if STATE_FILE.exists():
        STATE_FILE.unlink()
    supervisor = get_supervisor(fresh=True)
    threading.Thread(
        target=_run_supervisor,
        args=(supervisor, cve_id),
        daemon=True,
        name=f'supervisor-{cve_id}',
    ).start()
    return {'ok': True, 'cve': cve_id, 'mode': 'supervisor'}


def _run_supervisor(supervisor, cve_id: str) -> None:
    try:
        supervisor.run(cve_id)
    except Exception as exc:
        LOG.exception('Supervisor flow failed for %s', cve_id)
        supervisor._fail(str(exc))


def unified_approve(workflow_job_id: int) -> dict:
    """Approve in AAP when it is live, then resume the Supervisor either way."""
    aap_result = None
    try:
        aap_result = workflow_approval_action(workflow_job_id, 'approve', 'Approved via AIP Console')
    except Exception as exc:
        LOG.info('AAP approval unavailable (%s) — resuming supervisor locally', exc)

    supervisor = get_supervisor()
    threading.Thread(
        target=_resume_supervisor,
        args=(supervisor,),
        daemon=True,
        name='supervisor-resume',
    ).start()

    if aap_result and aap_result.get('ok'):
        return {**aap_result, 'mode': 'supervisor'}
    return {'ok': True, 'mode': 'supervisor_local_approval',
            'message': 'Approved locally — AAP approval unavailable'}


def _resume_supervisor(supervisor) -> None:
    try:
        supervisor.resume()
    except Exception as exc:
        LOG.exception('Supervisor resume failed')
        supervisor._fail(str(exc))


def _llm_inference(prompt: str, system_msg: str = '') -> str:
    llama_url = os.environ.get('LLAMA_STACK_URL', 'http://127.0.0.1:8321')
    model = os.environ.get('DEFAULT_LLM_MODEL', 'vllm-inference/llama-scout-17b')
    messages = []
    if system_msg:
        messages.append({'role': 'system', 'content': system_msg})
    messages.append({'role': 'user', 'content': prompt})
    body = json.dumps({'model': model, 'messages': messages, 'max_tokens': 1024}).encode()
    req = urllib.request.Request(
        f'{llama_url}/v1/chat/completions',
        data=body,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
        data = json.loads(resp.read())
    return data['choices'][0]['message']['content']


FALLBACK_WHATIF = {
    'source': 'fallback',
    'scenarios': [
        {
            'title': 'Change maintenance window',
            'icon': '\U0001f550',
            'change': 'Move from Friday 18:00 → Tuesday 10:00',
            'impact': '-15%',
            'impact_direction': 'down',
            'detail': 'Tuesday morning patches historically have 15% lower failure rate — more staff available for rollback, and workload is lower.',
            'confidence': 'HIGH',
            'evidence': '47 similar patches analyzed over 12 months',
        },
        {
            'title': 'Increase drain timeout',
            'icon': '⏱️',
            'change': 'Increase from 30s → 120s',
            'impact': '-40%',
            'impact_direction': 'down',
            'detail': '3 of 5 historical failures on this cluster were caused by incomplete connection draining. Longer timeout allows graceful shutdown.',
            'confidence': 'HIGH',
            'evidence': '3 similar failure records in vector store',
        },
        {
            'title': 'Confirm DBA availability',
            'icon': '\U0001f464',
            'change': 'DBA on-call confirmed for patch window',
            'impact': '-25%',
            'impact_direction': 'down',
            'detail': '2 past failures required emergency DBA intervention for connection pool recovery. Pre-arranged DBA reduces MTTR.',
            'confidence': 'MEDIUM',
            'evidence': '2 incident records with DBA escalation',
        },
        {
            'title': 'Skip canary phase',
            'icon': '⚠️',
            'change': 'Remove canary validation, patch all at once',
            'impact': '+60%',
            'impact_direction': 'up',
            'detail': 'Removing canary eliminates early failure detection. If the patch causes issues, all production systems are affected simultaneously.',
            'confidence': 'HIGH',
            'evidence': 'Canary caught 4 of 6 recent failures before production impact',
        },
    ],
}

FALLBACK_WHY = {
    'source': 'fallback',
    'factors': [
        {'name': 'CVSS Base Score', 'icon': '\U0001f534', 'value': 'Critical (9.8)', 'weight': '30%', 'detail': 'Network-exploitable with no authentication required. Attack complexity is low.'},
        {'name': 'Host Age & Patch Lag', 'icon': '\U0001f4c5', 'value': '47 days since last patch', 'weight': '20%', 'detail': 'This host has not been patched in 47 days. Hosts with patch lag >30 days have 2.3x higher failure rates.'},
        {'name': 'Operational Context', 'icon': '\U0001f3e2', 'value': 'Tier 1 / Production', 'weight': '25%', 'detail': 'Business-critical production workload. Historical success rate for similar patches: 82%. Below the 90% auto-approve threshold.'},
        {'name': 'Historical Pattern Match', 'icon': '\U0001f4ca', 'value': '3 similar failures found', 'weight': '15%', 'detail': 'RAG search found 3 historically similar patch operations that resulted in failure. Common root cause: connection pool exhaustion during rolling restart.'},
        {'name': 'Workload Sensitivity', 'icon': '⚡', 'value': 'High memory pressure', 'weight': '10%', 'detail': 'Current memory utilization at 78%. Kernel patches requiring reboot on high-memory hosts have 1.8x higher failure rate.'},
    ],
    'recommendation': 'REVIEW recommended. The combination of critical CVSS score, Tier 1 production environment, and 3 similar historical failures exceeds the auto-approve threshold. Human judgment needed for drain procedure timing.',
}


def _add_a2a(state: dict, from_agent: str, to_agent: str, msg_type: str, action: str, message: str) -> None:
    ts = now_iso()
    state.setdefault('stream', []).append({
        'time': ts, 'event': 'a2a_message',
        'from': from_agent, 'to': to_agent,
        'type': msg_type, 'action': action, 'message': message,
    })
    state['stream'] = state['stream'][-100:]
    persist_state(state)


def handle_whatif(state: dict) -> dict:
    summary = state.get('summary', {})
    hosts = state.get('hosts', [])
    ctx = summary.get('operational_context', {})
    cve_id = summary.get('cve_id', 'unknown')
    _add_a2a(state, 'Console UI', 'Reason Agent', 'request', 'what_if_analysis',
             f'Console UI → Reason Agent: What-If scenario analysis requested for {cve_id}')
    try:
        _add_a2a(state, 'Reason Agent', 'Llama Stack', 'request', 'llm_inference',
                 f'Reason Agent → Llama Stack: Generating 4 risk scenarios via /v1/chat/completions')
        prompt = (
            f"You are a patch risk analyst. Given this CVE patch scenario, generate exactly 4 what-if scenarios.\n\n"
            f"CVE: {cve_id}\n"
            f"CVSS: {summary.get('cvss', 'N/A')}\n"
            f"Risk classification: {summary.get('risk_classification', 'N/A')}\n"
            f"Failure probability: {summary.get('failure_probability', 'N/A')}%\n"
            f"Affected systems: {len(hosts)}\n"
            f"Environment: {ctx.get('environment', 'N/A')}\n"
            f"Business tier: {ctx.get('business_criticality', 'N/A')}\n"
            f"Maintenance window: {ctx.get('maintenance_window', 'N/A')}\n"
            f"Historical success rate: {ctx.get('historical_patch_success', 'N/A')}\n\n"
            f"For each scenario, provide a JSON object with fields: title, icon (single emoji), change, impact (e.g. '-15%' or '+20%'), "
            f"impact_direction ('up' for risk increase, 'down' for reduction), detail (2-3 sentences), confidence (HIGH/MEDIUM/LOW), evidence.\n"
            f"Return ONLY a JSON array of 4 scenario objects, no markdown."
        )
        raw = _llm_inference(prompt, 'You are a concise patch risk analyst. Return only valid JSON.')
        clean = raw.strip()
        if clean.startswith('```'):
            clean = clean.split('\n', 1)[1].rsplit('```', 1)[0].strip()
        scenarios = json.loads(clean)
        _add_a2a(state, 'Llama Stack', 'Reason Agent', 'response', 'llm_result',
                 f'Llama Stack → Reason Agent: Generated {len(scenarios)} scenarios (LIVE)')
        _add_a2a(state, 'Reason Agent', 'Console UI', 'response', 'what_if_result',
                 f'Reason Agent → Console UI: What-If analysis complete — {len(scenarios)} scenarios delivered')
        return {'ok': True, 'source': 'live', 'scenarios': scenarios}
    except Exception as exc:
        LOG.info('  FALLBACK: what-if LLM failed (%s). Using demo data.', exc)
        _add_a2a(state, 'Llama Stack', 'Reason Agent', 'error', 'llm_failed',
                 f'Llama Stack → Reason Agent: LLM inference failed — {exc}')
        _add_a2a(state, 'Reason Agent', 'Console UI', 'response', 'what_if_fallback',
                 f'Reason Agent → Console UI: What-If analysis complete — 4 scenarios (FALLBACK)')
        return {'ok': True, **FALLBACK_WHATIF}


def handle_why(state: dict, hostname: str) -> dict:
    summary = state.get('summary', {})
    host = None
    for h in state.get('hosts', []):
        if h.get('host') == hostname:
            host = h
            break
    if not host:
        host = {'host': hostname, 'risk_score': 'N/A', 'decision': 'N/A'}
    ctx = summary.get('operational_context', {})
    _add_a2a(state, 'Console UI', 'Risk Agent', 'request', 'why_analysis',
             f'Console UI → Risk Agent: Why risk explanation requested for {hostname}')
    try:
        _add_a2a(state, 'Risk Agent', 'Llama Stack', 'request', 'llm_inference',
                 f'Risk Agent → Llama Stack: Analyzing risk factors for {hostname} via /v1/chat/completions')
        prompt = (
            f"You are a patch risk explainer. Explain why this host received its risk score and decision.\n\n"
            f"Host: {host.get('host')}\n"
            f"Risk score: {host.get('risk_score')}\n"
            f"Decision: {host.get('decision')}\n"
            f"Reason: {host.get('reason', 'N/A')}\n"
            f"CVE: {summary.get('cve_id', 'unknown')}, CVSS: {summary.get('cvss', 'N/A')}\n"
            f"Environment: {ctx.get('environment', 'N/A')}\n"
            f"Business tier: {ctx.get('business_criticality', 'N/A')}\n"
            f"Historical success: {ctx.get('historical_patch_success', 'N/A')}\n\n"
            f"Return a JSON object with:\n"
            f"- factors: array of objects with fields: name, icon (emoji), value, weight (percentage), detail (1-2 sentences)\n"
            f"- recommendation: a 2-3 sentence summary recommendation\n"
            f"Return ONLY valid JSON, no markdown."
        )
        raw = _llm_inference(prompt, 'You are a concise risk explainer. Return only valid JSON.')
        clean = raw.strip()
        if clean.startswith('```'):
            clean = clean.split('\n', 1)[1].rsplit('```', 1)[0].strip()
        result = json.loads(clean)
        n = len(result.get('factors', []))
        _add_a2a(state, 'Llama Stack', 'Risk Agent', 'response', 'llm_result',
                 f'Llama Stack → Risk Agent: Risk analysis complete — {n} factors identified (LIVE)')
        _add_a2a(state, 'Risk Agent', 'Console UI', 'response', 'why_result',
                 f'Risk Agent → Console UI: Why analysis for {hostname} — {n} factors + recommendation')
        return {'ok': True, 'source': 'live', 'host': host, **result}
    except Exception as exc:
        LOG.info('  FALLBACK: why LLM failed (%s). Using demo data.', exc)
        _add_a2a(state, 'Llama Stack', 'Risk Agent', 'error', 'llm_failed',
                 f'Llama Stack → Risk Agent: LLM inference failed — {exc}')
        _add_a2a(state, 'Risk Agent', 'Console UI', 'response', 'why_fallback',
                 f'Risk Agent → Console UI: Why analysis for {hostname} — 5 factors (FALLBACK)')
        return {'ok': True, 'host': host, **FALLBACK_WHY}


def start_patch_process(cve_id: str) -> dict:
    env = os.environ.copy()
    triggered_at = now_iso()
    LOG.info('TRIGGER patch flow cve=%s triggered_at=%s', cve_id, triggered_at)
    with _FLOW_LOG_GUARD:
        with open(FLOW_LOG, 'a', encoding='utf-8') as log_f:
            log_f.write(f'{now_iso()} [cve-console] TRIGGER patch flow cve={cve_id}\n')
    proc = subprocess.Popen(
        ['python3', str(FLOW_SCRIPT), '--cve', cve_id, '--triggered-at', triggered_at],
        cwd=str(WORKSPACE),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    _start_flow_output_relay(proc)
    FLOW_PID.write_text(str(proc.pid))
    state = load_state()
    infer_aap_config(state)
    base_url = normalize_aap_base_url(state.get('aap', {}).get('base_url'))
    pending_run = {
        'triggered_at': triggered_at,
        'workflow': {
            'name': f'{cve_id} remediation workflow',
            'cve': cve_id,
            'status': 'in_progress',
            'flow_stage': 'starting',
            'last_updated': triggered_at,
            'triggered_at': triggered_at,
            'polling': 'live',
        },
        'summary': {
            'flow_stage': 'starting',
            'flow_message': 'Patch flow started — loading CVE from Insights…',
            'approval_state': 'flow_in_progress',
            'last_workflow_status': 'not_started',
            'last_job_status': 'not_started',
        },
        'hosts': [],
        'aap': {
            'enabled': bool(state.get('aap', {}).get('enabled')),
            'base_url': base_url,
        },
    }
    state['active_flow'] = {'cve': cve_id, 'pid': proc.pid, 'triggered_at': triggered_at}
    runs = state.get('runs', [])
    runs.insert(0, pending_run)
    state['runs'] = runs[:50]
    state['workflow'] = dict(pending_run['workflow'])
    state['summary'] = {**state.get('summary', {}), **pending_run['summary']}
    state['hosts'] = []
    state.setdefault('summary', {})['workflow_error'] = None
    add_stream_event(state, 'patch_process_started', f'Started patch flow for {cve_id} (pid {proc.pid}).')
    _FLOW_STATE_CACHE['expires_at'] = 0.0
    persist_state(state)
    return {'ok': True, 'pid': proc.pid, 'cve': cve_id, 'triggered_at': triggered_at}


def refresh_run_from_aap(run: dict, token: str) -> dict:
    if _is_flow_in_progress_run(run) and not (run.get('aap') or {}).get('workflow_template_id'):
        return run
    aap = run.get('aap', {}) or {}
    base_url = normalize_aap_base_url(aap.get('base_url'))
    wf_template_id = aap.get('workflow_template_id')
    job_template_id = aap.get('job_template_id')
    if base_url:
        normalize_run_template_urls(run, base_url)
    if not (token and base_url and wf_template_id):
        return run
    wf_endpoint = f"{base_url}/api/controller/v2/workflow_jobs/?workflow_job_template={wf_template_id}&order_by=-id&page_size=1"
    try:
        payload = fetch_json(wf_endpoint, token)
        results = payload.get('results', [])
        if results:
            latest = results[0]
            wf_status = latest.get('status', 'unknown')
            wf_job_id = latest.get('id')
            run.setdefault('aap', {})['latest_workflow_job'] = {
                'id': wf_job_id,
                'name': latest.get('name'),
                'status': wf_status,
                'finished': latest.get('finished'),
                'started': latest.get('started'),
                'api_url': f"{base_url}{latest.get('url')}" if latest.get('url') else None,
                'url': aap_workflow_job_ui_url(int(wf_job_id), base_url) if wf_job_id else None,
            }
            run.setdefault('summary', {})['last_workflow_status'] = wf_status
            run.setdefault('workflow', {})['status'] = wf_status
            run['workflow']['last_updated'] = now_iso()
            wf_job_id = latest.get('id')
            pending: list[dict] = []
            if wf_job_id and wf_status not in {'successful', 'failed', 'error', 'canceled', 'cancelled'}:
                pending = store_pending_approvals(run, base_url, token, int(wf_job_id))
            else:
                run.setdefault('aap', {})['pending_approvals'] = []
        if job_template_id:
            job_endpoint = f"{base_url}/api/controller/v2/jobs/?job_template={job_template_id}&order_by=-id&page_size=1"
            jobs_payload = fetch_json(job_endpoint, token)
            job_results = jobs_payload.get('results', [])
            if job_results:
                latest_job = job_results[0]
                job_id = latest_job.get('id')
                run['aap']['latest_job'] = {
                    'id': job_id,
                    'name': latest_job.get('name'),
                    'status': latest_job.get('status'),
                    'finished': latest_job.get('finished'),
                    'started': latest_job.get('started'),
                    'api_url': f"{base_url}{latest_job.get('url')}" if latest_job.get('url') else None,
                    'url': aap_playbook_job_ui_url(int(job_id), base_url) if job_id else None,
                }
                run['summary']['last_job_status'] = latest_job.get('status') or run['summary'].get('last_job_status') or 'unknown'
        pending = (run.get('aap') or {}).get('pending_approvals') or []
        wf_status = run.get('summary', {}).get('last_workflow_status') or run.get('workflow', {}).get('status')
        if pending:
            run['summary']['approval_state'] = 'pending_review'
            run['summary']['display_workflow_status'] = 'waiting_for_approval'
            if not (run.get('aap') or {}).get('latest_job'):
                run['summary']['last_job_status'] = 'not_started'
        elif workflow_likely_awaiting_approval(run, wf_status or ''):
            run['summary']['approval_state'] = 'pending_review'
            run['summary']['display_workflow_status'] = 'waiting_for_approval'
            run['summary']['last_job_status'] = 'not_started'
        elif wf_status in {'waiting', 'pending', 'new'}:
            run['summary']['approval_state'] = 'pending_review'
            run['summary']['display_workflow_status'] = 'waiting_for_approval'
        elif wf_status in {'successful'}:
            run['summary']['approval_state'] = 'approved_and_completed'
            run['summary']['display_workflow_status'] = wf_status
        elif wf_status in {'failed', 'error', 'canceled', 'cancelled'}:
            run['summary']['approval_state'] = 'execution_problem'
            run['summary']['display_workflow_status'] = wf_status
        else:
            run['summary']['approval_state'] = 'in_progress'
            run['summary']['display_workflow_status'] = wf_status
        run['aap']['last_error'] = None
        run['aap']['last_poll'] = now_iso()
    except Exception as e:
        run.setdefault('aap', {})['last_error'] = f'Polling error: {e}'
    if base_url:
        normalize_run_template_urls(run, base_url)
    return run


def refresh_aap_state(state: dict) -> dict:
    if _flow_process_active(state):
        return refresh_aap_state_during_flow()

    _FLOW_STATE_CACHE['expires_at'] = 0.0
    changed = sync_active_flow_status(state)
    if changed:
        persist_state(state)

    infer_aap_config(state)
    token = os.environ.get('AAP_TOKEN') or os.environ.get('CONTROLLER_OAUTH_TOKEN') or os.environ.get('AWX_TOKEN')
    if not state['aap']['enabled']:
        state['workflow']['polling'] = 'local_only'
        state['workflow']['last_updated'] = now_iso()
        persist_state(state)
        return state
    state = refresh_run_from_aap(state, token)
    runs = state.get('runs', [])
    if isinstance(runs, list) and runs:
        refreshed: list[dict] = []
        for run in runs:
            if _is_flow_in_progress_run(run) and not (run.get('aap') or {}).get('workflow_template_id'):
                refreshed.append(run)
            else:
                refreshed.append(refresh_run_from_aap(run, token))
        state['runs'] = refreshed
    persist_state(state)
    return state


HTML = '''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Agentic Patching Console</title>
  <style>
    :root {
      --bg: #0b1020;
      --panel: #151c33;
      --text: #e7ecff;
      --muted: #9aa7d1;
      --accent: #6ea8fe;
      --border: #2a355f;
    }
    body { margin: 0; font-family: Inter, system-ui, sans-serif; background: var(--bg); color: var(--text); }
    .wrap { max-width: 1400px; margin: 0 auto; padding: 24px; }
    h1 { margin-top: 0; }
    table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 14px; overflow: hidden; }
    th, td { text-align: left; vertical-align: top; padding: 14px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    a { color: var(--accent); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-word; }
    .muted { color: var(--muted); }
    ul { margin: 0; padding-left: 18px; }
    .empty { color: var(--muted); font-style: italic; }
    .btn-approve { padding: 6px 10px; background: #2ecc71; color: #081020; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; }
    .btn-deny { padding: 6px 10px; background: #ff7675; color: #081020; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; }
    .btn-approve:disabled, .btn-deny:disabled { opacity: 0.5; cursor: not-allowed; }
    .approval-actions { margin-top: 8px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .tabs { display: flex; gap: 8px; margin-bottom: 0; border-bottom: 1px solid var(--border); }
    .tab {
      padding: 10px 16px;
      background: transparent;
      color: var(--muted);
      border: 1px solid transparent;
      border-bottom: none;
      border-radius: 8px 8px 0 0;
      cursor: pointer;
      font-weight: 600;
    }
    .tab.active { color: var(--text); background: var(--panel); border-color: var(--border); }
    .tab-panel { display: none; padding-top: 16px; }
    .tab-panel.active { display: block; }
    .btn-start-cve {
      padding: 6px 10px;
      background: var(--accent);
      color: #081020;
      border: none;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      white-space: nowrap;
    }
    .cve-toolbar { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
    .cve-toolbar input {
      min-width: 320px;
      padding: 8px;
      background: var(--panel);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 8px;
    }
    .btn-secondary {
      padding: 8px 12px;
      background: var(--panel);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 8px;
      font-weight: 600;
      cursor: pointer;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Agentic Patching Console</h1>
    <div class="tabs">
      <button type="button" class="tab active" data-tab="runs">Patch Runs</button>
      <button type="button" class="tab" data-tab="cves">CVEs</button>
    </div>

    <div id="panel_runs" class="tab-panel active">
    <div style="margin-bottom: 16px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
      <label for="cve_input" class="muted">CVE</label>
      <input id="cve_input" type="text" placeholder="Enter CVE ID, e.g. CVE-2020-25681" style="min-width: 420px; padding: 8px; background: var(--panel); color: var(--text); border: 1px solid var(--border); border-radius: 8px;" />
      <button id="start_btn" style="padding: 10px 14px; background: var(--accent); color: #081020; border: none; border-radius: 8px; font-weight: 700; cursor: pointer;">Start Patch Process</button>
      <span id="launch_status" class="muted"></span>
    </div>
    <div id="workflow_error" class="muted" style="margin-bottom: 12px;"></div>
    <table>
      <thead>
        <tr>
          <th>Triggered At</th>
          <th>CVE Name</th>
          <th>Affected Hosts list</th>
          <th>Information from RAG for hosts</th>
          <th>Ansible URL's</th>
          <th>Current Ansible Status</th>
        </tr>
      </thead>
      <tbody id="runs_table_body"></tbody>
    </table>
    </div>

    <div id="panel_cves" class="tab-panel">
      <div class="cve-toolbar">
        <input id="cve_search" type="search" placeholder="Filter current page by CVE ID or description..." />
        <button type="button" id="cve_prev_btn" class="btn-secondary" disabled>Previous</button>
        <button type="button" id="cve_next_btn" class="btn-secondary" disabled>Next</button>
        <button type="button" id="cve_reload_btn" class="btn-secondary">Refresh</button>
        <span id="cve_load_status" class="muted">Open this tab to load CVEs from Insights.</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>CVE</th>
            <th>CVSS</th>
            <th>Affected Systems</th>
            <th>Published</th>
            <th>Description</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="cves_table_body">
          <tr><td colspan="6" class="empty">No CVEs loaded yet.</td></tr>
        </tbody>
      </table>
    </div>
  </div>

<script>
function esc(v) {
  return (v === null || v === undefined || v === '') ? '—' : String(v);
}

function renderHosts(hosts) {
  if (!hosts || !hosts.length) return '<div class="muted">Analyzing affected hosts…</div>';
  return `<ul>${hosts.map(h => `<li><strong>${esc(h.host)}</strong>${h.decision ? ` — ${esc(h.decision)}` : ''}</li>`).join('')}</ul>`;
}

function renderRag(hosts) {
  if (!hosts || !hosts.length) return '<div class="empty">No RAG info</div>';
  const items = hosts.map(h => {
    const ds = h.decision_support;
    let text = '';
    if (typeof ds === 'string') {
      text = ds;
    } else if (ds && typeof ds === 'object') {
      text = ds.answer || ds.summary || ds.text || JSON.stringify(ds, null, 2);
    }
    return `<li><strong>${esc(h.host)}</strong><br>${text ? `<span>${esc(text)}</span>` : '<span class="empty">No RAG info yet</span>'}</li>`;
  }).join('');
  return `<ul>${items}</ul>`;
}

function renderUrls(data) {
  const links = [];
  if (data.summary.job_template_url) {
    links.push(`<li><a target="_blank" rel="noreferrer" href="${data.summary.job_template_url}">Job Template</a></li>`);
  }
  if (data.summary.workflow_template_url) {
    links.push(`<li><a target="_blank" rel="noreferrer" href="${data.summary.workflow_template_url}">Workflow Template</a></li>`);
  }
  const wfJob = data.aap && data.aap.latest_workflow_job;
  if (wfJob && wfJob.url) {
    links.push(`<li><a target="_blank" rel="noreferrer" href="${wfJob.url}">Latest Workflow Job</a></li>`);
  }
  const job = data.aap && data.aap.latest_job;
  if (job && job.url) {
    links.push(`<li><a target="_blank" rel="noreferrer" href="${job.url}">Latest Job</a></li>`);
  }
  return links.length ? `<ul>${links.join('')}</ul>` : '<div class="empty">No URLs</div>';
}

function normalizeStatus(status, approvalState, data) {
  if (approvalState === 'flow_in_progress') return 'in_progress';
  if (approvalState === 'flow_failed') return 'failed';
  const pending = data && data.aap && data.aap.pending_approvals && data.aap.pending_approvals.length;
  if (pending || approvalState === 'pending_review') return 'waiting_for_approval';
  const display = data && data.summary && data.summary.display_workflow_status;
  if (display) return display;
  const s = (status || '').toLowerCase();
  if (!s && approvalState) return approvalState;
  if (s === 'successful') return 'successful';
  if (s === 'failed' || s === 'error' || s === 'canceled' || s === 'cancelled') return s;
  if (s === 'waiting' || s === 'pending' || s === 'new') return 'waiting_for_approval';
  if (s === 'running') return 'running';
  return status || 'unknown';
}

function needsApproval(data) {
  const wfJob = data.aap && data.aap.latest_workflow_job;
  if (!wfJob || !wfJob.id) return false;
  if (data.summary && data.summary.approval_state === 'pending_review') return true;
  if (data.aap && data.aap.pending_approvals && data.aap.pending_approvals.length) return true;
  const wfStatus = (wfJob.status || (data.summary && data.summary.last_workflow_status) || (data.workflow && data.workflow.status) || '').toLowerCase();
  const hasJob = data.aap && data.aap.latest_job;
  if (!hasJob && (wfStatus === 'running' || wfStatus === 'waiting' || wfStatus === 'pending' || wfStatus === 'new')) {
    return !!(data.summary && data.summary.workflow_template_url);
  }
  return false;
}

function renderApprovalActions(data) {
  if (!needsApproval(data)) return '';
  const wfJobId = data.aap.latest_workflow_job.id;
  const pending = (data.aap.pending_approvals || []).length;
  const hint = pending ? `${pending} pending approval(s)` : 'Awaiting approval';
  return `<div class="approval-actions">
    <span class="muted">${esc(hint)}</span>
    <button class="btn-approve" onclick="submitApproval(${wfJobId}, 'approve')">Approve</button>
    <button class="btn-deny" onclick="submitApproval(${wfJobId}, 'deny')">Deny</button>
  </div>`;
}

function renderStatus(data) {
  const parts = [];
  const summary = data.summary || {};
  const approvalState = summary.approval_state;
  const flowMessage = summary.flow_message;
  const flowStage = summary.flow_stage;

  if (approvalState === 'flow_in_progress') {
    parts.push(`<div style="color:#6ea8fe;"><strong>In progress:</strong> ${esc(flowMessage || flowStage || 'Running patch flow…')}</div>`);
    if (data.workflow && data.workflow.last_updated) {
      parts.push(`<div class="muted">Updated: ${esc(data.workflow.last_updated)}</div>`);
    }
    const hasWf = data.aap && data.aap.latest_workflow_job && data.aap.latest_workflow_job.id;
    if (!hasWf) {
      return parts.join('');
    }
    parts.push('<div class="muted" style="margin-top:8px;">AAP workflow launched — status below:</div>');
  }

  if (approvalState === 'flow_failed') {
    parts.push(`<div style="color:#ffb4b4;"><strong>Failed:</strong> Patch flow did not complete</div>`);
    if (summary.workflow_error) {
      parts.push(`<div style="margin-top:8px;color:#ffb4b4;">${esc(summary.workflow_error)}</div>`);
    }
    return parts.join('');
  }

  const wfJob = data.aap && data.aap.latest_workflow_job;
  const job = data.aap && data.aap.latest_job;
  const wfStatus = normalizeStatus(
    (wfJob && wfJob.status) || summary.last_workflow_status || (data.workflow && data.workflow.status),
    approvalState,
    data
  );
  const jobStatus = job && job.status
    ? normalizeStatus(job.status, null, data)
    : (summary.last_job_status === 'not_started' ? 'not started (awaiting approval)' : normalizeStatus(summary.last_job_status, null, data));
  parts.push(`<div><strong>Workflow:</strong> ${esc(wfStatus)}</div>`);
  parts.push(`<div><strong>Job:</strong> ${esc(jobStatus || 'unknown')}</div>`);
  if (approvalState && approvalState !== 'flow_in_progress') {
    parts.push(`<div><strong>Approval:</strong> ${esc(approvalState)}</div>`);
  }
  if (wfJob && wfJob.finished) {
    parts.push(`<div><strong>Workflow finished:</strong> ${esc(wfJob.finished)}</div>`);
  }
  if (job && job.finished) {
    parts.push(`<div><strong>Job finished:</strong> ${esc(job.finished)}</div>`);
  }
  if (data.summary && data.summary.workflow_error) {
    parts.push(`<div style="margin-top:8px;color:#ffb4b4;"><strong>Error:</strong> ${esc(data.summary.workflow_error)}</div>`);
  }
  if (data.aap && data.aap.last_error) {
    parts.push(`<div style="margin-top:8px;color:#ffb4b4;"><strong>AAP:</strong> ${esc(data.aap.last_error)}</div>`);
  }
  parts.push(renderApprovalActions(data));
  return parts.join('');
}

async function submitApproval(workflowJobId, action) {
  const endpoint = action === 'approve' ? '/api/approve' : '/api/deny';
  const comment = action === 'approve'
    ? 'Approved via Agentic Patching Console'
    : 'Denied via Agentic Patching Console';
  document.querySelectorAll('.btn-approve, .btn-deny').forEach(btn => { btn.disabled = true; });
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({workflow_job_id: workflowJobId, comment})
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    document.getElementById('launch_status').textContent =
      action === 'approve' ? `Approved workflow job ${workflowJobId}` : `Denied workflow job ${workflowJobId}`;
  } catch (e) {
    document.getElementById('launch_status').textContent = `${action} failed: ${e.message || e}`;
  } finally {
    document.querySelectorAll('.btn-approve, .btn-deny').forEach(btn => { btn.disabled = false; });
  }
  await refresh();
}

async function startPatch() {
  const cve = document.getElementById('cve_input').value.trim();
  const btn = document.getElementById('start_btn');
  const status = document.getElementById('launch_status');
  btn.disabled = true;
  status.textContent = `Starting ${cve}...`;
  try {
    const res = await fetch('/api/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({cve})
    });
    const data = await res.json();
    status.textContent = data.ok ? `Started ${data.cve}` : 'Failed to start';
  } catch (e) {
    status.textContent = `Start failed: ${e}`;
  } finally {
    btn.disabled = false;
  }
  await refresh();
}

function renderRow(run) {
  return `
    <tr>
      <td>${esc(run.workflow && run.workflow.triggered_at)}</td>
      <td>${esc(run.workflow && run.workflow.cve)}</td>
      <td>${renderHosts(run.hosts || [])}</td>
      <td>${renderRag(run.hosts || [])}</td>
      <td>${renderUrls(run)}</td>
      <td>${renderStatus(run)}</td>
    </tr>`;
}

let cveCatalog = [];
let cvePageCache = {};
let activeTab = 'runs';
let cvesLoaded = false;
let cvePageOffset = 0;
let cvePageSize = 20;
let cveHasMore = false;
let runsPollMs = 5000;
let runsPollTimer = null;

function updateCvePager() {
  document.getElementById('cve_prev_btn').disabled = cvePageOffset <= 0;
  document.getElementById('cve_next_btn').disabled = !cveHasMore;
}

function switchTab(name) {
  activeTab = name;
  document.querySelectorAll('.tab').forEach(tab => tab.classList.toggle('active', tab.dataset.tab === name));
  document.getElementById('panel_runs').classList.toggle('active', name === 'runs');
  document.getElementById('panel_cves').classList.toggle('active', name === 'cves');
  if (name === 'cves' && !cvesLoaded) {
    loadCves(0);
  }
  if (name === 'runs') {
    refresh();
  }
}

async function refresh() {
  if (activeTab !== 'runs') return;
  const res = await fetch('/api/state');
  const data = await res.json();
  const runs = (data.runs && data.runs.length) ? data.runs : [{workflow: data.workflow, hosts: data.hosts, summary: data.summary, aap: data.aap}];
  document.getElementById('runs_table_body').innerHTML = runs.map(renderRow).join('');
  document.getElementById('workflow_error').textContent = (data.summary && data.summary.workflow_error) ? `Workflow error for ${data.workflow.cve}: ${data.summary.workflow_error}` : '';
  const nextPollMs = (data.workflow && data.workflow.polling === 'flow_in_progress') ? 10000 : 5000;
  if (nextPollMs !== runsPollMs) {
    runsPollMs = nextPollMs;
    if (runsPollTimer) clearInterval(runsPollTimer);
    runsPollTimer = setInterval(refresh, runsPollMs);
  }
}

function filteredCves() {
  const q = document.getElementById('cve_search').value.trim().toLowerCase();
  if (!q) return cveCatalog;
  return cveCatalog.filter(cve => {
    const haystack = [cve.id, cve.description, cve.label, cve.cvss, cve.public_date, cve.systems_affected]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    return haystack.includes(q);
  });
}

function renderCveTable() {
  const rows = filteredCves();
  const body = document.getElementById('cves_table_body');
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty">No CVEs match the current filter.</td></tr>';
    return;
  }
  body.innerHTML = rows.map(cve => `
    <tr>
      <td class="mono"><strong>${esc(cve.id)}</strong></td>
      <td>${esc(cve.cvss)}</td>
      <td>${esc(cve.systems_affected)}</td>
      <td>${esc(cve.public_date)}</td>
      <td>${esc((cve.description || '').slice(0, 220))}</td>
      <td><button type="button" class="btn-start-cve" data-cve-id="${String(cve.id || '').replace(/"/g, '&quot;')}">Start Patch</button></td>
    </tr>`).join('');
  body.querySelectorAll('.btn-start-cve').forEach(btn => {
    btn.addEventListener('click', () => startPatchForCve(btn.getAttribute('data-cve-id')));
  });
}

function applyCvePage(data) {
  cveCatalog = data.cves || [];
  cvePageOffset = data.offset ?? cvePageOffset;
  cvePageSize = data.limit ?? cvePageSize;
  cveHasMore = !!data.has_more;
  cvesLoaded = true;
  renderCveTable();
  updateCvePager();
  const from = cvePageOffset + 1;
  const to = cvePageOffset + cveCatalog.length;
  const range = cveCatalog.length ? `${from}–${to}` : 'none';
  const cacheHint = data.cached ? ', from cache' : '';
  document.getElementById('cve_load_status').textContent =
    `${cveCatalog.length} CVE(s) from Insights (showing ${range}${cveHasMore ? ', more available' : ''}${cacheHint})`;
}

async function loadCves(offset, forceRefresh) {
  const status = document.getElementById('cve_load_status');
  const nextOffset = typeof offset === 'number' ? Math.max(0, offset) : cvePageOffset;
  if (!forceRefresh && cvePageCache[nextOffset]) {
    applyCvePage(cvePageCache[nextOffset]);
    return;
  }
  status.textContent = 'Loading CVEs from Insights...';
  document.getElementById('cve_prev_btn').disabled = true;
  document.getElementById('cve_next_btn').disabled = true;
  try {
    const params = new URLSearchParams({
      limit: String(cvePageSize),
      offset: String(nextOffset),
    });
    if (forceRefresh) params.set('refresh', '1');
    const res = await fetch(`/api/cves?${params.toString()}`);
    const raw = await res.text();
    let data;
    try {
      data = JSON.parse(raw);
    } catch (parseErr) {
      const snippet = raw.slice(0, 80).replace(/\\s+/g, ' ');
      throw new Error(
        res.ok
          ? `Invalid JSON from /api/cves (${snippet})`
          : `HTTP ${res.status} from /api/cves (${snippet || 'gateway timeout — retry or use Next for another page'})`
      );
    }
    if (!data.ok) {
      throw new Error(data.error || 'Insights CVE list failed');
    }
    cvePageCache[nextOffset] = data;
    applyCvePage(data);
  } catch (e) {
    cvesLoaded = false;
    status.textContent = `Load failed: ${e.message || e}`;
    updateCvePager();
  }
}

async function startPatchForCve(cveId) {
  document.getElementById('cve_input').value = cveId;
  switchTab('runs');
  await startPatch();
}

document.getElementById('start_btn').addEventListener('click', startPatch);
document.getElementById('cve_search').addEventListener('input', renderCveTable);
document.getElementById('cve_reload_btn').addEventListener('click', () => {
  delete cvePageCache[cvePageOffset];
  loadCves(cvePageOffset, true);
});
document.getElementById('cve_prev_btn').addEventListener('click', () => loadCves(Math.max(0, cvePageOffset - cvePageSize)));
document.getElementById('cve_next_btn').addEventListener('click', () => loadCves(cvePageOffset + cvePageSize));
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => switchTab(tab.dataset.tab));
});
refresh();
runsPollTimer = setInterval(refresh, runsPollMs);
</script>
</body>
</html>
'''


class Handler(BaseHTTPRequestHandler):
    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            # Browser/probes often close idle connections during slow /api/state polls.
            pass

    def write_body(self, body: bytes) -> None:
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def respond(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.write_body(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'
        if path == '/api/state':
            if not STATE_FILE.exists():
                self.respond(200, 'application/json', json.dumps(EMPTY_STATE).encode())
                return
            with _API_STATE_LOCK:
                state = refresh_aap_state(load_state())
            self.respond(200, 'application/json', json.dumps(state).encode())
            return
        if path == '/api/cves':
            try:
                query = parse_qs(parsed.query or '')
                limit = int((query.get('limit') or [str(CVE_LIST_PAGE_SIZE)])[0])
                offset = int((query.get('offset') or ['0'])[0])
                refresh_flag = (query.get('refresh') or ['0'])[0].lower() in {'1', 'true', 'yes'}
                if refresh_flag:
                    clear_cve_page_cache()
                payload = fetch_cve_page(limit=limit, offset=offset, use_cache=not refresh_flag)
                if not payload.get('ok', True):
                    raise RuntimeError(payload.get('error', 'fetch failed'))
                self.respond(200, 'application/json', json.dumps(payload).encode())
            except Exception:
                fallback = {'ok': True, 'cves': FALLBACK_CVES, 'count': len(FALLBACK_CVES),
                            'offset': 0, 'limit': len(FALLBACK_CVES), 'has_more': False, 'source': 'fallback'}
                self.respond(200, 'application/json', json.dumps(fallback).encode())
            return
        if path == '/api/settings':
            env = read_env_file()
            masked = {}
            for k in SETTINGS_KEYS:
                v = env.get(k, '')
                if k in SECRET_KEYS and v:
                    masked[k] = v[:4] + '****'
                else:
                    masked[k] = v
            self.respond(200, 'application/json', json.dumps({'ok': True, 'settings': masked}).encode())
            return
        if path == '/api/flow-log':
            lines: list[str] = []
            if FLOW_LOG.exists():
                lines = FLOW_LOG.read_text().splitlines()[-200:]
            self.respond(200, 'application/json', json.dumps({'ok': True, 'lines': lines}).encode())
            return
        if path == '/api/what-if':
            try:
                state = load_state()
                result = handle_whatif(state)
                self.respond(200, 'application/json', json.dumps(result).encode())
            except Exception as exc:
                self.respond(500, 'application/json', json.dumps({'ok': False, 'error': str(exc)}).encode())
            return
        if path == '/api/why':
            try:
                query = parse_qs(parsed.query or '')
                hostname = (query.get('host') or [''])[0]
                state = load_state()
                result = handle_why(state, hostname)
                self.respond(200, 'application/json', json.dumps(result).encode())
            except Exception as exc:
                self.respond(500, 'application/json', json.dumps({'ok': False, 'error': str(exc)}).encode())
            return
        if path == '/api/approval-targets':
            try:
                state = load_state()
                infer_aap_config(state)
                token = os.environ.get('AAP_TOKEN') or os.environ.get('CONTROLLER_OAUTH_TOKEN') or os.environ.get('AWX_TOKEN')
                wf_job_id = state.get('aap', {}).get('latest_workflow_job', {}) or {}
                workflow_job_id = wf_job_id.get('id')
                if not workflow_job_id:
                    raise ValueError('No latest_workflow_job.id in state')
                base_url = state['aap']['base_url']
                pending = list_pending_workflow_approvals(base_url, token, int(workflow_job_id))
                body = json.dumps({
                    'workflow_job_id': workflow_job_id,
                    'targets': pending,
                    'approve_urls': [
                        approval_action_candidates(base_url, item, 'approve')
                        for item in pending
                    ],
                }, indent=2).encode()
                self.respond(200, 'application/json', body)
                return
            except Exception as e:
                self.respond(500, 'application/json', json.dumps({'ok': False, 'error': str(e)}).encode())
                return
        if path == '/' or path == '/index.html':
            static_file = WORKSPACE / 'static' / 'index.html'
            if static_file.exists():
                self.respond(200, 'text/html; charset=utf-8', static_file.read_bytes())
            else:
                self.respond(200, 'text/html; charset=utf-8', HTML.encode())
            return
        if path == '/healthz':
            self.respond(200, 'text/plain; charset=utf-8', b'ok')
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == '/api/start':
            length = int(self.headers.get('Content-Length', '0') or '0')
            raw = self.rfile.read(length) if length else b'{}'
            cve = None
            try:
                payload = json.loads(raw.decode() or '{}')
                cve = payload.get('cve')
                if not cve:
                    raise ValueError('Missing cve')
                result = start_unified_flow(cve)
                self.respond(200, 'application/json', json.dumps(result).encode())
                return
            except Exception as e:
                LOG.exception('POST /api/start failed cve=%s', cve)
                self.respond(500, 'application/json', json.dumps({'ok': False, 'error': str(e)}).encode())
                return
        if parsed.path == '/api/settings':
            length = int(self.headers.get('Content-Length', '0') or '0')
            raw = self.rfile.read(length) if length else b'{}'
            try:
                payload = json.loads(raw.decode() or '{}')
                updates = {k: v for k, v in payload.items() if k in SETTINGS_KEYS and v}
                write_env_file(updates)
                for k, v in updates.items():
                    os.environ[k] = v
                self.respond(200, 'application/json', json.dumps({'ok': True}).encode())
                return
            except Exception as e:
                self.respond(500, 'application/json', json.dumps({'ok': False, 'error': str(e)}).encode())
                return
        if parsed.path in {'/api/approve', '/api/deny'}:
            length = int(self.headers.get('Content-Length', '0') or '0')
            raw = self.rfile.read(length) if length else b'{}'
            try:
                payload = json.loads(raw.decode() or '{}')
                workflow_job_id = payload.get('workflow_job_id')
                if workflow_job_id is None:
                    state = load_state()
                    wf_job = (state.get('aap') or {}).get('latest_workflow_job') or {}
                    workflow_job_id = wf_job.get('id')
                if not workflow_job_id:
                    raise ValueError('Missing workflow_job_id and no latest workflow job in state')
                action = 'approve' if parsed.path == '/api/approve' else 'deny'
                comment = str(payload.get('comment') or '').strip()
                if action == 'approve':
                    result = unified_approve(int(workflow_job_id))
                else:
                    result = workflow_approval_action(int(workflow_job_id), action, comment)
                self.respond(200, 'application/json', json.dumps(result).encode())
                return
            except Exception as e:
                self.respond(500, 'application/json', json.dumps({'ok': False, 'error': str(e)}).encode())
                return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        try:
            msg = format % args
        except Exception:
            return
        if '/api/state' in msg or '/healthz' in msg or msg.startswith('GET / '):
            return
        if '/api/' in msg:
            LOG.info('HTTP %s', msg)


SETTINGS_DEFAULTS = {
    'LLAMA_STACK_URL': 'http://127.0.0.1:8321',
    'DEFAULT_LLM_MODEL': 'vllm-inference/llama-scout-17b',
    'VECTOR_DB_ID': 'patch_history',
    'RISK_URL': 'http://risk-model.apps.ocp.example.com/v2/models/patch-risk/infer',
    'INSIGHTS_MCP_ENDPOINT': 'http://127.0.0.1:8400',
    'INSIGHTS_TOOLGROUP': 'insights_mcp',
    'AAP_BASE_URL': 'https://aap-controller.apps.ocp.example.com',
    'AAP_VERIFY_TLS': 'false',
    'GITHUB_MCP_ENDPOINT': 'http://127.0.0.1:8401',
    'GITHUB_REPO_OWNER': 'svalluru',
    'GITHUB_REPO_NAME': 'agentic-ai-patching',
    'PLAYBOOK_PUSH_METHOD': 'git',
    'CVE_CONSOLE_HOST': '127.0.0.1',
    'CVE_CONSOLE_PORT': '8787',
    'CVE_FLOW_LOG_LEVEL': 'INFO',
    'ROI_LABOR_RATE': '72',
    'ROI_MANUAL_MIN_PER_HOST': '30',
    'ROI_AI_MIN_PER_HOST': '5',
    'ROI_EXPOSURE_MANUAL_FACTOR': '1.4',
    'ROI_EXPOSURE_AI_FACTOR': '0.6',
    'ROI_DIM_ENGINEERING_PCT': '35',
    'ROI_DIM_EXPOSURE_PCT': '44',
    'ROI_DIM_REUSE_PCT': '13',
    'ROI_DIM_RECOVERY_PCT': '8',
}


def seed_defaults():
    """Write default settings to .env for keys that have no value yet."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    existing = read_env_file()
    missing = {k: v for k, v in SETTINGS_DEFAULTS.items() if not existing.get(k)}
    if missing:
        write_env_file(missing)
        for k, v in missing.items():
            os.environ.setdefault(k, v)
        LOG.info('Seeded %d default settings: %s', len(missing), ', '.join(sorted(missing)))


if __name__ == '__main__':
    if STATE_FILE.exists():
        STATE_FILE.unlink()
        LOG.info('Cleaned previous state on startup')
    seed_defaults()
    LOG.info('Unified mode — tries real APIs first, falls back to demo data')
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    LOG.info('CVE console listening on http://%s:%s', HOST, PORT)
    server.serve_forever()
