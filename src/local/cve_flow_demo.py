#!/usr/bin/env python3
"""
Unified patch flow — tries real APIs at each stage, falls back to demo data.
Writes state.json data through all 12 scenes with timed delays.
"""
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

WORKSPACE = Path(os.environ.get('WORKSPACE', str(Path(__file__).resolve().parent)))
STATE_DIR = WORKSPACE / 'cve_console'
STATE_FILE = STATE_DIR / 'state.json'
FLOW_LOG = WORKSPACE / 'cve_console.log'

DEMO_CVE = 'CVE-2026-31337'
DEMO_CVSS = 9.8
DEMO_DESCRIPTION = (
    'A critical buffer overflow vulnerability in the RHEL kernel networking subsystem '
    'allows remote unauthenticated attackers to execute arbitrary code via a crafted '
    'TCP packet. All RHEL 8 and RHEL 9 systems with default networking configurations '
    'are affected. Red Hat has released errata RHSA-2026:4821 with a kernel update.'
)

DEMO_HOSTS = [
    {'host': 'pay-app-03.acme.internal',   'system_uuid': 'uuid-pay-03', 'age_days': 365, 'risk_score': 67.20, 'decision': 'review', 'reason': 'Tier-1 payment application — kernel update requires explicit approval.',
     'decision_support': {'summary': 'Previous patching of pay-app-03 failed twice (RHSA-2025-1842, RHSA-2025-3190). Root cause: application was not fully drained before restart. DBA intervention was required in both cases. Successful patches used a 120-second drain period with DBA present. Friday evening windows have a higher failure rate for this host.'}},
    {'host': 'pay-app-05.acme.internal',   'system_uuid': 'uuid-pay-05', 'age_days': 210, 'risk_score': 58.40, 'decision': 'review', 'reason': 'Tier-1 payment application — kernel update requires explicit approval.',
     'decision_support': {'summary': 'pay-app-05 was successfully patched 3 times in the last 6 months. All successful executions used application draining (120s) and had DBA availability confirmed. No rollbacks recorded. Risk is moderate due to workload similarity with pay-app-03.'}},
    {'host': 'pay-app-07.acme.internal',   'system_uuid': 'uuid-pay-07', 'age_days': 540, 'risk_score': 72.80, 'decision': 'review', 'reason': 'Tier-1 payment application — highest risk score in fleet.',
     'decision_support': {'summary': 'pay-app-07 has the worst patch history in the payment cluster. Last patch (RHSA-2025-3190) failed on a Friday at 18:32 — DBA was unavailable, manual restart required. Drain timeout was only 30 seconds vs. the required 120 seconds. Recommend scheduling outside Friday windows and confirming DBA availability.'}},
    {'host': 'pay-app-09.acme.internal',   'system_uuid': 'uuid-pay-09', 'age_days': 150, 'risk_score': 45.10, 'decision': 'review', 'reason': 'Tier-1 payment application — kernel update requires explicit approval.',
     'decision_support': {'summary': 'pay-app-09 patching history is clean — 4 successful patches, zero rollbacks. Application drain procedure is automated. Low operational risk but flagged due to Tier-1 classification.'}},
    {'host': 'pay-db-01.acme.internal',    'system_uuid': 'uuid-db-01',  'age_days': 420, 'risk_score': 61.50, 'decision': 'review', 'reason': 'Production database server — requires DBA coordination.',
     'decision_support': {'summary': 'pay-db-01 is the primary PostgreSQL database for payment processing. Previous kernel patches required a coordinated failover to the replica (pay-db-02). Patching without failover caused a 4-minute outage in Q1 2026. Always coordinate with DBA team and verify replica is in sync before patching.'}},
    {'host': 'pay-db-02.acme.internal',    'system_uuid': 'uuid-db-02',  'age_days': 180, 'risk_score': 38.90, 'decision': 'review', 'reason': 'Production database replica — must stay available during primary patch.',
     'decision_support': {'summary': 'pay-db-02 is the streaming replica. Should be patched AFTER pay-db-01 is confirmed healthy post-patch. No independent failure history.'}},
    {'host': 'api-gw-01.acme.internal',    'system_uuid': 'uuid-gw-01',  'age_days': 90, 'risk_score': 52.30, 'decision': 'review', 'reason': 'Production API gateway — serves external traffic.',
     'decision_support': {'summary': 'api-gw-01 runs the external-facing API gateway (nginx + custom modules). Previous kernel updates required a rolling restart coordinated with the load balancer. Two incidents in 2025 where connections were dropped during patching due to missing connection drain.'}},
    {'host': 'api-gw-02.acme.internal',    'system_uuid': 'uuid-gw-02',  'age_days': 75, 'risk_score': 48.70, 'decision': 'review', 'reason': 'Production API gateway — redundant pair.',
     'decision_support': {'summary': 'api-gw-02 is the secondary API gateway. Can be patched while api-gw-01 handles traffic. Clean patch history — 5 successful patches with zero downtime.'}},
    {'host': 'batch-proc-01.acme.internal', 'system_uuid': 'uuid-bp-01', 'age_days': 280, 'risk_score': 41.60, 'decision': 'review', 'reason': 'Production batch processing — nightly settlement jobs.',
     'decision_support': {'summary': 'batch-proc-01 runs nightly settlement processing (02:00-04:00 UTC). Must not be patched during batch window. All historical patches applied during 10:00-14:00 UTC were successful.'}},
    {'host': 'monitor-01.acme.internal',   'system_uuid': 'uuid-mon-01', 'age_days': 45, 'risk_score': 27.40, 'decision': 'ok', 'reason': 'Monitoring stack — low complexity, clean history.'},
    {'host': 'web-prod-01.acme.internal',  'system_uuid': 'uuid-web-01', 'age_days': 30, 'risk_score': 24.80, 'decision': 'ok', 'reason': 'Standard web frontend — no special dependencies.'},
    {'host': 'web-prod-02.acme.internal',  'system_uuid': 'uuid-web-02', 'age_days': 18, 'risk_score': 22.60, 'decision': 'ok', 'reason': 'Standard web frontend — recently provisioned.'},
    {'host': 'test-app-01.acme.internal',  'system_uuid': 'uuid-tst-01', 'age_days': 8,   'risk_score': 21.30, 'decision': 'ok', 'reason': 'Test environment — no production impact.'},
    {'host': 'test-app-02.acme.internal',  'system_uuid': 'uuid-tst-02', 'age_days': 15,  'risk_score': 19.70, 'decision': 'ok', 'reason': 'Test environment — standard RHEL instance.'},
    {'host': 'test-app-03.acme.internal',  'system_uuid': 'uuid-tst-03', 'age_days': 22,  'risk_score': 17.20, 'decision': 'ok', 'reason': 'Test environment — isolated network.'},
    {'host': 'test-db-01.acme.internal',   'system_uuid': 'uuid-tst-db', 'age_days': 60,  'risk_score': 26.10, 'decision': 'ok', 'reason': 'Test database — no production data.'},
    {'host': 'test-gw-01.acme.internal',   'system_uuid': 'uuid-tst-gw', 'age_days': 10,  'risk_score': 14.50, 'decision': 'ok', 'reason': 'Test gateway — mirrors prod config.'},
    {'host': 'test-batch-01.acme.internal','system_uuid': 'uuid-tst-bt', 'age_days': 5,   'risk_score': 11.80, 'decision': 'ok', 'reason': 'Test batch — no settlement data.'},
    {'host': 'test-web-01.acme.internal',  'system_uuid': 'uuid-tst-w1', 'age_days': 35,  'risk_score': 16.40, 'decision': 'ok', 'reason': 'Test web tier — clean history.'},
    {'host': 'test-web-02.acme.internal',  'system_uuid': 'uuid-tst-w2', 'age_days': 7,   'risk_score': 8.90,  'decision': 'ok', 'reason': 'Test web — recently rebuilt.'},
    {'host': 'test-web-03.acme.internal',  'system_uuid': 'uuid-tst-w3', 'age_days': 42,  'risk_score': 23.50, 'decision': 'ok', 'reason': 'Test web — older instance, stable.'},
    {'host': 'test-web-04.acme.internal',  'system_uuid': 'uuid-tst-w4', 'age_days': 14,  'risk_score': 12.70, 'decision': 'ok', 'reason': 'Test web — low utilization.'},
    {'host': 'test-web-05.acme.internal',  'system_uuid': 'uuid-tst-w5', 'age_days': 3,   'risk_score': 5.60,  'decision': 'ok', 'reason': 'Test web — freshly deployed.'},
    {'host': 'test-monitor-01.acme.internal','system_uuid':'uuid-tst-mn','age_days': 28,  'risk_score': 19.80, 'decision': 'ok', 'reason': 'Test monitoring — standalone.'},
    {'host': 'test-ci-01.acme.internal',   'system_uuid': 'uuid-tst-ci', 'age_days': 20,  'risk_score': 10.20, 'decision': 'ok', 'reason': 'CI runner — ephemeral workloads.'},
    {'host': 'dev-app-01.acme.internal',   'system_uuid': 'uuid-dev-01', 'age_days': 90,  'risk_score': 15.30, 'decision': 'ok', 'reason': 'Dev environment — shared app server.'},
    {'host': 'dev-app-02.acme.internal',   'system_uuid': 'uuid-dev-02', 'age_days': 12,  'risk_score': 7.40,  'decision': 'ok', 'reason': 'Dev — personal dev instance.'},
    {'host': 'dev-app-03.acme.internal',   'system_uuid': 'uuid-dev-03', 'age_days': 180, 'risk_score': 28.90, 'decision': 'ok', 'reason': 'Dev — legacy app testing, older kernel.'},
    {'host': 'dev-db-01.acme.internal',    'system_uuid': 'uuid-dev-db', 'age_days': 55,  'risk_score': 13.60, 'decision': 'ok', 'reason': 'Dev database — synthetic data only.'},
    {'host': 'dev-web-01.acme.internal',   'system_uuid': 'uuid-dev-w1', 'age_days': 6,   'risk_score': 3.20,  'decision': 'ok', 'reason': 'Dev web — minimal footprint.'},
    {'host': 'dev-web-02.acme.internal',   'system_uuid': 'uuid-dev-w2', 'age_days': 25,  'risk_score': 9.80,  'decision': 'ok', 'reason': 'Dev web — shared frontend testing.'},
    {'host': 'dev-web-03.acme.internal',   'system_uuid': 'uuid-dev-w3', 'age_days': 75,  'risk_score': 20.10, 'decision': 'ok', 'reason': 'Dev web — integration test target.'},
    {'host': 'dev-ci-01.acme.internal',    'system_uuid': 'uuid-dev-ci', 'age_days': 40,  'risk_score': 6.50,  'decision': 'ok', 'reason': 'Dev CI — disposable runner.'},
    {'host': 'dev-sandbox-01.acme.internal','system_uuid':'uuid-dev-sb', 'age_days': 2,   'risk_score': 2.40,  'decision': 'ok', 'reason': 'Sandbox — throwaway environment.'},
    {'host': 'dev-sandbox-02.acme.internal','system_uuid':'uuid-dev-s2', 'age_days': 120, 'risk_score': 17.80, 'decision': 'ok', 'reason': 'Sandbox — long-running experiment.'},
    {'host': 'dev-sandbox-03.acme.internal','system_uuid':'uuid-dev-s3', 'age_days': 8,   'risk_score': 4.10,  'decision': 'ok', 'reason': 'Sandbox — recently spun up.'},
    {'host': 'dev-test-runner.acme.internal','system_uuid':'uuid-dev-tr','age_days': 15,  'risk_score': 11.30, 'decision': 'ok', 'reason': 'Test runner — stateless workloads.'},
]

DEMO_PLAYBOOK_PATH = f'playbooks/generated/{DEMO_CVE}-v3-demo.yml'

OPERATIONAL_CONTEXT = {
    'environment': 'Production',
    'application': 'Payments',
    'business_criticality': 'Tier 1',
    'maintenance_window': 'Friday 18:00',
    'historical_patch_success': '91%',
    'similar_workload_success': '82%',
    'previous_failures': 3,
    'recent_incidents': 1,
    'available_automation': True,
}

PATCH_HISTORY = [
    {
        'host': 'Payment-App-03',
        'patch': 'RHSA-2025-1842',
        'result': 'FAILED',
        'notes': [
            'Application was not completely drained',
            'DBA intervention required',
            'Rollback performed',
        ],
    },
    {
        'host': 'Payment-App-05',
        'patch': 'RHSA-2025-3190',
        'result': 'SUCCESS',
        'notes': [
            'Application drained',
            'DBA present',
            '120-second drain period',
            'Health checks passed',
        ],
    },
    {
        'host': 'Payment-App-07',
        'patch': 'RHSA-2025-3190',
        'result': 'FAILED',
        'day': 'Friday',
        'time': '18:32',
        'notes': [
            'DBA unavailable',
            'Manual restart required',
        ],
    },
]

HISTORY_ANALYSIS = {
    'similar_failures': 3,
    'patterns': [
        'Failures concentrated around Friday evening windows.',
        'Similar workloads required manual intervention.',
        'Successful patches used application draining.',
        'Successful executions had DBA availability.',
        'Current window has reduced DBA availability.',
    ],
    'contextual_risk': 'HIGH',
}

LIGHTSPEED_PLAYBOOK = """- name: Drain payment application
  hosts: payment_servers
  become: true

  tasks:

    - name: Verify application health
      uri:
        url: "http://{{ inventory_hostname }}:8080/health"
        return_content: yes
      register: health_pre

    - name: Drain application traffic
      command: /opt/acme/bin/drain-app --graceful
      register: drain_result

    - name: Wait for connections to drain
      wait_for:
        timeout: 120
        msg: "Waiting for active connections to complete"

    - name: Apply security updates
      yum:
        name: kernel
        state: latest
        security: yes
      register: patch_result

    - name: Restart application
      systemd:
        name: acme-payments
        state: restarted
      when: patch_result.changed

    - name: Validate application health
      uri:
        url: "http://{{ inventory_hostname }}:8080/health"
        return_content: yes
      register: health_post
      retries: 5
      delay: 10
      until: health_post.status == 200"""


DEMO_STAGES_AGENTIC = [
    ('workflow_start',        'Patch flow started',                                    2, {
        '_a2a': [{'from': 'console', 'to': 'patch_manager', 'action': 'run_flow', 'type': 'request', 'message': 'Console → Patch Manager: initiate CVE patch flow'}],
    }),
    ('loading_cve',           'Loading CVE from Red Hat Insights',                     4, {
        '_a2a': [{'from': 'patch_manager', 'to': 'vulnerability', 'action': 'fetch_cve', 'type': 'request', 'message': 'Patch Manager → Vulnerability Agent: fetch CVE details from Insights'}],
    }),
    ('loading_cve_done',      'CVE loaded — 37 affected systems identified',           3, {
        '_add_cve_meta': True,
        '_a2a': [{'from': 'vulnerability', 'to': 'patch_manager', 'action': 'fetch_cve', 'type': 'response', 'message': 'Vulnerability Agent → Patch Manager: CVE loaded — 37 affected systems, CVSS 9.8'}],
    }),
    ('enriching_context',     'Enriching with operational context — CMDB, ITSM',       4, {
        '_add_operational_context': True,
        '_a2a': [{'from': 'patch_manager', 'to': 'risk', 'action': 'enrich_context', 'type': 'request', 'message': 'Patch Manager → Risk Agent: enrich with operational context from CMDB, ITSM'}],
    }),
    ('scoring_hosts',         'Invoking RHOAI predictive risk model',                  5, {
        '_add_hosts_partial': True,
        '_a2a': [
            {'from': 'patch_manager', 'to': 'risk', 'action': 'score_hosts', 'type': 'request', 'message': 'Patch Manager → Risk Agent: score 37 hosts with RHOAI predictive model'},
            {'from': 'risk', 'to': 'risk', 'action': 'rag_lookup', 'type': 'event', 'message': 'Risk Agent: querying RAG vector store for historical patch records'},
        ],
    }),
    ('scoring_hosts_done',    'Risk assessment: 27% failure probability, HIGH risk',   3, {
        '_add_hosts_full': True,
        '_a2a': [{'from': 'risk', 'to': 'patch_manager', 'action': 'score_hosts', 'type': 'response', 'message': 'Risk Agent → Patch Manager: 9 hosts require review, 24% failure probability, HIGH risk'}],
    }),
    ('analyzing_history',     'LLM analyzing historical patch records via RAG',        6, {
        '_add_history': True,
        '_a2a': [
            {'from': 'risk', 'to': 'risk', 'action': 'llm_analyze', 'type': 'event', 'message': 'Risk Agent: LLM analyzing patch history — failures on Fridays, drain timeout issues'},
            {'from': 'risk', 'to': 'patch_manager', 'action': 'history_analysis', 'type': 'event', 'message': 'Risk Agent → Patch Manager: historical pattern detected — Friday patches have higher failure rate'},
        ],
    }),
    ('generating_strategy',   'Creating phased patch strategy: Test → Canary → Prod',  4, {
        '_add_strategy': True,
        '_a2a': [{'from': 'patch_manager', 'to': 'automation', 'action': 'plan_strategy', 'type': 'request', 'message': 'Patch Manager → Automation Agent: create phased strategy — Test → Canary → Production'}],
    }),
    ('lightspeed_assist',     'Ansible Lightspeed generating drain procedure playbook', 4, {
        '_add_lightspeed': True,
        '_a2a': [
            {'from': 'patch_manager', 'to': 'automation', 'action': 'generate_playbook', 'type': 'request', 'message': 'Patch Manager → Automation Agent: generate remediation playbook with drain procedure'},
            {'from': 'automation', 'to': 'patch_manager', 'action': 'generate_playbook', 'type': 'response', 'message': 'Automation Agent → Patch Manager: playbook generated with 120s drain timeout (learned from history)'},
        ],
    }),
    ('publishing_playbook',   'Publishing playbook to GitHub',                         3, {
        '_add_playbook': True,
        '_a2a': [{'from': 'automation', 'to': 'automation', 'action': 'publish', 'type': 'event', 'message': 'Automation Agent: publishing playbook to GitHub via MCP'}],
    }),
    ('syncing_aap_project',   'Syncing AAP project from GitHub',                       3, {
        '_add_sync_project': True,
        '_a2a': [{'from': 'automation', 'to': 'automation', 'action': 'sync_aap', 'type': 'event', 'message': 'Automation Agent: syncing AAP project from GitHub'}],
    }),
    ('creating_aap_templates','Creating AAP job and workflow templates',               3, {
        '_add_templates': True,
        '_a2a': [{'from': 'automation', 'to': 'patch_manager', 'action': 'create_templates', 'type': 'response', 'message': 'Automation Agent → Patch Manager: AAP templates created with approval gate'}],
    }),
    ('launching_workflow',    'Launching AAP workflow — waiting for approval gate',     2, {
        '_add_workflow_pending': True,
        '_a2a': [{'from': 'patch_manager', 'to': 'automation', 'action': 'launch_workflow', 'type': 'request', 'message': 'Patch Manager → Automation Agent: launch AAP workflow — human approval required'}],
    }),
    ('awaiting_aap',          'Workflow running — waiting for operator approval',       0, {
        '_add_approval_pending': True,
        '_a2a': [{'from': 'patch_manager', 'to': 'console', 'action': 'awaiting_approval', 'type': 'event', 'message': 'Patch Manager → Console: workflow paused — awaiting human approval'}],
    }),
]


REVIEW_THRESHOLD = 30.0


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def log(msg):
    ts = now_iso()
    line = f'{ts} [cve-flow] INFO {msg}'
    print(line, file=sys.stderr)
    with open(FLOW_LOG, 'a') as f:
        f.write(line + '\n')


def write_state(state):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def base_state(triggered_at):
    return {
        'active_flow': {'cve': DEMO_CVE, 'pid': os.getpid(), 'triggered_at': triggered_at},
        'workflow': {
            'name': f'{DEMO_CVE} remediation workflow',
            'cve': DEMO_CVE,
            'status': 'in_progress',
            'flow_stage': 'starting',
            'last_updated': triggered_at,
            'triggered_at': triggered_at,
            'polling': 'flow_in_progress',
        },
        'summary': {
            'flow_stage': 'starting',
            'flow_message': 'Patch flow started...',
            'approval_state': 'flow_in_progress',
            'last_workflow_status': 'not_started',
            'last_job_status': 'not_started',
            'mode': 'hybrid-v3',
        },
        'hosts': [],
        'stream': [],
        'aap': {'enabled': False, 'base_url': None},
        'runs': [],
    }


def strict_mode() -> bool:
    """STRICT_MODE=true turns every fallback into a hard failure.

    Use when verifying which backends are actually wired up — graceful
    degradation is exactly what hides a missing service.
    """
    return os.environ.get('STRICT_MODE', '').strip().lower() in {'1', 'true', 'yes'}


def try_real(stage_name, real_fn, fallback_data, fix_hint):
    """Try a real API call; on failure return fallback data with clear logging."""
    try:
        result = real_fn()
        log(f'  LIVE: {stage_name} — using real API data')
        return result, 'LIVE'
    except Exception as exc:
        if strict_mode():
            log(f'  STRICT FAIL: {stage_name} ({type(exc).__name__}: {exc}). FIX: {fix_hint}')
            raise RuntimeError(
                f'{stage_name} failed and STRICT_MODE is enabled: '
                f'{type(exc).__name__}: {exc}. FIX: {fix_hint}'
            ) from exc
        log(f'  FALLBACK: {stage_name} failed ({type(exc).__name__}: {exc}). Using fallback data. FIX: {fix_hint}')
        return fallback_data, 'FALLBACK'


def _try_fetch_cve(cve_id):
    """Try real CVE fetch from Insights; fall back to demo data."""
    import cve_flow
    def real():
        cve_data, systems = cve_flow.fetch_cve_and_systems(cve_id)
        attrs = cve_data.get('data', {}).get('attributes', {}) if isinstance(cve_data, dict) else {}
        cvss = float(attrs.get('cvss3_score') or attrs.get('cvss2_score') or 0.0)
        description = attrs.get('description') or ''
        hosts = []
        for s in systems:
            s_attrs = s.get('attributes', {}) if isinstance(s, dict) else {}
            host_name = s_attrs.get('display_name') or s.get('id') or 'unknown'
            first_reported = s_attrs.get('first_reported')
            hosts.append({
                'host': host_name,
                'system_uuid': s.get('id'),
                'age_days': cve_flow.age_days_from_timestamp(first_reported),
            })
        return {
            'cvss': cvss or DEMO_CVSS,
            'description': description or DEMO_DESCRIPTION,
            'hosts': hosts,
            'count': len(hosts),
        }

    fallback = {
        'cvss': DEMO_CVSS,
        'description': DEMO_DESCRIPTION,
        'hosts': [{'host': h['host'], 'system_uuid': h['system_uuid'], 'age_days': h['age_days']} for h in DEMO_HOSTS],
        'count': len(DEMO_HOSTS),
    }
    return try_real('fetch_cve_and_systems', real, fallback,
                    'configure INSIGHTS_MCP_ENDPOINT + LIGHTSPEED_CLIENT_ID/SECRET in .env')


def _try_score_hosts(hosts_raw, cvss):
    """Try real RHOAI risk scoring; fall back to demo scores."""
    import cve_flow
    affected_count = len(hosts_raw)

    def real():
        result = []
        for h in hosts_raw:
            score = cve_flow.risk_score(cvss, h['age_days'], affected_count)
            decision = 'review' if score > REVIEW_THRESHOLD else 'ok'
            reason = 'Risk score exceeds threshold — requires review.' if decision == 'review' else 'Below risk threshold.'
            result.append({**h, 'risk_score': score, 'decision': decision, 'reason': reason})
        return result

    fallback = list(DEMO_HOSTS)
    return try_real('risk_score (RHOAI model)', real, fallback,
                    'configure RISK_URL in .env')


def _try_rag_summaries(hosts):
    """Try real RAG summaries for review hosts; fall back to demo decision_support."""
    import cve_flow
    vector_db_id = os.environ.get('VECTOR_DB_ID', 'patch_history')

    def real():
        result = []
        for h in hosts:
            if h.get('decision') == 'review':
                rag = cve_flow.rag_summary_for_host(h['host'], vector_db_id)
                result.append({**h, 'decision_support': rag})
            else:
                result.append(h)
        return result

    demo_support = {h['host']: h.get('decision_support') for h in DEMO_HOSTS if h.get('decision_support')}
    fallback = []
    for h in hosts:
        if h.get('decision') == 'review' and h['host'] in demo_support:
            fallback.append({**h, 'decision_support': demo_support[h['host']]})
        else:
            fallback.append(h)

    return try_real('rag_summary_for_host (RAG + LLM)', real, fallback,
                    'configure LLAMA_STACK_URL + VECTOR_DB_ID in .env')


def _try_generate_playbook(cve_id, hosts):
    """Try real playbook generation via Insights MCP; fall back to demo playbook."""
    import cve_flow

    def real():
        uuids = [h.get('system_uuid') or '' for h in hosts if h.get('system_uuid')]
        yaml_text = cve_flow.generate_playbook(cve_id, uuids[:20])
        return {'needed': True, 'reason': 'Generated via Insights remediations MCP.', 'generated_content': yaml_text}

    fallback = {
        'needed': True,
        'reason': 'No approved playbook exists for application-specific pre-patch drain procedure.',
        'generated_content': LIGHTSPEED_PLAYBOOK,
    }
    return try_real('generate_playbook (Insights MCP)', real, fallback,
                    'configure INSIGHTS_MCP_ENDPOINT + LIGHTSPEED_CLIENT_ID/SECRET in .env')


def _try_publish_playbook(cve_id, playbook_yaml):
    """Try real playbook publish to GitHub; fall back to demo path."""
    import cve_flow

    def real():
        repo_root = cve_flow.DEFAULT_AAP_PROJECT_CHECKOUT
        playbook_path = f'playbooks/generated/{cve_id}-remediation.yml'
        full_path = repo_root / playbook_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(playbook_yaml)
        method = cve_flow.playbook_push_method()
        cve_flow.publish_playbook(repo_root, playbook_path, cve_id, playbook_yaml)
        return {'path': playbook_path, 'method': method}

    fallback = {'path': DEMO_PLAYBOOK_PATH, 'method': 'git'}
    return try_real('publish_playbook (GitHub)', real, fallback,
                    'configure GITHUB_TOKEN + GITHUB_MCP_ENDPOINT or GITHUB_REPO_* in .env')


def _try_sync_project():
    """Try real AAP project sync; fall back silently."""
    import cve_flow

    def real():
        return cve_flow.sync_project()

    return try_real('sync_project (AAP)', real, {},
                    'configure AAP_BASE_URL + AAP_TOKEN in .env')


def _try_create_templates(cve_id, playbook_path):
    """Try real AAP template creation; fall back to demo template IDs."""
    import cve_flow

    def real():
        return cve_flow.create_templates(cve_id, playbook_path)

    fallback = {
        'job_template_id': 98,
        'workflow_template_id': 99,
        'job_template_url': '#fallback-job-template',
        'workflow_template_url': '#fallback-workflow-template',
    }
    return try_real('create_templates (AAP)', real, fallback,
                    'configure AAP_BASE_URL + AAP_TOKEN in .env')


def _try_launch_workflow(workflow_template_id):
    """Try real AAP workflow launch; fall back to demo workflow job stub."""
    import cve_flow

    def real():
        return cve_flow.launch_workflow_template(workflow_template_id)

    return try_real('launch_workflow (AAP)', real, None,
                    'configure AAP_BASE_URL + AAP_TOKEN in .env')


def run_unified_flow(cve_id=None, speed=1.0):
    """Run the staged flow — tries real APIs at each stage, falls back to demo data."""
    cve = cve_id or DEMO_CVE
    triggered_at = now_iso()
    state = base_state(triggered_at)
    state['workflow']['cve'] = cve

    run_entry = {
        'triggered_at': triggered_at,
        'workflow': dict(state['workflow']),
        'summary': dict(state['summary']),
        'hosts': [],
        'aap': dict(state['aap']),
    }
    state['runs'] = [run_entry]
    write_state(state)

    stages = DEMO_STAGES_AGENTIC
    log(f'FLOW starting cve={cve} speed={speed}x')

    ctx = {
        'cvss': None,
        'hosts_raw': None,
        'hosts_scored': None,
        'hosts_full': None,
        'playbook_yaml': None,
        'playbook_path': None,
        'workflow_template_id': None,
        'job_template_id': None,
        'source_log': [],
    }

    for stage_key, message, delay, extras in stages:
        flow_stage = stage_key.split('_done')[0].split('_rag')[0].split('_partial')[0]

        ts = now_iso()
        log(f'STEP {stage_key} — {message}')

        state['workflow']['flow_stage'] = flow_stage
        state['workflow']['last_updated'] = ts
        state['summary']['flow_stage'] = flow_stage
        state['summary']['flow_message'] = message
        state['summary']['approval_state'] = 'flow_in_progress'

        state['stream'].append({'time': ts, 'event': stage_key, 'message': message})

        for a2a_msg in extras.get('_a2a', []):
            state['stream'].append({
                'time': ts,
                'event': 'a2a_message',
                'from': a2a_msg['from'],
                'to': a2a_msg['to'],
                'type': a2a_msg['type'],
                'action': a2a_msg['action'],
                'message': a2a_msg['message'],
            })

        if extras.get('_add_cve_meta'):
            cve_data, source = _try_fetch_cve(cve)
            ctx['source_log'].append(('fetch_cve', source))
            ctx['cvss'] = cve_data['cvss']
            ctx['hosts_raw'] = cve_data['hosts']
            state['summary']['cvss'] = cve_data['cvss']
            state['summary']['affected_count'] = cve_data['count']
            state['summary']['cve_summary'] = cve_data['description']
            state['hosts'] = list(cve_data['hosts'])

        if extras.get('_add_operational_context'):
            state['summary']['operational_context'] = OPERATIONAL_CONTEXT

        if extras.get('_add_hosts_partial'):
            hosts_to_score = ctx.get('hosts_raw') or [
                {'host': h['host'], 'system_uuid': h['system_uuid'], 'age_days': h['age_days']}
                for h in DEMO_HOSTS
            ]
            cvss = ctx.get('cvss') or DEMO_CVSS
            scored, source = _try_score_hosts(hosts_to_score, cvss)
            ctx['source_log'].append(('risk_score', source))
            ctx['hosts_scored'] = scored
            state['hosts'] = [
                {k: v for k, v in h.items() if k != 'decision_support'}
                for h in scored
            ]

        if extras.get('_add_hosts_full'):
            hosts_to_enrich = ctx.get('hosts_scored') or DEMO_HOSTS
            enriched, source = _try_rag_summaries(hosts_to_enrich)
            ctx['source_log'].append(('rag_summary', source))
            ctx['hosts_full'] = enriched
            state['hosts'] = enriched
            state['summary']['failure_probability'] = 27
            state['summary']['impact_probability'] = 34
            state['summary']['risk_classification'] = 'HIGH'

        if extras.get('_add_history'):
            state['summary']['patch_history'] = PATCH_HISTORY
            state['summary']['history_analysis'] = HISTORY_ANALYSIS

        if extras.get('_add_strategy'):
            hosts = ctx.get('hosts_scored') or DEMO_HOSTS
            review_count = sum(1 for h in hosts if h.get('decision') == 'review')
            ok_count = len(hosts) - review_count
            test_count = ok_count
            canary_count = min(3, review_count)
            prod_count = review_count - canary_count
            state['summary']['patch_strategy'] = {
                'phases': [
                    {'name': 'Test Systems', 'count': test_count, 'status': 'planned'},
                    {'name': 'Production Canaries', 'count': canary_count, 'status': 'planned'},
                    {'name': 'Remaining Production', 'count': prod_count, 'status': 'planned'},
                ],
                'existing_automation': 'patch_rhel_security_v4.yml',
            }

        if extras.get('_add_lightspeed'):
            hosts = ctx.get('hosts_full') or DEMO_HOSTS
            ls_data, source = _try_generate_playbook(cve, hosts)
            ctx['source_log'].append(('generate_playbook', source))
            ctx['playbook_yaml'] = ls_data['generated_content']
            state['summary']['lightspeed'] = ls_data

        if extras.get('_add_playbook'):
            yaml_content = ctx.get('playbook_yaml') or LIGHTSPEED_PLAYBOOK
            pub_data, source = _try_publish_playbook(cve, yaml_content)
            ctx['source_log'].append(('publish_playbook', source))
            ctx['playbook_path'] = pub_data['path']
            state['summary']['playbook_path'] = pub_data['path']
            state['summary']['playbook_push_method'] = pub_data['method']

        if extras.get('_add_sync_project'):
            _, source = _try_sync_project()
            ctx['source_log'].append(('sync_project', source))

        if extras.get('_add_templates'):
            playbook_path = ctx.get('playbook_path') or DEMO_PLAYBOOK_PATH
            tmpl_data, source = _try_create_templates(cve, playbook_path)
            ctx['source_log'].append(('create_templates', source))
            ctx['job_template_id'] = tmpl_data.get('job_template_id', 98)
            ctx['workflow_template_id'] = tmpl_data.get('workflow_template_id', 99)
            state['summary']['job_template_url'] = tmpl_data.get('job_template_url', '#fallback-job-template')
            state['summary']['workflow_template_url'] = tmpl_data.get('workflow_template_url', '#fallback-workflow-template')
            state['aap'] = {
                'enabled': True,
                'base_url': tmpl_data.get('base_url', '#fallback'),
                'workflow_template_id': ctx['workflow_template_id'],
                'job_template_id': ctx['job_template_id'],
            }

        if extras.get('_add_workflow_pending'):
            wf_id = ctx.get('workflow_template_id') or 99
            wf_result, source = _try_launch_workflow(wf_id)
            ctx['source_log'].append(('launch_workflow', source))
            if wf_result and isinstance(wf_result, dict) and wf_result.get('id'):
                state['aap']['latest_workflow_job'] = {
                    'id': wf_result['id'],
                    'name': wf_result.get('name', f'{cve} approval workflow'),
                    'status': wf_result.get('status', 'waiting'),
                    'started': ts,
                    'finished': None,
                    'url': wf_result.get('url', f'#workflow-job-{wf_result["id"]}'),
                }
            else:
                state['aap']['latest_workflow_job'] = {
                    'id': 1001,
                    'name': f'{cve} approval workflow',
                    'status': 'waiting',
                    'started': ts,
                    'finished': None,
                    'url': '#fallback-workflow-job-1001',
                }
            state['summary']['last_workflow_status'] = 'waiting'

        if extras.get('_add_approval_pending'):
            state['aap']['pending_approvals'] = [{
                'id': 2001,
                'name': 'approval_review',
                'status': 'pending',
            }]
            state['summary']['approval_state'] = 'pending_review'
            state['summary']['display_workflow_status'] = 'waiting_for_approval'
            state['workflow']['status'] = 'waiting'

        run_entry['workflow'] = dict(state['workflow'])
        run_entry['summary'] = dict(state['summary'])
        run_entry['hosts'] = state['hosts']
        run_entry['aap'] = dict(state['aap'])
        state['runs'] = [run_entry]

        write_state(state)

        if delay > 0:
            time.sleep(delay / speed)

    live_count = sum(1 for _, s in ctx['source_log'] if s == 'LIVE')
    total_count = len(ctx['source_log'])
    fallback_count = total_count - live_count
    log(f'FLOW SUMMARY: {live_count}/{total_count} stages used LIVE data, {fallback_count}/{total_count} used FALLBACK')
    for name, source in ctx['source_log']:
        log(f'  {source}: {name}')

    log('Awaiting approval — press Enter or use the UI Approve button to continue')
    state.pop('active_flow', None)
    write_state(state)

    return state


def run_post_approval(state=None, speed=1.0):
    """Simulate scenes 8-12: phased execution with failure, remediation, and learning."""
    if STATE_FILE.exists():
        state = json.loads(STATE_FILE.read_text())
    if not state:
        log('ERROR: No state file found for approval simulation')
        return

    for _ in range(30):
        if STATE_FILE.exists():
            state = json.loads(STATE_FILE.read_text())
        pending = (state.get('aap') or {}).get('pending_approvals') or []
        wf_job = (state.get('aap') or {}).get('latest_workflow_job')
        if pending or wf_job:
            break
        time.sleep(1)
    if STATE_FILE.exists():
        state = json.loads(STATE_FILE.read_text())

    cve = (state.get('workflow') or {}).get('cve', DEMO_CVE)

    strategy = (state.get('summary') or {}).get('patch_strategy', {})
    phases = strategy.get('phases', [])
    T = phases[0]['count'] if len(phases) > 0 else 25
    C = phases[1]['count'] if len(phases) > 1 else 3
    P = phases[2]['count'] if len(phases) > 2 else 9
    T_mid = max(1, T // 2)
    P_mid = max(1, (P * 2) // 3)

    post_approval_stages = [
        ('approved', 'Approval granted — starting phased execution', 2, {
            'approval_state': 'approved_in_progress',
            'wf_status': 'running',
            '_a2a': [
                {'from': 'console', 'to': 'patch_manager', 'action': 'approval_granted', 'type': 'event', 'message': 'Console → Patch Manager: human approval granted — proceed with execution'},
                {'from': 'patch_manager', 'to': 'automation', 'action': 'execute_phased', 'type': 'request', 'message': 'Patch Manager → Automation Agent: begin phased execution — Test → Canary → Production'},
            ],
        }),
        ('executing_test', f'Phase 1: Patching test systems (0/{T})', 3, {
            'exec_progress': {'test': {'total': T, 'completed': 0, 'status': 'running'}, 'canary': {'total': C, 'completed': 0, 'status': 'pending'}, 'production': {'total': P, 'completed': 0, 'status': 'pending'}},
            '_a2a': [{'from': 'automation', 'to': 'patch_manager', 'action': 'phase_update', 'type': 'event', 'message': f'Automation Agent → Patch Manager: Phase 1 started — patching {T} test systems'}],
        }),
        ('executing_test_mid', f'Phase 1: Patching test systems ({T_mid}/{T})', 3, {
            'exec_progress': {'test': {'total': T, 'completed': T_mid, 'status': 'running'}, 'canary': {'total': C, 'completed': 0, 'status': 'pending'}, 'production': {'total': P, 'completed': 0, 'status': 'pending'}},
            'slack': f'Phase 1 in progress — {T_mid}/{T} test systems patched',
        }),
        ('test_complete', f'Phase 1 complete — {T}/{T} test systems patched', 2, {
            'exec_progress': {'test': {'total': T, 'completed': T, 'status': 'complete'}, 'canary': {'total': C, 'completed': 0, 'status': 'pending'}, 'production': {'total': P, 'completed': 0, 'status': 'pending'}},
            'slack': f'Test environment completed — all {T} systems patched successfully',
            '_a2a': [{'from': 'automation', 'to': 'patch_manager', 'action': 'phase_complete', 'type': 'response', 'message': f'Automation Agent → Patch Manager: Phase 1 complete — {T}/{T} test systems healthy'}],
        }),
        ('executing_canary', f'Phase 2: Patching production canaries (0/{C})', 3, {
            'exec_progress': {'test': {'total': T, 'completed': T, 'status': 'complete'}, 'canary': {'total': C, 'completed': 0, 'status': 'running'}, 'production': {'total': P, 'completed': 0, 'status': 'pending'}},
            '_a2a': [{'from': 'patch_manager', 'to': 'automation', 'action': 'execute_phase', 'type': 'request', 'message': 'Patch Manager → Automation Agent: proceed to Phase 2 — canary validation'}],
        }),
        ('canary_complete', f'Phase 2 complete — {C}/{C} canary systems validated', 2, {
            'exec_progress': {'test': {'total': T, 'completed': T, 'status': 'complete'}, 'canary': {'total': C, 'completed': C, 'status': 'complete'}, 'production': {'total': P, 'completed': 0, 'status': 'pending'}},
            'slack': f'Canary validation passed — {C}/{C} production canaries healthy',
            '_a2a': [{'from': 'automation', 'to': 'patch_manager', 'action': 'phase_complete', 'type': 'response', 'message': f'Automation Agent → Patch Manager: Phase 2 complete — {C}/{C} canaries validated'}],
        }),
        ('executing_production', f'Phase 3: Patching remaining production (0/{P})', 2, {
            'exec_progress': {'test': {'total': T, 'completed': T, 'status': 'complete'}, 'canary': {'total': C, 'completed': C, 'status': 'complete'}, 'production': {'total': P, 'completed': 0, 'status': 'running'}},
            'slack': 'Production rollout started',
            '_a2a': [{'from': 'patch_manager', 'to': 'automation', 'action': 'execute_phase', 'type': 'request', 'message': 'Patch Manager → Automation Agent: proceed to Phase 3 — production rollout'}],
        }),
        ('executing_production_mid', f'Phase 3: Patching production ({P_mid}/{P})', 3, {
            'exec_progress': {'test': {'total': T, 'completed': T, 'status': 'complete'}, 'canary': {'total': C, 'completed': C, 'status': 'complete'}, 'production': {'total': P, 'completed': P_mid, 'status': 'running'}},
            'slack': f'Production: {P_mid}/{P} systems completed',
        }),
        ('patch_failure', 'ALERT: PAY-APP-07 post-patch health check FAILED', 3, {
            'exec_progress': {'test': {'total': T, 'completed': T, 'status': 'complete'}, 'canary': {'total': C, 'completed': C, 'status': 'complete'}, 'production': {'total': P, 'completed': P_mid, 'status': 'paused'}},
            'failure': {
                'host': 'pay-app-07.acme.internal',
                'check': 'POST-PATCH HEALTH CHECK',
                'status': 'FAILED',
            },
            'slack': 'ALERT: PAY-APP-07 post-patch health check FAILED — production rollout paused',
            '_a2a': [
                {'from': 'automation', 'to': 'patch_manager', 'action': 'patch_failure', 'type': 'error', 'message': 'Automation Agent → Patch Manager: ALERT — PAY-APP-07 health check FAILED, rollout paused'},
                {'from': 'patch_manager', 'to': 'diagnosis', 'action': 'analyze_failure', 'type': 'request', 'message': 'Patch Manager → Diagnosis Agent: analyze failure on PAY-APP-07'},
            ],
        }),
        ('rollback', 'Ansible performing automatic rollback on PAY-APP-07', 3, {
            'failure': {
                'host': 'pay-app-07.acme.internal',
                'check': 'POST-PATCH HEALTH CHECK',
                'status': 'FAILED',
                'rollback_status': 'SUCCESS',
                'app_status': 'HEALTHY',
                'patch_status': 'NOT APPLIED',
            },
            'slack': 'PAY-APP-07: Rollback successful — application healthy, patch NOT applied',
            '_a2a': [{'from': 'automation', 'to': 'patch_manager', 'action': 'rollback_complete', 'type': 'response', 'message': 'Automation Agent → Patch Manager: rollback successful — PAY-APP-07 healthy, patch reverted'}],
        }),
        ('analyzing_failure', 'Diagnosis Agent analyzing failure — searching historical records', 4, {
            'failure_analysis': {
                'current_failure': {
                    'host': 'PAY-APP-07',
                    'application': 'Payments',
                    'patch': cve,
                },
                'similar_records': [
                    {'host': 'Payment-App-03', 'result': 'Similar failure'},
                    {'host': 'Payment-App-05', 'result': 'Successful execution'},
                    {'host': 'Payment-App-09', 'result': 'Successful execution'},
                ],
                'likely_cause': 'Application drain timeout',
                'evidence': {
                    'failed_drain': '30 seconds',
                    'successful_drain': '120 seconds',
                },
                'recommendation': 'Increase drain timeout from 30 seconds to 120 seconds',
            },
            '_a2a': [
                {'from': 'diagnosis', 'to': 'diagnosis', 'action': 'rag_lookup', 'type': 'event', 'message': 'Diagnosis Agent: searching RAG vector store for similar failure patterns'},
                {'from': 'diagnosis', 'to': 'diagnosis', 'action': 'llm_analyze', 'type': 'event', 'message': 'Diagnosis Agent: LLM correlating 3 similar records — drain timeout pattern identified'},
                {'from': 'diagnosis', 'to': 'patch_manager', 'action': 'analyze_failure', 'type': 'response', 'message': 'Diagnosis Agent → Patch Manager: root cause = insufficient drain timeout (30s vs required 120s)'},
            ],
        }),
        ('remediation_proposed', 'Remediation: increase drain timeout 30s to 120s', 3, {
            'remediation': {
                'problem': 'Post-patch application health failure',
                'proposed_change': 'Increase application drain timeout',
                'from_value': '30 seconds',
                'to_value': '120 seconds',
                'evidence_count': 3,
                'risk': 'Medium',
                'approval_required': True,
                'status': 'proposed',
            },
            '_a2a': [
                {'from': 'diagnosis', 'to': 'patch_manager', 'action': 'propose_remediation', 'type': 'request', 'message': 'Diagnosis Agent → Patch Manager: propose increasing drain timeout 30s → 120s (3 supporting records)'},
                {'from': 'patch_manager', 'to': 'console', 'action': 'remediation_approval', 'type': 'event', 'message': 'Patch Manager → Console: remediation requires approval — increase drain timeout'},
            ],
        }),
        ('remediation_approved', 'Remediation approved — retrying PAY-APP-07', 2, {
            'remediation': {
                'problem': 'Post-patch application health failure',
                'proposed_change': 'Increase application drain timeout',
                'from_value': '30 seconds',
                'to_value': '120 seconds',
                'evidence_count': 3,
                'risk': 'Medium',
                'approval_required': True,
                'status': 'executing',
            },
            '_a2a': [
                {'from': 'console', 'to': 'patch_manager', 'action': 'remediation_approved', 'type': 'event', 'message': 'Console → Patch Manager: remediation approved'},
                {'from': 'patch_manager', 'to': 'automation', 'action': 'execute_remediation', 'type': 'request', 'message': 'Patch Manager → Automation Agent: retry PAY-APP-07 with 120s drain timeout'},
            ],
        }),
        ('remediation_executing', 'Executing remediation on PAY-APP-07 with 120s drain', 4, {
            'remediation_progress': {
                'host': 'PAY-APP-07',
                'steps': [
                    {'name': 'Application drain', 'status': 'complete'},
                    {'name': 'Patch', 'status': 'complete'},
                    {'name': 'Restart', 'status': 'complete'},
                    {'name': 'Health check', 'status': 'complete'},
                    {'name': 'Connectivity', 'status': 'complete'},
                ],
                'result': 'SUCCESS',
            },
            'slack': 'PAY-APP-07 patched successfully after remediation (120s drain)',
            '_a2a': [{'from': 'automation', 'to': 'patch_manager', 'action': 'remediation_complete', 'type': 'response', 'message': 'Automation Agent → Patch Manager: PAY-APP-07 patched successfully with 120s drain — all health checks passed'}],
        }),
        ('remediation_success', 'PAY-APP-07 patched successfully — resuming rollout', 2, {
            'exec_progress': {'test': {'total': T, 'completed': T, 'status': 'complete'}, 'canary': {'total': C, 'completed': C, 'status': 'complete'}, 'production': {'total': P, 'completed': P_mid + 1, 'status': 'running'}},
            '_a2a': [{'from': 'patch_manager', 'to': 'automation', 'action': 'resume_rollout', 'type': 'request', 'message': f'Patch Manager → Automation Agent: resume production rollout ({P_mid + 1}/{P} complete)'}],
        }),
        ('rollout_complete', f'Production rollout complete — {P}/{P} systems patched', 2, {
            'exec_progress': {'test': {'total': T, 'completed': T, 'status': 'complete'}, 'canary': {'total': C, 'completed': C, 'status': 'complete'}, 'production': {'total': P, 'completed': P, 'status': 'complete'}},
            'slack': f'Production rollout complete — all {P} production systems patched',
            '_a2a': [{'from': 'automation', 'to': 'patch_manager', 'action': 'rollout_complete', 'type': 'response', 'message': f'Automation Agent → Patch Manager: all {P} production systems patched successfully'}],
        }),
        ('workflow_complete', f'All {T+C+P} systems patched — generating training records', 2, {
            'approval_state': 'approved_and_completed',
            'wf_status': 'successful',
            'job_status': 'successful',
            'exec_progress': {'test': {'total': T, 'completed': T, 'status': 'complete'}, 'canary': {'total': C, 'completed': C, 'status': 'complete'}, 'production': {'total': P, 'completed': P, 'status': 'complete'}},
            'final_summary': {
                'systems_evaluated': T + C + P,
                'systems_patched': T + C + P,
                'initial_failure_prediction': '27%',
                'actual_failures': 1,
                'automatic_rollbacks': 1,
                'human_interventions': 1,
                'historical_records_updated': T + C + P,
                'training_events_generated': T + C + P,
            },
            '_a2a': [
                {'from': 'patch_manager', 'to': 'learning', 'action': 'update_training', 'type': 'request', 'message': f'Patch Manager → Learning Agent: generate {T+C+P} training records for continuous learning'},
                {'from': 'learning', 'to': 'patch_manager', 'action': 'training_complete', 'type': 'response', 'message': 'Learning Agent → Patch Manager: training data updated — drain timeout pattern added to model'},
                {'from': 'patch_manager', 'to': 'console', 'action': 'flow_complete', 'type': 'event', 'message': f'Patch Manager → Console: flow complete — {T+C+P}/{T+C+P} systems patched, model updated'},
            ],
        }),
    ]

    # ── ROI Agent stages (after workflow_complete) ──
    # All values configurable via Settings → ROI Agent
    labor_rate = float(os.environ.get('ROI_LABOR_RATE', '72'))
    manual_min_per_host = float(os.environ.get('ROI_MANUAL_MIN_PER_HOST', '30'))
    ai_min_per_host = float(os.environ.get('ROI_AI_MIN_PER_HOST', '5'))
    exposure_manual_factor = float(os.environ.get('ROI_EXPOSURE_MANUAL_FACTOR', '1.4'))
    exposure_ai_factor = float(os.environ.get('ROI_EXPOSURE_AI_FACTOR', '0.6'))
    dim_engineering_pct = float(os.environ.get('ROI_DIM_ENGINEERING_PCT', '35')) / 100
    dim_exposure_pct = float(os.environ.get('ROI_DIM_EXPOSURE_PCT', '44')) / 100
    dim_reuse_pct = float(os.environ.get('ROI_DIM_REUSE_PCT', '13')) / 100
    dim_recovery_pct = float(os.environ.get('ROI_DIM_RECOVERY_PCT', '8')) / 100

    total_systems = T + C + P
    manual_hours = round(total_systems * manual_min_per_host / 60, 1)
    ai_hours = round(total_systems * ai_min_per_host / 60, 1)
    hours_saved = round(manual_hours - ai_hours, 1)
    labor_saved = round(hours_saved * labor_rate)
    manual_cost_per_host = round(manual_min_per_host * labor_rate / 60)
    ai_cost_per_host = round(ai_min_per_host * labor_rate / 60)
    cost_reduction_pct = round((1 - ai_cost_per_host / max(manual_cost_per_host, 1)) * 100)
    exposure_manual_hrs = round(manual_hours * exposure_manual_factor, 1)
    exposure_ai_hrs = round(ai_hours * exposure_ai_factor, 1)

    roi_data = {
        'assumptions': {
            'labor_rate': labor_rate,
            'manual_min_per_host': manual_min_per_host,
            'ai_min_per_host': ai_min_per_host,
            'exposure_manual_factor': exposure_manual_factor,
            'exposure_ai_factor': exposure_ai_factor,
            'dim_pcts': {'engineering': round(dim_engineering_pct * 100), 'exposure': round(dim_exposure_pct * 100), 'reuse': round(dim_reuse_pct * 100), 'recovery': round(dim_recovery_pct * 100)},
        },
        'systems': total_systems,
        'manual_hours': manual_hours,
        'ai_hours': ai_hours,
        'hours_saved': hours_saved,
        'labor_saved': labor_saved,
        'manual_cost_per_host': manual_cost_per_host,
        'ai_cost_per_host': ai_cost_per_host,
        'cost_reduction_pct': cost_reduction_pct,
        'exposure_manual_hrs': exposure_manual_hrs,
        'exposure_ai_hrs': exposure_ai_hrs,
        'dimensions': {
            'engineering_effort': round(hours_saved * labor_rate * dim_engineering_pct),
            'reduced_exposure': round(hours_saved * labor_rate * dim_exposure_pct),
            'automation_reuse': round(hours_saved * labor_rate * dim_reuse_pct),
            'faster_recovery': round(hours_saved * labor_rate * dim_recovery_pct),
        },
        'total_value': round(hours_saved * labor_rate),
        'ai_contributions': {
            'systems_analyzed': total_systems,
            'remediation_decisions': total_systems,
            'risk_assessments': sum(1 for h in (state.get('hosts') or []) if h.get('decision') == 'review'),
            'historical_correlations': 8,
            'a2a_handoffs': len([e for e in state.get('stream', []) if e.get('event') == 'a2a_message']),
            'health_checks': 3,
            'failures_diagnosed': 1,
            'rollbacks_executed': 1,
            'human_approvals': 1,
        },
        'benchmarks': [
            {'metric': 'Vulnerability remediation time reduction', 'value': '91%', 'source': 'Red Hat / Principled Technologies'},
            {'metric': 'Manual security-update effort reduction', 'value': '80%', 'source': 'Forrester TEI — Ansible Tower'},
            {'metric': 'Patch-status tracking reduction', 'value': '88%', 'source': 'Red Hat / Principled Technologies'},
            {'metric': 'Legacy system patching acceleration', 'value': '10 days → 6 hrs', 'source': 'Red Hat IT case study'},
            {'metric': 'Automation labor savings', 'value': '1,800+ hrs/mo', 'source': 'ABB case study — AAP'},
            {'metric': 'Ansible Tower ROI', 'value': '146% / $1.03M NPV', 'source': 'Forrester TEI study'},
            {'metric': 'RHEL + Insights + Satellite ROI', 'value': '540% over 3 yrs', 'source': 'IDC study'},
        ],
        'timeline_manual': [
            {'time': '09:00', 'event': 'Discovery', 'duration_min': 80},
            {'time': '10:20', 'event': 'Investigation', 'duration_min': 115},
            {'time': '12:15', 'event': 'Risk analysis', 'duration_min': 105},
            {'time': '14:00', 'event': 'Change approval', 'duration_min': 150},
            {'time': '16:30', 'event': 'Script preparation', 'duration_min': 90},
            {'time': '18:00', 'event': 'Patch execution', 'duration_min': 165},
            {'time': '20:45', 'event': 'Validation', 'duration_min': 85},
            {'time': '22:10', 'event': 'Failure investigation', 'duration_min': 80},
            {'time': '23:30', 'event': 'Recovery', 'duration_min': 60},
        ],
        'timeline_ai': [
            {'time': '09:00', 'event': 'Discovery', 'duration_min': 3},
            {'time': '09:03', 'event': 'Risk assessment', 'duration_min': 2},
            {'time': '09:05', 'event': 'Change request', 'duration_min': 3},
            {'time': '09:08', 'event': 'Approval', 'duration_min': 1},
            {'time': '09:09', 'event': 'Canary', 'duration_min': 5},
            {'time': '09:14', 'event': 'Production', 'duration_min': 3},
            {'time': '09:17', 'event': 'Failure', 'duration_min': 1},
            {'time': '09:18', 'event': 'Diagnosis', 'duration_min': 3},
            {'time': '09:21', 'event': 'Recovery', 'duration_min': 4},
            {'time': '09:25', 'event': 'Complete', 'duration_min': 0},
        ],
    }

    roi_stages = [
        ('roi_calculating', 'ROI Agent analyzing patch economics', 3, {
            'roi': roi_data,
            '_a2a': [
                {'from': 'patch_manager', 'to': 'roi', 'action': 'calculate_roi', 'type': 'request', 'message': f'Patch Manager → ROI Agent: calculate value created for {total_systems} systems patched'},
                {'from': 'roi', 'to': 'roi', 'action': 'benchmark_lookup', 'type': 'event', 'message': 'ROI Agent: loading industry benchmarks — Forrester TEI, Red Hat/PT, IDC studies'},
            ],
        }),
        ('roi_complete', f'ROI: ${labor_saved:,} saved — {hours_saved} hours recovered — {cost_reduction_pct}% cost reduction', 2, {
            'roi': roi_data,
            '_a2a': [
                {'from': 'roi', 'to': 'patch_manager', 'action': 'roi_complete', 'type': 'response', 'message': f'ROI Agent → Patch Manager: ${labor_saved:,} value created — {hours_saved} hours recovered vs manual remediation'},
                {'from': 'roi', 'to': 'console', 'action': 'roi_dashboard', 'type': 'event', 'message': f'ROI Agent → Console: dashboard ready — {cost_reduction_pct}% cost reduction per system (${manual_cost_per_host} → ${ai_cost_per_host})'},
            ],
        }),
    ]
    post_approval_stages.extend(roi_stages)

    for stage_key, message, delay, updates in post_approval_stages:
        ts = now_iso()
        log(f'STEP {stage_key} — {message}')

        state['stream'].append({'time': ts, 'event': stage_key, 'message': message})
        state['summary']['flow_message'] = message
        state['summary']['flow_stage'] = stage_key
        state['workflow']['flow_stage'] = stage_key
        state['workflow']['last_updated'] = ts

        if 'approval_state' in updates:
            state['summary']['approval_state'] = updates['approval_state']
        if 'wf_status' in updates:
            if not state['aap'].get('latest_workflow_job'):
                state['aap']['latest_workflow_job'] = {
                    'id': 1001, 'name': 'approval workflow',
                    'status': updates['wf_status'], 'started': ts, 'finished': None,
                    'url': '#fallback-workflow-job-1001',
                }
            else:
                state['aap']['latest_workflow_job']['status'] = updates['wf_status']
            state['summary']['last_workflow_status'] = updates['wf_status']
            state['workflow']['status'] = updates['wf_status']
        if 'job_status' in updates:
            if not state['aap'].get('latest_job'):
                state['aap']['latest_job'] = {
                    'id': 3001,
                    'name': f'{DEMO_CVE} remediation',
                    'status': updates['job_status'],
                    'started': ts,
                    'finished': None,
                    'url': '#fallback-job-3001',
                }
            else:
                state['aap']['latest_job']['status'] = updates['job_status']
            state['summary']['last_job_status'] = updates['job_status']
            if updates['job_status'] == 'successful':
                state['aap']['latest_job']['finished'] = ts
                state['aap']['latest_workflow_job']['finished'] = ts

        for a2a_msg in updates.get('_a2a', []):
            state['stream'].append({
                'time': ts,
                'event': 'a2a_message',
                'from': a2a_msg['from'],
                'to': a2a_msg['to'],
                'type': a2a_msg['type'],
                'action': a2a_msg['action'],
                'message': a2a_msg['message'],
            })

        if 'exec_progress' in updates:
            state['summary']['exec_progress'] = updates['exec_progress']
        if 'failure' in updates:
            state['summary']['failure'] = updates['failure']
        if 'failure_analysis' in updates:
            state['summary']['failure_analysis'] = updates['failure_analysis']
        if 'remediation' in updates:
            state['summary']['remediation'] = updates['remediation']
        if 'remediation_progress' in updates:
            state['summary']['remediation_progress'] = updates['remediation_progress']
        if 'final_summary' in updates:
            state['summary']['final_summary'] = updates['final_summary']
        if 'roi' in updates:
            state['summary']['roi'] = updates['roi']
        if 'slack' in updates:
            state['summary']['latest_slack'] = updates['slack']

        state['aap'].pop('pending_approvals', None)

        run_entry = state['runs'][0]
        run_entry['workflow'] = dict(state['workflow'])
        run_entry['summary'] = dict(state['summary'])
        run_entry['aap'] = dict(state['aap'])

        write_state(state)
        if delay > 0:
            time.sleep(delay / speed)

    log(f'FLOW complete — all {T+C+P} systems patched successfully')


def run_full_flow(cve_id=None, speed=1.0, auto_approve=False):
    """Run the complete flow: stages -> approval pause -> execution -> learn."""
    state = run_unified_flow(cve_id=cve_id, speed=speed)

    if auto_approve:
        log('Auto-approving (--auto flag)')
        time.sleep(3)
        run_post_approval(state, speed=speed)
    else:
        print('\n' + '=' * 60, file=sys.stderr)
        print('  Flow paused at APPROVAL GATE', file=sys.stderr)
        print('  ', file=sys.stderr)
        print('  Option 1: Click "Approve" in the UI', file=sys.stderr)
        print('  Option 2: Press Enter here to simulate approval', file=sys.stderr)
        print('=' * 60, file=sys.stderr)
        try:
            input()
            run_post_approval(state, speed=speed)
        except (EOFError, KeyboardInterrupt):
            log('Flow interrupted')


# Backward-compatible aliases
run_demo = run_unified_flow
simulate_approval = run_post_approval
run_full_demo = run_full_flow


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Run the AIP patch flow (tries real APIs, falls back to demo data)')
    parser.add_argument('--cve', default=DEMO_CVE, help='CVE ID to simulate')
    parser.add_argument('--speed', type=float, default=1.0, help='Speed multiplier (2.0 = twice as fast)')
    parser.add_argument('--auto', action='store_true', help='Auto-approve without pausing')
    args = parser.parse_args()
    run_full_flow(cve_id=args.cve, speed=args.speed, auto_approve=args.auto)
