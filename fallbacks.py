"""Default data used when a backing service is unreachable.

Every value here is fabricated. Nothing in this file is a real measurement, so
anything derived from it must be labelled `degraded` and carry `source` all the
way to the operator — the dry-run report is what a human approves against, and
an unlabelled guess is worse than an outright failure.

Set STRICT=true to disable all of it and let the real error surface instead;
that is the mode to use when you are checking what is actually wired up.

Hosts here are deliberately the pay-app-* names that rag-setup/data/ describes,
so a fully offline demo still produces coherent history lookups.
"""
from __future__ import annotations

import os
from typing import Any

# --------------------------------------------------------------------- C1

# Two CVEs, deliberately. One wide blast radius and one narrow, which is the
# only distinction the demo needs — a longer list makes the severity pills
# look busier without exercising anything extra.
#
# systems_affected must match len(HOSTS_BY_CVE[id]); the console shows the two
# side by side ("2 host(s) of 2") and a mismatch reads as a lost host.
CVE_LIST: list[dict[str, Any]] = [
    {'id': 'CVE-2024-3094', 'cvss': 10.0, 'impact': 'Critical', 'systems_affected': 5,
     'public_date': '2024-03-29T00:00:00Z', 'known_exploit': True,
     'description': 'Malicious code in the xz/liblzma upstream tarballs allows '
                    'sshd authentication bypass.'},
    {'id': 'CVE-2024-1086', 'cvss': 7.8, 'impact': 'Important', 'systems_affected': 2,
     'public_date': '2024-01-31T00:00:00Z', 'known_exploit': True,
     'description': 'Linux kernel nf_tables use-after-free allows local privilege '
                    'escalation to root.'},
]

# --------------------------------------------------------------------- C2

# The payments tier from rag-setup/data/. age_days varies so the risk model has
# something to discriminate on, and every host here has an entry in HISTORY so
# the RAG fallback stays coherent.
HOSTS: list[dict[str, Any]] = [
    {'host': 'pay-app-07.acme.internal', 'system_uuid': 'fb-0000-0007', 'age_days': 47},
    {'host': 'pay-app-03.acme.internal', 'system_uuid': 'fb-0000-0003', 'age_days': 31},
    {'host': 'pay-app-05.acme.internal', 'system_uuid': 'fb-0000-0005', 'age_days': 12},
    {'host': 'pay-app-09.acme.internal', 'system_uuid': 'fb-0000-0009', 'age_days': 5},
    {'host': 'pay-db-01.acme.internal',  'system_uuid': 'fb-0000-0011', 'age_days': 63},
]

_BY_NAME = {h['host'].split('.')[0]: h for h in HOSTS}

# Which hosts each CVE affects. The overlap is intentional: pay-app-07 and
# pay-db-01 appear in both, as a real estate would have hosts behind on more
# than one advisory.
HOSTS_BY_CVE: dict[str, list[dict[str, Any]]] = {
    'CVE-2024-3094': [_BY_NAME[n] for n in
                      ('pay-app-07', 'pay-app-03', 'pay-app-05',
                       'pay-app-09', 'pay-db-01')],
    'CVE-2024-1086': [_BY_NAME[n] for n in ('pay-app-07', 'pay-db-01')],
}

CVE_DETAIL_DEFAULT = {
    'cvss': 8.8,
    'impact': 'Important',
    'description': 'Offline fallback CVE record — Insights was unreachable, so '
                   'this description is placeholder text, not the real advisory.',
}


def cve_detail(cve_id: str) -> dict[str, Any]:
    """Detail for a CVE, preferring real metadata from CVE_LIST if we have it.

    A CVE typed into the console that is not one of the two above still
    resolves — to the full host pool — rather than reporting zero affected
    hosts, which would look like a working answer.
    """
    known = next((c for c in CVE_LIST if c['id'] == cve_id), None)
    hosts = HOSTS_BY_CVE.get(cve_id, HOSTS)
    return {
        'cve_id': cve_id,
        'cvss': known['cvss'] if known else CVE_DETAIL_DEFAULT['cvss'],
        'impact': known['impact'] if known else CVE_DETAIL_DEFAULT['impact'],
        'description': known['description'] if known else CVE_DETAIL_DEFAULT['description'],
        'hosts': [dict(h) for h in hosts],
        'count': len(hosts),
        'total_affected': len(hosts),
    }


# ----------------------------------------------------------------- step 3

# The model clamps to 0-100 and this does not, so the two are not on the same
# scale. A heuristic score of 30 does not mean what a model score of 30 means,
# which is why the caller has to use HEURISTIC_THRESHOLD rather than the usual
# one. cvss*6 alone passes 30 at CVSS 5.0, so almost everything would otherwise
# land in 'review'.
HEURISTIC_THRESHOLD = float(os.environ.get('HEURISTIC_THRESHOLD', '55') or 55)


def heuristic_risk(cvss: float, age_days: int, affected_hosts: int) -> float:
    return round(min(100.0, (cvss * 6.0)
                     + min(age_days / 30.0, 10.0)
                     + min(affected_hosts, 10)), 2)


# ----------------------------------------------------------------- step 1

NO_HISTORY = ('No patch history available — the RAG store could not be reached, '
              'so this host has not been checked against past outcomes.')

# Keyed on a substring of the hostname. Mirrors rag-setup/data/ so an offline
# demo tells the same story the ingested documents do.
HISTORY: dict[str, str] = {
    'pay-app-07': 'Repeated post-patch failures caused by a 30 second application '
                  'drain being too short; 120 seconds has been reliable. /var fills '
                  'quickly, so a 2 GB free-space pre-check is required, and the '
                  'service needs a 90 second post-restart grace period. Three '
                  'consecutive first-attempt successes since those became defaults.',
    'pay-app-03': 'One kernel patch failure attributed to connection pool drain '
                  'timing. No rollbacks since the drain timeout was raised.',
    'pay-app-05': 'Patched successfully three times in six months, always with a '
                  '120 second drain and DBA availability confirmed. No rollbacks.',
    'pay-app-09': 'Clean history — four successful patches, zero rollbacks. Drain '
                  'is automated. Low operational risk but Tier 1 by classification.',
    'pay-db-01':  'Database tier. Patches require a maintenance window and DBA '
                  'sign-off; no unattended patching has been attempted.',
}


def history(host: str) -> str:
    for key, text in HISTORY.items():
        if key in host:
            return text
    return NO_HISTORY


# ---------------------------------------------------------------- step 5-10

# Agent 2 hands steps 5-10 to Ansible Orchestrator. When AO is down there are
# two possible fallbacks and the choice is a policy one:
#
#   simulate    (default) run the workflow locally so the console can be
#               demonstrated end to end. Nothing is patched. Every result is
#               marked degraded/source=fallback and carries a sim- execution
#               id that exists nowhere in AO.
#   unavailable report that the workflow was never dispatched. Honest, but it
#               stops the demo at the first host.
#
# Set FALLBACK_PATCH=unavailable for the second. STRICT=true disables both.

# Mirrors the node sequence of the AO workflow 'DemoJam Agentic Patching',
# which implements steps 5-10 of the architecture. route_switch and
# fetch_and_commit_prod are the real node ids; the console keys off both.
SIM_STEPS = [
    ('route_switch',                 'Step 5 — env gate, route prod/dev'),
    ('approval_gate',                'Step 5 — hold for operator approval'),
    ('generate_playbook',            'Step 6 — generate playbook from Lightspeed'),
    ('fetch_and_commit_prod',        'Step 7 — commit remediation to git'),
    ('sync_aap_project',             'Step 8 — sync the AAP project'),
    ('schedule_job',                 'Step 9 — schedule inside the window'),
    ('run_cve_remediation',          'Step 10 — phased remediation'),
]


def sim_steps(up_to: str, *, status: str = 'completed',
           skip: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """Step list ending at `up_to`; nodes after it stay pending."""
    out, reached = [], False
    for name, label in SIM_STEPS:
        if name in skip:
            continue
        if reached:
            out.append({'name': name, 'label': label, 'status': 'pending', 'error': None})
            continue
        out.append({'name': name, 'label': label,
                    'status': status if name == up_to else 'completed',
                    'error': None})
        reached = name == up_to
    return out


def patch_simulated(cve_id: str, host: str, group: str, reason: str,
                    execution_id: str) -> dict[str, Any]:
    """A workflow run that did not happen, shaped like one that did.

    approved_patch pauses at the approval gate exactly as the real workflow
    does, so Approve / Reject stay exercisable with AO down. auto_patch runs
    straight through.
    """
    pending = group == 'approved_patch'
    return {
        'host': host, 'group': group, 'cve_id': cve_id,
        'execution_id': execution_id,
        'status': 'waiting' if pending else 'completed',
        'outcome': 'awaiting_approval' if pending else 'patched',
        'approval_pending': pending,
        'approval_activity_id': 'approval_gate' if pending else '',
        'matched_port': group,
        'steps': (sim_steps('approval_gate', status='waiting') if pending
                  else sim_steps('run_cve_remediation', skip=('approval_gate',))),
        'error': None,
        'degraded': True, 'source': 'fallback', 'simulated': True,
        'reason': f'Ansible Orchestrator unreachable: {reason}',
        'url': '',
    }


def patch_unavailable(host: str, group: str, reason: str) -> dict[str, Any]:
    return {
        'host': host, 'group': group, 'execution_id': '',
        'status': 'not_dispatched', 'outcome': 'unavailable',
        'approval_pending': False, 'approval_activity_id': '',
        'matched_port': '', 'steps': [],
        'error': f'Ansible Orchestrator unreachable: {reason}',
        'degraded': True, 'source': 'fallback', 'simulated': True, 'url': '',
    }


def simulate_patch() -> bool:
    return os.environ.get('FALLBACK_PATCH', 'simulate').strip().lower() != 'unavailable'


# -------------------------------------------------------------------- mode

def strict() -> bool:
    """STRICT=true disables every fallback above and re-raises the real error."""
    return os.environ.get('STRICT', '').strip().lower() in {'1', 'true', 'yes'}
