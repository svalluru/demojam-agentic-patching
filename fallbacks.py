"""Default data used when a backing service is unreachable.

Every value here is fabricated. Nothing in this file is a real measurement, so
anything derived from it must be labelled `degraded` and carry `source` all the
way to the operator — the patch plan is what a human approves against, and
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
    """Only reachable in demo mode, where simulating is the point.

    Live mode raises before this is consulted, so the 'report it as not
    dispatched' alternative had no caller left once the middle ground went.
    """
    return True


# --------------------------------------------------------------------- ROI
#
# The manual baseline the console compares itself against. Every number below
# is an assumption and none of it is measurable from this system: the manual
# run never happened, so there is no clock to read it off. They live here with
# the rest of the fabricated data for exactly that reason, they are exposed in
# the settings panel, and roi_report() ships them back to the console with the
# result so the operator can see what the claim rests on and argue with it.
#
# The automated side is the opposite — it comes from this run's own clock.
# That clock only measures patching if something was patched: offline it is
# DEMO_LATENCY rather than work, and live with Ansible Orchestrator down it is
# real time spent failing over to patch_simulated() below. The report marks
# itself illustrative in both cases and says which.
#
# Defaults are deliberately unflattering to the automation. A baseline that
# assumes four unattended hours per host produces a wonderful number and
# convinces nobody; these are meant to survive an argument with whoever
# actually does this work today. Someone who patches faster than this should
# change them in the panel and watch the result move.

# Per CVE, once: read the advisory, pull the affected host list out of
# Insights or a spreadsheet, decide what the exposure actually is.
ROI_TRIAGE_MIN = float(os.environ.get('ROI_TRIAGE_MIN', '45') or 45)

# Per host: adapt the playbook, raise the change record, book the window.
ROI_PREP_MIN = float(os.environ.get('ROI_PREP_MIN', '15') or 15)

# Per host: run it, watch it, confirm the package moved and the service came
# back. Counted separately from prep so the chart can show that automation
# collapses these two very differently.
ROI_EXEC_MIN = float(os.environ.get('ROI_EXEC_MIN', '10') or 10)

# Per host that needs sign-off: assembling the request, finding the approver,
# waiting on the back-and-forth. On top of prep, not instead of it.
ROI_APPROVAL_MIN = float(os.environ.get('ROI_APPROVAL_MIN', '20') or 20)

# The automated path is not free of people, and a comparison that pretends it
# is would be dishonest. This is what the operator still spends per gated
# host: reading the plan, judging the risk score, pressing Approve.
ROI_REVIEW_MIN = float(os.environ.get('ROI_REVIEW_MIN', '2') or 2)

# Fully-loaded hourly cost of whoever does the work. Fully loaded, not salary.
ROI_HOURLY_RATE = float(os.environ.get('ROI_HOURLY_RATE', '85') or 85)
ROI_CURRENCY = os.environ.get('ROI_CURRENCY', '$') or '$'

# Elapsed hours from "this CVE is ours" to "this host is patched" by hand.
# This is wall clock, not effort — it is mostly queueing, waiting on an
# approver and waiting for the next maintenance window, which is why it is
# an order of magnitude larger than the labour figures above. It is also the
# number that matters most, since it is how long the host stays exploitable.
ROI_LEAD_HOURS = float(os.environ.get('ROI_LEAD_HOURS', '72') or 72)

# Share of hosts that have to be done twice by hand — the patch does not take,
# the service does not come back, the window is lost and the whole booking
# repeats. Not invented for the chart: HISTORY above describes exactly this on
# pay-app-07, where a drain timeout that was too short caused repeated
# post-patch failures until someone worked out why.
#
# Applied to the manual side only, and that asymmetry is deliberate rather
# than generous. Automated failures are not waved away — a run that fails
# never reaches 'patched', so roi_history() drops it from the saving entirely
# and counts it under `excluded`. The manual equivalent has no such record,
# which is why it has to be estimated here.
ROI_REWORK_PCT = float(os.environ.get('ROI_REWORK_PCT', '12') or 12)

# How wrong the manual baseline might be, as a percentage either way. An
# estimate built out of seven guesses and quoted to the cent is making a
# promise it cannot keep, so the console publishes a range beside the point
# figure. The band is itself a judgement — it is listed with the other
# assumptions for the same reason they are.
ROI_BAND_PCT = float(os.environ.get('ROI_BAND_PCT', '30') or 30)

# The remediation deadline this organisation holds itself to, in hours. Policy,
# not physics, which is why it has no defensible default — 48 is a common
# internal standard for a Critical and is a placeholder for whatever yours is.
#
# This exists so the exposure figure can be stated against something the
# business already agreed to, instead of being converted into money. Pricing
# an exposure window needs a breach probability and a breach cost, both
# unknowable, multiplied together — which would put the largest number on the
# page on the weakest footing of anything in this file.
ROI_SLA_HOURS = float(os.environ.get('ROI_SLA_HOURS', '48') or 48)

# What standing this platform up cost, one off: the build, the integration
# work, the cluster it sits on. The weakest assumption here by some distance —
# nobody can source it from this repo and it varies by an order of magnitude
# between organisations. It earns its place because it is the first question
# anyone holding a budget asks, and refusing to answer is not neutral: it
# leaves them to assume a number, and the one they assume is usually worse.
# Set it to 0 to drop the payback card entirely.
ROI_PLATFORM_COST = float(os.environ.get('ROI_PLATFORM_COST', '25000') or 25000)


# -------------------------------------------------------------------- mode

def strict() -> bool:
    """Whether a missing service raises instead of falling back to this file.

    True in live mode, and that is the whole point of live mode: a patch plan
    built partly from stored defaults is not something to approve a
    production change against. Demo mode is the opposite — nothing here is
    reachable by design, so everything falls back.
    """
    return os.environ.get('MODE', 'demo').strip().lower() == 'live'
