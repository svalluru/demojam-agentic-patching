"""Default data used when a backing service is unreachable.

Every value here is fabricated. Nothing in this file is a real measurement, so
anything derived from it must be labelled `degraded` and carry `source` all the
way to the operator — the patch plan is what a human approves against, and
an unlabelled guess is worse than an outright failure.

MODE=live disables all of it and lets the real error surface instead; that
is the mode to use against real infrastructure, and for checking what is
actually wired up.

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

# The gate for heuristic scores, and a constant rather than a setting: it is
# only meaningful alongside the formula below, and it is only ever reached in
# demo mode — a live run scores with the model or fails.
#
# The model clamps to 0-100 from a fitted distribution and this is a straight
# line, so a 30 does not mean the same thing in each. cvss*6 alone passes the
# model's gate of 30 at CVSS 5.0, which would put every CVE above that into
# review and leave the unattended branch never exercised. At 55 the two demo
# CVEs split: CVSS 10.0 scores ~66 and stops at the gate, CVSS 7.8 scores ~50
# and patches unattended. Change this and the formula together, or the demo
# loses one of its two paths.
HEURISTIC_THRESHOLD = 55.0


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


# ------------------------------------------------- remediation parameters

# The knobs the remediation playbook takes, with the value it uses when the
# console sends nothing. These are the defaults a first attempt runs with, so
# they are deliberately the unsafe ones -- the whole point of the history
# above is that some hosts need more than the default and the fleet-wide
# default cannot know which.
REMEDIATION_INPUTS: dict[str, dict[str, Any]] = {
    'drain_timeout': {
        'label': 'Application drain timeout',
        'unit': 's', 'default': 30, 'min': 0, 'max': 600,
        'help': 'How long to wait for in-flight connections to close before '
                'the package transaction starts.',
    },
    'min_free_gb': {
        'label': 'Free space pre-check',
        'unit': 'GB', 'default': 0, 'min': 0, 'max': 50,
        'help': 'Abort before downloading if /var has less than this free. '
                '0 skips the check.',
    },
    'restart_grace': {
        'label': 'Post-restart grace',
        'unit': 's', 'default': 0, 'min': 0, 'max': 600,
        'help': 'Settle time after the service comes back, before verify '
                'reads the host.',
    },
}


def remediation_defaults() -> dict[str, int]:
    return {k: v['default'] for k, v in REMEDIATION_INPUTS.items()}


# The structured form of the prose in HISTORY above, for the hosts whose
# history actually prescribes something. Only the demo has this: live, the RAG
# store returns a paragraph written by a person and there is nothing to parse
# it into, so the console shows the paragraph and the operator reads the
# numbers out of it themselves. That asymmetry is why the retry panel renders
# its fields either way and only pre-fills them when there is something to
# pre-fill -- a pre-filled box that quietly held a default would be the
# console inventing an operational recommendation, which is worse than a
# blank one.
HISTORY_TUNING: dict[str, dict[str, int]] = {
    'pay-app-07': {'drain_timeout': 120, 'min_free_gb': 2, 'restart_grace': 90},
    'pay-app-03': {'drain_timeout': 120},
    'pay-app-05': {'drain_timeout': 120},
}


def history_tuning(host: str) -> dict[str, int]:
    for key, vals in HISTORY_TUNING.items():
        if key in host:
            return dict(vals)
    return {}


# ------------------------------------------------------- the verify verdict

# Hosts where the first attempt does not actually clear the advisory, and what
# it takes to make it. This is the case the real workflow's last node exists
# for: `dnf` exits 0, every node goes green, and the advisory is still listed.
# aap-setup/README.md records it happening on this project in both directions.
#
# Keyed by hostname substring like HISTORY, and deliberately deterministic --
# a failure that lands on a different host each run cannot be rehearsed, and a
# presenter who cannot rehearse it will not show it.
VERIFY_REQUIRES: dict[str, dict[str, Any]] = {
    'pay-app-07': {
        'input': 'drain_timeout',
        'at_least': 120,
        'advisory': 'RHSA-2024:2456',
        'why': ('the 30 second drain expired with connections still open, so '
                'the remediation skipped the package transaction and left the '
                'advisory outstanding'),
    },
}


def verify_check(host: str, inputs: dict[str, Any] | None) -> dict[str, Any]:
    """What the verify node would report for this host at these settings.

    Shaped like the playbook's own artifacts (`patched`,
    `outstanding_advisories`, `dnf_rc`) so the console reads the simulated
    verdict through exactly the same code path as a real one. A host with no
    entry here verifies clean, which is every host but one.
    """
    vals = dict(remediation_defaults(), **{
        k: v for k, v in (inputs or {}).items() if k in REMEDIATION_INPUTS})
    for key, rule in VERIFY_REQUIRES.items():
        if key not in host:
            continue
        try:
            got = float(vals.get(rule['input']) or 0)
        except (TypeError, ValueError):
            got = 0.0
        if got >= rule['at_least']:
            break
        return {
            'patched': False,
            'outstanding_advisories': [rule['advisory']],
            'dnf_rc': 0,
            'verified_host': host,
            # Not an error string: the job did not fail. This is the verify
            # node reporting a clean run that did not achieve anything, and
            # the distinction is the entire point of the node.
            'why': rule['why'],
            'remedy': {'input': rule['input'], 'at_least': rule['at_least']},
        }
    return {'patched': True, 'outstanding_advisories': [], 'dnf_rc': 0,
            'verified_host': host}


# ---------------------------------------------------------------- step 5-10

# Agent 2 hands steps 5-10 to Ansible Orchestrator. When AO is down there are
# two possible fallbacks and the choice is a policy one:
#
# Demo mode runs the workflow locally so the console can be demonstrated end
# to end. Nothing is patched: every result is marked degraded/source=fallback
# and carries an execution id that exists in no AO instance. Live mode never
# reaches here — it raises instead.

# Mirrors the AO workflow the console dispatches to — node ids and the names
# the workflow itself gives them — so the offline demo tells the same story
# as a live run, verification step included.
#
# This used to be a seven-step list of its own: an approval_gate, a
# generate_playbook, a schedule_job that no workflow has ever contained, and
# no verify step at all. The demo showed a run that could not happen and left
# out the part of the real one that proves the patch landed.
#
# Two branches, because the real workflow has two and they use different node
# ids — fetch_and_commit on the unattended path, fetch_and_commit_prod behind
# the gate. The console keys off route_switch and fetch_and_commit_prod.
SIM_STEPS_PROD = [
    ('trigger_manual',            'CVE Alert'),
    ('route_switch',              'Route Decision'),
    ('approval_prod',             'Approve Production Patch'),
    ('fetch_and_commit_prod',     'Fetch from Lightspeed & Commit to Gitea'),
    ('deploy_script_prod',        'Sync & Deploy via AAP'),
    ('run_cve_remediation_prod',  'Run CVE Remediation'),
    ('verify_patch_prod',         'Verify Patch'),
]
SIM_STEPS_DEV = [
    ('trigger_manual',            'CVE Alert'),
    ('route_switch',              'Route Decision'),
    ('fetch_and_commit',          'Fetch from Lightspeed & Commit to Gitea'),
    ('deploy_script',             'Sync & Deploy via AAP'),
    ('run_cve_remediation',       'Run CVE Remediation'),
    ('verify_patch',              'Verify Patch'),
]
SIM_GATE = 'approval_prod'
SIM_LAST_PROD = SIM_STEPS_PROD[-1][0]
SIM_LAST_DEV = SIM_STEPS_DEV[-1][0]


def sim_steps(up_to: str, *, status: str = 'completed',
              prod: bool = True,
              verify: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Step list ending at `up_to`; nodes after it stay pending.

    `verify` is the verdict the verify node published, attached to that node
    as `output` so the console reads it off a step exactly as it reads a real
    execution's `output_data`. Note that a failed verdict still leaves the
    node `completed`: the node did its job, and what it found is in the
    output. A node coloured red here would be describing the wrong failure.
    """
    out, reached = [], False
    for name, label in (SIM_STEPS_PROD if prod else SIM_STEPS_DEV):
        if reached:
            out.append({'name': name, 'label': label, 'status': 'pending', 'error': None})
            continue
        step = {'name': name, 'label': label,
                'status': status if name == up_to else 'completed',
                'error': None}
        if verify is not None and name.startswith('verify_patch'):
            step['output'] = dict(verify)
        out.append(step)
        reached = name == up_to
    return out


def patch_simulated(cve_id: str, host: str, group: str, reason: str,
                    execution_id: str,
                    inputs: dict[str, Any] | None = None) -> dict[str, Any]:
    """A workflow run that did not happen, shaped like one that did.

    approved_patch pauses at the approval gate exactly as the real workflow
    does, so Approve / Reject stay exercisable with AO down. auto_patch runs
    straight through -- and runs all the way through verify, which is where
    an unattended host can still come back unpatched.

    `inputs` are the remediation parameters the console dispatched with. They
    are kept on the run because the gated path settles later, in _decide_sim,
    and by then the only record of what this run was asked to do is here.
    """
    pending = group == 'approved_patch'
    verdict = verify_check(host, inputs)
    ok = bool(verdict.get('patched'))
    return {
        'host': host, 'group': group, 'cve_id': cve_id,
        'execution_id': execution_id,
        'status': 'waiting' if pending else 'completed',
        'outcome': ('awaiting_approval' if pending
                    else 'patched' if ok else 'not_verified'),
        'approval_pending': pending,
        'approval_activity_id': SIM_GATE if pending else '',
        'matched_port': group,
        'steps': (sim_steps(SIM_GATE, status='waiting') if pending
                  else sim_steps(SIM_LAST_DEV, prod=False, verify=verdict)),
        'error': None,
        'inputs': dict(inputs or {}),
        'verify': None if pending else verdict,
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


# ------------------------------------------------- ROI, the application side
#
# The same idea for the other half of the console: what it costs by hand to
# get a vulnerable dependency out of a repository. A separate baseline rather
# than the one above reused, because it is not the same work and the counts it
# scales on are not the same counts.
#
# A host patch is one unit of work per host. A dependency fix is two: per
# component — find a fixed version, edit the manifest, re-lock — and per
# repository, which is where the build, the test suite and the pull request
# live however many components moved. Folding both into a per-host figure
# would misprice every estate that is not one component per repository, which
# is all of them.
#
# The other difference is the count that drives it. Infrastructure triage is
# paid once per CVE; here it is paid once per advisory, and a single scan of a
# handful of repositories routinely returns dozens. That is the application
# side's whole argument and it is why the triage figure below is smaller than
# the one above and still dominates the total.

# Per distinct advisory, once: read it, work out whether the vulnerable code
# path is reachable from yours, decide whether it matters. Smaller than a CVE
# triage because there is no affected-host list to assemble — and paid far
# more often, which is the point.
ROI_APP_TRIAGE_MIN = float(os.environ.get('ROI_APP_TRIAGE_MIN', '20') or 20)

# Per vulnerable component: find a fixed version that actually exists, check it
# does not drag a transitive conflict in behind it, edit the manifest, re-lock.
ROI_APP_BUMP_MIN = float(os.environ.get('ROI_APP_BUMP_MIN', '12') or 12)

# Per repository: build it and run the suite once the bumps are in, then read
# whatever broke. Per repository and not per component, because one build
# covers every change in it — which is precisely why the two are separate
# lines here.
ROI_APP_BUILD_MIN = float(os.environ.get('ROI_APP_BUILD_MIN', '25') or 25)

# Per repository: raise the pull request, find a reviewer, answer them, merge.
# The analogue of the approval paperwork on the infrastructure side.
ROI_APP_PR_MIN = float(os.environ.get('ROI_APP_PR_MIN', '15') or 15)

# Share of bumps that break something and have to be redone or backed out.
# Higher than the host figure above, deliberately: a package upgrade changes
# code that runs, where a patched RPM usually does not.
ROI_APP_BREAK_PCT = float(os.environ.get('ROI_APP_BREAK_PCT', '18') or 18)

# What the operator still spends per repository on the automated path: reading
# the change list, pressing Approve and run, reading the diff that comes back.
# Larger than the two minutes a host plan takes, because a diff across several
# manifests is more to look at than one risk score.
ROI_APP_REVIEW_MIN = float(os.environ.get('ROI_APP_REVIEW_MIN', '6') or 6)

# Elapsed hours from an advisory being published to the fix being merged, by
# hand. Wall clock rather than effort, like ROI_LEAD_HOURS above: mostly it is
# the advisory sitting in a queue behind feature work. Ten days is generous to
# the manual path against what the dependency-management literature reports.
ROI_APP_LEAD_HOURS = float(os.environ.get('ROI_APP_LEAD_HOURS', '240') or 240)


# -------------------------------------------------------------------- mode

def strict() -> bool:
    """Whether a missing service raises instead of falling back to this file.

    True in live mode, and that is the whole point of live mode: a patch plan
    built partly from stored defaults is not something to approve a
    production change against. Demo mode is the opposite — nothing here is
    reachable by design, so everything falls back.
    """
    return os.environ.get('MODE', 'demo').strip().lower() == 'live'
