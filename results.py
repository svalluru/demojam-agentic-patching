"""Agent 4 — Results Publishing. Feeds the outcome back into the two stores.

Step 13 of the architecture, in two halves:

  RAG       a patch record per host, in rag-setup/data/, matching the format
            of the hand-written records already there. Next ingest run makes
            it searchable, so agent 1 can cite this run when the same host
            comes up again.

  Training  a row per host in risk_score/training/observed/outcomes.csv,
            using the same four features the model takes, plus provenance.

Two decisions worth knowing about, because both are easy to get wrong:

1. The label is derived from what happened, never from what the model said.
   Writing the prediction back as ground truth is self-training: the model
   would be fitted on its own output and would only ever confirm itself.
   OBSERVED_RISK below is the rule, and it is deliberately crude and in one
   place so it is easy to argue with.

2. Simulated runs are written but marked simulated=true, and the merge step
   drops them by default. In offline mode every run is simulated, so without
   that guard a few demo runs would quietly become training data.

Nothing here is destructive: the RAG record is a new file per run and the
CSV is append-only. The synthetic risk_score/training/*/data.csv is never
touched.
"""
from __future__ import annotations

import csv
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CSV_FIELDS = [
    # the four features the model is trained on — order matches data.csv
    'cvss', 'age_days', 'affected_hosts', 'type', 'risk_score',
    # provenance, so a row can always be traced back and filtered
    'cve_id', 'host', 'outcome', 'observed_at', 'simulated',
    'predicted_score', 'decision', 'attempts', 'degraded_inputs',
]

# Observed risk by outcome. The model scores how much attention a host-CVE
# pair deserves, so the signal we actually have is whether touching this host
# went cleanly. A failure is the strongest evidence available that it did not.
#
# These are starting values, not measurements. Tune them against real runs
# before anyone retrains on this.
OBSERVED_RISK = {
    'failed': 95.0,        # patch failed or rolled back — worst case
    'timeout': 85.0,       # never settled; needs a human either way
    'rejected': 60.0,      # an operator looked and said no
    'unavailable': None,   # never dispatched — tells us nothing, so no row
    'awaiting_approval': None,   # not finished; revisited at completion
    'patched': 30.0,       # went through cleanly
}

# A clean patch on a host with a bad history is more informative than one on
# a host that has never failed, so nudge the label by what the RAG lookup
# said. Small, because this is a weak signal.
HISTORY_PENALTY = 10.0


def observed_risk(outcome: str, had_prior_failure: bool) -> float | None:
    base = OBSERVED_RISK.get(outcome)
    if base is None:
        return None
    if had_prior_failure and outcome == 'patched':
        base += HISTORY_PENALTY
    return round(min(100.0, base), 2)


def _slug(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]', '_', str(s))[:80]


class ResultsAgent:
    """Stateless. The Supervisor hands it the finished run."""

    name = 'results-publishing-agent'

    def __init__(self, rag_dir: Path, training_dir: Path, trace=None):
        self.rag_dir = rag_dir
        self.csv_path = training_dir / 'outcomes.csv'
        self._trace = trace or (lambda *a, **k: None)

    # -- step 13a: RAG ------------------------------------------------------

    def _record(self, state: dict, result: dict, host_info: dict) -> str:
        cve = state.get('cve_id', 'unknown')
        host = result.get('host', 'unknown')
        outcome = result.get('outcome', 'unknown')
        now = datetime.now(timezone.utc)
        steps = [s for s in (result.get('steps') or []) if s.get('status')]
        done = [s['name'] for s in steps if s['status'] == 'completed']
        failed = [s['name'] for s in steps if s['status'] in ('failed', 'error')]
        risk = host_info.get('risk') or host_info.get('risk_score')

        verdict = {'patched': 'SUCCESS', 'failed': 'FAILED', 'timeout': 'FAILED',
                   'rejected': 'NOT ATTEMPTED'}.get(outcome, outcome.upper())

        lines = [
            f'# Patch record — {host} — {now:%Y-%m-%d}',
            '',
            f'CVE: {cve} ({state.get("description", "")[:120].rstrip()}'
            f'{", CVSS " + str(state.get("cvss")) if state.get("cvss") else ""})',
            f'Change type: {result.get("group", "unknown")} via '
            f'{(state.get("patch") or {}).get("workflow", "Automation Orchestrator")}',
            f'Result: {verdict}',
            '',
        ]
        if result.get('simulated'):
            lines += [
                'NOTE: simulated run. Automation Orchestrator was unreachable, so this',
                'outcome was produced by the local simulator. No change was made to',
                'the host. Do not treat this record as evidence of a real patch.',
                '',
            ]
        lines += ['What happened:']
        if outcome == 'patched':
            lines += [f'Workflow completed all {len(done)} steps '
                      f'({", ".join(done)}). Host reported healthy afterwards.']
        elif failed:
            lines += [f'Workflow stopped at {failed[0]}. '
                      f'Completed before that: {", ".join(done) or "nothing"}.']
            if result.get('error'):
                lines += [f'Reported error: {str(result["error"])[:300]}']
        elif outcome == 'rejected':
            lines += ['An operator rejected the change at the approval gate. '
                      'The remediation steps never ran.']
        else:
            lines += [f'Run ended as {outcome}. '
                      f'Completed steps: {", ".join(done) or "none"}.']
        lines += ['']

        if risk is not None:
            lines += [f'Risk score at assessment: {risk} '
                      f'({(state.get("dry_run") or {}).get("risk_source", "unknown")} source), '
                      f'routed to {result.get("group", "unknown")}.']
        if host_info.get('history'):
            lines += ['', 'Prior history consulted at assessment:',
                      str(host_info['history'])[:600]]

        degraded = (state.get('degraded') or [])
        if degraded:
            lines += ['', 'Degraded inputs during this run: '
                      + ', '.join(f'{d.get("step")} ({d.get("service")})'
                                  for d in degraded) + '.']

        lines += ['', f'Execution: {result.get("execution_id", "n/a")}',
                  f'Recorded: {now:%Y-%m-%d %H:%M UTC} by {self.name}.', '']

        # Matches the naming already in rag-setup/data/. The time suffix keeps
        # two runs of the same CVE on the same day from clobbering each other.
        name = (f'{now:%Y-%m-%d}-{_slug(cve)}-{_slug(host.split(".")[0])}'
                f'-{verdict.replace(" ", "-")}-{now:%H%M%S}.md')
        path = self.rag_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('\n'.join(lines))
        return name

    # -- step 13b: training data -------------------------------------------

    def _rows(self, state: dict, results: list[dict],
              by_host: dict[str, dict]) -> list[dict]:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        hosts_affected = len(state.get('hosts') or [])
        degraded = ';'.join(sorted({d.get('step', '') for d in
                                    (state.get('degraded') or [])}))
        rows = []
        for r in results:
            h = by_host.get(r.get('host'), {})
            label = observed_risk(r.get('outcome', ''),
                                  'fail' in str(h.get('history', '')).lower())
            if label is None:
                continue              # nothing was learned about this host
            rows.append({
                'cvss': state.get('cvss', ''),
                'age_days': h.get('age_days', ''),
                'affected_hosts': hosts_affected,
                'type': 'security',
                'risk_score': label,
                'cve_id': state.get('cve_id', ''),
                'host': r.get('host', ''),
                'outcome': r.get('outcome', ''),
                'observed_at': now.isoformat().replace('+00:00', 'Z'),
                'simulated': bool(r.get('simulated')),
                'predicted_score': h.get('risk') or h.get('risk_score') or '',
                'decision': h.get('decision', ''),
                'attempts': r.get('attempts', 1),
                'degraded_inputs': degraded,
            })
        return rows

    def _append(self, rows: list[dict]) -> int:
        if not rows:
            return 0
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        new = not self.csv_path.exists()
        with self.csv_path.open('a', newline='') as fh:
            w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
            if new:
                w.writeheader()
            w.writerows(rows)
        return len(rows)

    # -- entry point --------------------------------------------------------

    def publish(self, state: dict) -> dict[str, Any]:
        results = ((state.get('patch') or {}).get('results')) or []
        by_host = {h.get('host'): h for h in (state.get('hosts') or [])}

        # Only settled hosts teach us anything. A host still at the approval
        # gate will be published when the run completes.
        settled = [r for r in results
                   if r.get('outcome') not in ('awaiting_approval', 'running')]
        if not settled:
            return {'skipped': 'no settled hosts yet', 'records': [], 'rows': 0}

        records = [self._record(state, r, by_host.get(r.get('host'), {}))
                   for r in settled]
        rows = self._rows(state, settled, by_host)
        written = self._append(rows)
        simulated = sum(1 for r in rows if r['simulated'])

        self._trace('results', 'console',
                    f'{len(records)} RAG record(s), {written} training row(s)'
                    + (f' ({simulated} simulated)' if simulated else ''))
        return {
            'records': records,
            'rag_dir': str(self.rag_dir),
            'rows': written,
            'simulated_rows': simulated,
            'csv': str(self.csv_path),
            'reingest': ('./rag-setup/ingest.py --route $LLAMA_STACK_URL '
                         '--dir ./rag-setup/data --ensure'),
        }
