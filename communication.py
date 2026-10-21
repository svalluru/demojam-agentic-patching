"""Agent 3 — Communication. Renders the patch status report.

The architecture puts two steps here: 11 send a Slack notification, 12 raise a
ServiceNow ticket. Neither is wired up yet — this renders the report those
channels would carry, as a PDF on disk, so the content can be agreed before
anyone commits to a transport.

When Slack and SNOW do arrive they should format *this* summary rather than
build their own, so the three channels cannot drift apart.

Called by the Supervisor at the three points the diagram marks: pause (hosts
waiting at the approval gate), abandon (hosts given up on) and completion.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pdf

# Palette matches the console so the report is recognisably the same system.
INK = '#1a1a1a'
MUTED = '#6b7280'
GREEN = '#d7f0dc'
AMBER = '#ffe2b8'
RED = '#ffd9d9'
GREY = '#eceff3'

# Matches the console: the workflow's branch name is implementation
# vocabulary, and the report is read by the same operator.
PATCH_TYPE = {'auto_patch': 'Auto', 'approved_patch': 'Approved'}

OUTCOME_LABEL = {
    'patched': 'Patched',
    'awaiting_approval': 'Awaiting approval',
    'rejected': 'Rejected',
    'failed': 'Failed',
    'timeout': 'Timed out',
    'unavailable': 'Not dispatched',
    'running': 'Running',
}


def _safe(name: str) -> str:
    """A filename component that cannot escape the reports directory."""
    return re.sub(r'[^A-Za-z0-9._-]', '_', str(name))[:64] or 'report'


def _phase(summary: dict) -> tuple[str, str, str]:
    """Headline for the run. Returns (title, body, background)."""
    failed = summary.get('failed', 0)
    waiting = summary.get('awaiting_approval', 0)
    patched = summary.get('patched', 0)
    if failed:
        return ('Action required — remediation incomplete',
                f'{failed} host(s) failed to patch and need investigation '
                f'before this CVE can be closed out.', RED)
    if waiting:
        return ('Awaiting operator approval',
                f'{waiting} host(s) are paused at the approval gate. No change '
                f'has been made to them yet.', AMBER)
    if patched:
        return ('Remediation complete',
                f'All {patched} affected host(s) were patched successfully.', GREEN)
    return ('No hosts dispatched',
            'The run produced no patch attempts. See the per-host table below.',
            GREY)


class CommunicationAgent:
    """Stateless, like the others — the Supervisor owns the run state."""

    name = 'communication-agent'

    def __init__(self, reports_dir: Path, trace=None, simulated: bool = False):
        self.dir = reports_dir
        self._trace = trace or (lambda *a, **k: None)
        # Stamped onto the page so a report cannot be mistaken for evidence of
        # a real remediation once it has been saved, mailed or printed.
        self.simulated = simulated

    def report(self, state: dict) -> dict[str, Any]:
        cve = state.get('cve_id', 'unknown')
        patch = state.get('patch') or {}
        results = patch.get('results') or []
        summary = patch.get('summary') or {}
        dry = state.get('dry_run') or {}
        hosts = state.get('hosts') or []
        now = datetime.now(timezone.utc)

        doc = pdf.Doc()

        doc.text('CVE Remediation Report', size=19, bold=True)
        doc.text(f'{cve}  ·  CVSS {state.get("cvss", "—")}  ·  '
                 f'{now.strftime("%d %b %Y %H:%M UTC")}', size=9.5, color=MUTED)
        doc.rule()
        doc.gap(4)

        if self.simulated:
            doc.banner('Simulated run — nothing was patched',
                       'Ansible Orchestrator was not reachable, so remediation ran in '
                       'the local simulator. No host was changed and these executions '
                       'exist in no AO instance. This report is for demonstration only.',
                       AMBER)

        title, body, bg = _phase(summary)
        doc.banner(title, body, bg)

        if state.get('description'):
            doc.text('Vulnerability', size=11, bold=True)
            doc.text(state['description'], size=9, color=INK)
            doc.gap(8)

        doc.text('Summary', size=11, bold=True)
        doc.gap(2)
        doc.table(
            ['Patched', 'Awaiting approval', 'Failed', 'Rejected', 'Hosts assessed'],
            [[summary.get('patched', 0), summary.get('awaiting_approval', 0),
              summary.get('failed', 0), summary.get('rejected', 0), len(hosts)]],
            [100, 120, 80, 80, 119])
        doc.gap(10)

        doc.text('Per-host outcome', size=11, bold=True)
        doc.gap(2)
        by_host = {h.get('host'): h for h in hosts}
        rows = []
        for r in results:
            h = by_host.get(r.get('host'), {})
            risk = h.get('risk') or h.get('risk_score') or ''
            # Each step carries what it cost. 'how long did patching take' was
            # unanswerable from this report, which is the first thing anyone
            # asks of it — and a per-step breakdown answers the more useful
            # second question of where the time actually went.
            steps = ' · '.join(
                f'{s.get("label") or s.get("name")}:{s.get("status")}'
                + (f' ({s["elapsed"]})' if s.get('elapsed') else '')
                for s in (r.get('steps') or [])
                if s.get('status') and s.get('status') not in ('pending', 'skipped')
            ) or '—'
            rows.append([r.get('host', '—'),
                         OUTCOME_LABEL.get(r.get('outcome'), r.get('outcome', '—')),
                         f'{risk:.1f}' if isinstance(risk, (int, float)) else '—',
                         PATCH_TYPE.get(r.get('group'), r.get('group') or '—'),
                         r.get('elapsed') or '—',
                         steps])
        doc.table(['Host', 'Outcome', 'Risk', 'Patch type', 'Elapsed',
                   'Workflow steps completed'],
                  rows or [['—', 'no hosts dispatched', '—', '—', '—', '—']],
                  [118, 74, 32, 72, 48, 155])
        if any(r.get('gate_wait') for r in results):
            doc.gap(3)
            doc.text('Elapsed is the time the workflow spent executing. Where a host '
                     'waited at the approval gate that wait is excluded, and shown '
                     'against the approval step itself — it measures how long the '
                     'operator took, not the automation.', size=8.6, color=MUTED)
        doc.gap(10)

        if dry.get('notes'):
            doc.text('Assessment notes', size=11, bold=True)
            for n in dry['notes']:
                doc.text(f'•  {n}', size=9)
            doc.gap(8)

        degraded = (patch.get('degraded') or []) + (state.get('degraded') or [])
        seen, uniq = set(), []
        for d in degraded:
            key = (d.get('step'), d.get('service'))
            if key not in seen:
                seen.add(key)
                uniq.append(d)
        if uniq:
            doc.text('Degraded inputs', size=11, bold=True)
            doc.text('These steps fell back to stored defaults because the named '
                     'service could not be reached.', size=8.6, color=MUTED)
            doc.gap(2)
            doc.table(['Step', 'Service', 'Suggested fix'],
                      [[d.get('step', ''), d.get('service', ''), d.get('fix', '')]
                       for d in uniq],
                      [110, 130, 259])
            doc.gap(10)

        doc.text('Context', size=11, bold=True)
        doc.gap(2)
        doc.table(['Field', 'Value'], [
            ['Maintenance window', dry.get('maintenance_window', '—')],
            ['Risk source', dry.get('risk_source', '—')],
            ['Verdict', dry.get('verdict', '—')],
            ['Workflow', patch.get('workflow', '—')],
            ['Assessment time', f'{state.get("elapsed_s", "—")}s'],
        ], [130, 369])

        doc.gap(14)
        doc.rule()
        doc.text('Generated by the Communication Agent (agent 3). The same summary '
                 'is what the Slack notification and ServiceNow ticket will carry '
                 'once those channels are wired up.', size=8, color=MUTED)

        stamp = now.strftime('%Y%m%d-%H%M%S')
        path = doc.save(self.dir / f'{_safe(cve)}-{stamp}.pdf')
        self._trace('communication', 'console', f'report written — {path.name}')
        return {
            'file': path.name,
            'path': str(path),
            'bytes': path.stat().st_size,
            'created_at': now.replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
            'cve_id': cve,
            'headline': title,
            'simulated': self.simulated,
            # Not sent anywhere yet; the diagram's steps 11 and 12.
            'channels': {'pdf': 'written', 'slack': 'not implemented',
                         'servicenow': 'not implemented'},
        }

    def recent(self, limit: int = 40) -> list[dict]:
        out = []
        for p in sorted(self.dir.glob('*.pdf'), key=lambda f: f.stat().st_mtime,
                        reverse=True)[:limit]:
            st = p.stat()
            out.append({
                'file': p.name, 'bytes': st.st_size,
                'cve_id': p.name.rsplit('-', 2)[0],
                'created_at': datetime.fromtimestamp(st.st_mtime, timezone.utc)
                              .replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
            })
        return out
