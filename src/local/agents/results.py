"""Results publishing agent — training data and observability.

Steps 13-14. Write-behind: neither store should ever fail a run, so both spool
to the workspace and replay on a later successful run.

Records which inputs were degraded alongside the outcome, so a later failure
can be correlated with "we patched this blind".
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from a2a.messages import AgentMessage
from agents.base import BaseAgent

WORKSPACE = Path(os.environ.get('WORKSPACE', '.'))
TRAINING_SPOOL = WORKSPACE / 'cve_console' / 'training_spool.jsonl'
OBSERVABILITY_SPOOL = WORKSPACE / 'cve_console' / 'observability_spool.jsonl'
BACKLOG_ALERT_THRESHOLD = 500


class ResultsAgent(BaseAgent):
    name = 'results'

    def on_publish(self, msg: AgentMessage) -> AgentMessage:
        """Payload: cve_id, hosts, outcomes, degraded_inputs, attempts, exits."""
        record = {
            'time': datetime.now(timezone.utc).isoformat(),
            'cve_id': msg.payload.get('cve_id'),
            'hosts_total': len(msg.payload.get('outcomes') or []),
            'outcomes': msg.payload.get('outcomes'),
            'attempts': msg.payload.get('attempts'),
            'exits': msg.payload.get('exits'),
            'degraded_inputs': sorted(set(msg.payload.get('degraded_inputs') or [])),
            'remediations': msg.payload.get('remediations'),
        }

        training_ok, training_backlog = self._write(TRAINING_SPOOL, record, self._push_training)
        obs_ok, obs_backlog = self._write(OBSERVABILITY_SPOOL, record, self._push_observability)

        degraded = []
        if not training_ok:
            degraded.append('training_store')
        if not obs_ok:
            degraded.append('observability_store')

        backlog_alert = max(training_backlog, obs_backlog) > BACKLOG_ALERT_THRESHOLD

        return msg.reply({
            'message': (
                f'Results Agent → Supervisor: outcome recorded for '
                f'{record["cve_id"]} ({record["hosts_total"]} hosts)'
                + (f' — spooled locally: {", ".join(degraded)}' if degraded else '')
                + (' — SPOOL BACKLOG GROWING' if backlog_alert else '')
            ),
            'record': record,
            'degraded_inputs': degraded,
            'backlog_alert': backlog_alert,
        })

    def _write(self, spool: Path, record: dict[str, Any], push) -> tuple[bool, int]:
        """Try the real store; spool on failure. Returns (ok, backlog_lines)."""
        try:
            push(record)
            self._replay(spool, push)
            return True, 0
        except Exception as exc:
            self.log.info('%s unavailable (%s) — spooling', spool.name, exc)
            try:
                spool.parent.mkdir(parents=True, exist_ok=True)
                with open(spool, 'a', encoding='utf-8') as fh:
                    fh.write(json.dumps(record) + '\n')
                return False, sum(1 for _ in open(spool, encoding='utf-8'))
            except OSError as werr:
                self.log.warning('Spool write failed for %s: %s', spool.name, werr)
                return False, 0

    def _replay(self, spool: Path, push) -> None:
        """Drain a previous outage's backlog once the store is reachable."""
        if not spool.exists():
            return
        try:
            lines = [l for l in spool.read_text(encoding='utf-8').splitlines() if l.strip()]
        except OSError:
            return
        if not lines:
            return
        self.log.info('Replaying %d spooled records from %s', len(lines), spool.name)
        remaining = []
        for line in lines:
            try:
                push(json.loads(line))
            except Exception:
                remaining.append(line)
        try:
            if remaining:
                spool.write_text('\n'.join(remaining) + '\n', encoding='utf-8')
            else:
                spool.unlink()
        except OSError:
            pass

    @staticmethod
    def _push_training(record: dict[str, Any]) -> None:
        """Step 13 — append to the RAG vector store so future runs learn."""
        import cve_flow

        vector_db_id = os.environ.get('VECTOR_DB_ID', cve_flow.DEFAULT_VECTOR_DB_ID)
        if not os.environ.get('LLAMA_STACK_URL'):
            raise RuntimeError('LLAMA_STACK_URL not configured')
        summary = (
            f'CVE {record["cve_id"]}: {record["hosts_total"]} hosts. '
            f'Outcomes: {json.dumps(record.get("outcomes"))}. '
            f'Remediations: {json.dumps(record.get("remediations"))}. '
            f'Degraded inputs: {record.get("degraded_inputs")}.'
        )
        cve_flow.http_json(
            f'{cve_flow.LLAMA_URL}/v1/vector-io/insert',
            method='POST',
            payload={
                'vector_db_id': vector_db_id,
                'chunks': [{'content': summary, 'metadata': {
                    'cve_id': record['cve_id'], 'time': record['time'],
                    'kind': 'patch_outcome',
                }}],
            },
            headers={'Content-Type': 'application/json'},
            verify_tls=True,
        )

    @staticmethod
    def _push_observability(record: dict[str, Any]) -> None:
        """Step 14 — ship the run record to the observability endpoint."""
        endpoint = os.environ.get('OBSERVABILITY_URL', '').strip()
        if not endpoint:
            raise RuntimeError('OBSERVABILITY_URL not configured')
        import cve_flow
        cve_flow.http_json(
            endpoint, method='POST', payload=record,
            headers={'Content-Type': 'application/json'}, verify_tls=False,
        )
