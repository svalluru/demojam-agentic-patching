"""Info agent — enrichment and diagnosis.

Steps 1-4: RAG history, scheduler window, risk score, dry-run report.
Also serves ``diagnose`` during the Supervisor's self-healing loop — same RAG
and LLM plumbing, pointed at a failure instead of a CVE.

Replaces the former vulnerability.py, risk.py and diagnosis.py.
"""
from __future__ import annotations

import os
import re
from typing import Any

from a2a.messages import AgentMessage
from agents.base import BaseAgent

REVIEW_THRESHOLD_MODEL = 30.0
# The heuristic produces systematically higher scores than the model
# (cvss*6 alone crosses 30 at CVSS 5.0), so it needs its own threshold.
REVIEW_THRESHOLD_HEURISTIC = 55.0

DEFAULT_MAINTENANCE_WINDOW = os.environ.get('DEFAULT_MAINTENANCE_WINDOW', 'Sat 02:00-06:00 UTC')

# Step 20 fallback: known failure signatures, used when the LLM is unreachable.
# Ordered — first match wins.
FAILURE_SIGNATURES: list[tuple[str, dict[str, str]]] = [
    (r'drain|connection pool|graceful|in-flight', {
        'likely_cause': 'Application drain timeout too short',
        'proposed_change': 'Increase application drain timeout',
        'from_value': '30 seconds', 'to_value': '120 seconds',
    }),
    (r'no space|disk full|ENOSPC', {
        'likely_cause': 'Insufficient disk space for package extraction',
        'proposed_change': 'Reclaim space before patching',
        'from_value': 'no pre-check', 'to_value': 'dnf clean all + 2GB free check',
    }),
    (r'lock|another app|yum.pid|dpkg.*lock', {
        'likely_cause': 'Package manager lock held by another process',
        'proposed_change': 'Wait for lock release before retry',
        'from_value': 'immediate', 'to_value': 'poll lock up to 300s',
    }),
    (r'failed to (re)?start|service.*(dead|inactive)|systemctl', {
        'likely_cause': 'Service failed to restart after patch',
        'proposed_change': 'Extend post-restart health check grace period',
        'from_value': '10 seconds', 'to_value': '90 seconds',
    }),
]


class InfoAgent(BaseAgent):
    name = 'info'

    def __init__(self, bus, *, flow_module):
        super().__init__(bus)
        self._flow = flow_module

    # ---------------------------------------------------------------- gather

    def on_gather(self, msg: AgentMessage) -> AgentMessage:
        """Steps 1-4. Payload: cve_id, cvss, hosts (from intake)."""
        cve_id = msg.payload['cve_id']
        cvss = msg.payload['cvss']
        hosts_raw = msg.payload['hosts']
        degraded: list[str] = []

        self.emit('stage_update', {'message': f'Info Agent enriching {len(hosts_raw)} hosts for {cve_id}'})

        # Step 3 — risk score (before RAG so we know which hosts need history)
        hosts_scored, risk_source = self._score(hosts_raw, cvss)
        if risk_source != 'live':
            degraded.append('risk_score')

        # Step 1 — RAG history, only for hosts flagged for review
        hosts_full, rag_source = self._flow._try_rag_summaries(hosts_scored)
        if rag_source != 'LIVE':
            degraded.append('history')

        # Step 2 — scheduler
        window, window_source = self._window()
        if window_source != 'live':
            degraded.append('maintenance_window')

        review = [h for h in hosts_full if h.get('decision') == 'review']

        # Step 4 — dry-run report
        dry_run = {
            'cve_id': cve_id,
            'cvss': cvss,
            'hosts_total': len(hosts_full),
            'hosts_review': len(review),
            'hosts_auto': len(hosts_full) - len(review),
            'maintenance_window': window,
            'risk_source': risk_source,
            'degraded_inputs': degraded,
            'verdict': 'review_required' if review else 'auto_approve_eligible',
        }

        return msg.reply({
            'message': (
                f'Info Agent → Supervisor: {len(hosts_full)} hosts scored, '
                f'{len(review)} need review'
                + (f' (degraded: {", ".join(degraded)})' if degraded else '')
            ),
            'hosts': hosts_full,
            'dry_run': dry_run,
            'maintenance_window': window,
            'degraded_inputs': degraded,
        })

    def _score(self, hosts_raw: list[dict], cvss: float) -> tuple[list[dict], str]:
        """Step 3. Model first; heuristic fallback is labelled, not silent."""
        affected = len(hosts_raw)
        try:
            scored = []
            for h in hosts_raw:
                score = self._flow_risk_live(cvss, h['age_days'], affected)
                scored.append(self._decide(h, score, REVIEW_THRESHOLD_MODEL, 'model'))
            return scored, 'live'
        except Exception as exc:
            if self._flow.strict_mode():
                raise RuntimeError(
                    f'risk model unreachable and STRICT_MODE is enabled: {exc}. '
                    f'FIX: set RISK_URL (and RISK_VERIFY_TLS=false for sandbox certs)'
                ) from exc
            self.log.info('Risk model unavailable (%s) — heuristic fallback', exc)
            self.emit('risk_degraded', {
                'message': f'Info Agent: risk model unreachable, using heuristic — {exc}',
            })
            scored = []
            for h in hosts_raw:
                score = round((cvss * 6.0) + min(h['age_days'] / 30.0, 10.0) + min(affected, 10), 2)
                scored.append(self._decide(h, score, REVIEW_THRESHOLD_HEURISTIC, 'heuristic'))
            return scored, 'heuristic'

    def _flow_risk_live(self, cvss: float, age_days: int, affected: int) -> float:
        """Call the risk model, letting failures propagate.

        cve_flow.risk_score() swallows every exception and silently returns the
        heuristic, so the caller can never tell the model was down. This goes
        straight to the endpoint so _score() can label the result honestly.
        """
        import json
        import cve_flow

        payload = {'instances': [{
            'cvss': cvss, 'age_days': age_days,
            'affected_hosts': affected, 'type': 'security',
        }]}
        # Cluster Routes commonly use sandbox/self-signed certs, so follow the
        # same opt-out the rest of the codebase uses rather than failing closed
        # and silently dropping to the heuristic.
        verify = os.environ.get(
            'RISK_VERIFY_TLS', os.environ.get('AAP_VERIFY_TLS', 'true'),
        ).lower() not in {'0', 'false', 'no'}
        result = cve_flow.http_json(
            cve_flow.RISK_URL, method='POST', payload=payload,
            headers={'Content-Type': 'application/json'}, verify_tls=verify,
        )
        for key in ('predictions', 'outputs', 'data'):
            if result.get(key):
                value = result[key][0]
                if isinstance(value, dict):
                    for inner in ('score', 'risk_score', 'prediction', 'value'):
                        if inner in value:
                            return float(value[inner])
                return float(value)
        raise RuntimeError(f'Unexpected risk model response: {json.dumps(result)[:200]}')

    @staticmethod
    def _decide(host: dict, score: float, threshold: float, source: str) -> dict:
        review = score > threshold
        return {
            **host,
            'risk_score': round(score, 2),
            'risk_source': source,
            'decision': 'review' if review else 'ok',
            'reason': (
                f'Risk {score:.1f} exceeds {threshold:.0f} threshold ({source}) — requires review.'
                if review else f'Risk {score:.1f} below {threshold:.0f} threshold ({source}).'
            ),
        }

    def _window(self) -> tuple[str, str]:
        """Step 2. No scheduler service yet — config default, never 'now' for prod."""
        configured = os.environ.get('MAINTENANCE_WINDOW')
        if configured:
            return configured, 'live'
        return DEFAULT_MAINTENANCE_WINDOW, 'default'

    # -------------------------------------------------------------- diagnose

    def on_diagnose(self, msg: AgentMessage) -> AgentMessage:
        """Self-heal step. Payload: host, error, cve_id, tried_fixes."""
        host = msg.payload['host']
        error = msg.payload.get('error', 'Unknown failure')
        cve_id = msg.payload.get('cve_id', '')
        tried = set(msg.payload.get('tried_fixes') or [])

        self.emit('stage_update', {'message': f'Info Agent diagnosing failure on {host}'})

        history = ''
        try:
            rag = self._flow_rag(host)
            history = rag.get('summary', '')
        except Exception as exc:
            self.log.info('RAG unavailable during diagnose (%s)', exc)

        fix, source = self._propose(host, error, cve_id, history)

        if fix is None:
            return msg.reply({
                'message': f'Info Agent → Supervisor: no known remediation for {host}',
                'host': host, 'fix': None, 'source': source,
            })

        if fix['proposed_change'] in tried:
            return msg.reply({
                'message': (
                    f'Info Agent → Supervisor: only remediation for {host} '
                    f'was already attempted — no new option'
                ),
                'host': host, 'fix': None, 'source': source, 'exhausted': True,
            })

        return msg.reply({
            'message': (
                f'Info Agent → Supervisor: root cause on {host} = '
                f'{fix["likely_cause"]} ({source})'
            ),
            'host': host, 'fix': fix, 'source': source, 'history': history,
        })

    def _flow_rag(self, host: str) -> dict:
        vector_db_id = os.environ.get('VECTOR_DB_ID', self._flow_default_vector_db())
        import cve_flow
        return cve_flow.rag_summary_for_host(host, vector_db_id)

    @staticmethod
    def _flow_default_vector_db() -> str:
        import cve_flow
        return cve_flow.DEFAULT_VECTOR_DB_ID

    def _propose(self, host: str, error: str, cve_id: str,
                 history: str) -> tuple[dict | None, str]:
        """LLM first; rule table when it is unreachable; never guess."""
        try:
            fix = self._propose_llm(host, error, cve_id, history)
            if fix:
                return fix, 'llm'
        except Exception as exc:
            if self._flow.strict_mode():
                raise RuntimeError(
                    f'LLM unreachable during diagnose and STRICT_MODE is enabled: {exc}. '
                    f'FIX: start Llama Stack / set LLAMA_STACK_URL'
                ) from exc
            self.log.info('LLM unavailable during diagnose (%s) — rule table', exc)
            self.emit('diagnose_degraded', {
                'message': f'Info Agent: LLM unreachable, matching failure signatures — {exc}',
            })

        haystack = f'{error} {history}'.lower()
        for pattern, fix in FAILURE_SIGNATURES:
            if re.search(pattern, haystack):
                return {**fix, 'evidence': 'matched known failure signature',
                        'risk': 'Medium'}, 'rule_table'
        return None, 'no_match'

    def _propose_llm(self, host: str, error: str, cve_id: str, history: str) -> dict | None:
        import json
        import cve_flow

        prompt = (
            f'A patch for {cve_id} failed on host {host}. Error: {error}. '
            f'Historical context: {history or "none available"}. '
            'Return ONLY a JSON object with keys: likely_cause, proposed_change, '
            'from_value, to_value, evidence. No markdown.'
        )
        result = cve_flow.http_json(
            f'{cve_flow.LLAMA_URL}/v1/responses',
            method='POST',
            payload={
                'model': cve_flow.DEFAULT_LLM_MODEL,
                'input': [{'role': 'user', 'content': prompt}],
                'stream': False,
            },
            headers={'Content-Type': 'application/json'},
            verify_tls=True,
        )
        text = ''
        for item in result.get('output', []):
            for content in item.get('content', []):
                if content.get('text'):
                    text = content['text'].strip()
                    break
            if text:
                break
        if not text:
            return None
        if text.startswith('```'):
            text = text.split('\n', 1)[1].rsplit('```', 1)[0].strip()
        fix = json.loads(text)
        fix.setdefault('risk', 'Medium')
        return fix
