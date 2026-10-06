"""Supervisor agent — owns control flow and per-CVE state.

Calls the four agents per CVE and owns the self-healing loop. The loop spans
three agents (Patching reports a failure, Info diagnoses it, Patching retries),
so only the Supervisor sees all of it — which is why the counters and the stop
decision live here and the agents stay stateless.

Replaces the former patch_manager.py.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from a2a.messages import AgentMessage, MessageType
from agents.base import BaseAgent

MAX_ATTEMPTS_PER_HOST = int(os.environ.get('MAX_ATTEMPTS_PER_HOST', '2'))
MAX_FAILED_PER_PHASE = int(os.environ.get('MAX_FAILED_PER_PHASE', '2'))

WORKSPACE = Path(os.environ.get('WORKSPACE', str(Path(__file__).resolve().parent.parent)))
STATE_DIR = WORKSPACE / 'cve_console'
STATE_FILE = STATE_DIR / 'state.json'

EXIT_HEALED = 'A'
EXIT_ABANDONED = 'B'
EXIT_ABORTED = 'C'


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


class SupervisorAgent(BaseAgent):
    name = 'supervisor'

    def __init__(self, bus, *, flow_module):
        super().__init__(bus)
        self._flow = flow_module
        self._lock = threading.Lock()
        self.reset()
        # Every A2A message lands in the console's agent sidebar.
        bus.on_message('*', self._stream_a2a)

    def reset(self) -> None:
        self.attempts: dict[str, int] = {}
        self.tried_fixes: dict[str, set[str]] = {}
        self.phase_failures = 0
        self.degraded: list[str] = []
        self.outcomes: dict[str, str] = {}
        self.remediations: list[dict] = []
        self.state: dict[str, Any] = {}

    # ------------------------------------------------------------- state

    def _stage(self, stage: str, message: str, **summary_updates) -> None:
        """Advance the pipeline stage and persist. Stage keys match the UI's STAGE_MAP."""
        ts = now_iso()
        with self._lock:
            self.state.setdefault('workflow', {}).update(
                flow_stage=stage, last_updated=ts)
            self.state.setdefault('summary', {}).update(
                flow_stage=stage, flow_message=message, **summary_updates)
            self.state.setdefault('stream', []).append(
                {'time': ts, 'event': stage, 'message': message})
            self._persist()
        self.log.info('STEP %s — %s', stage, message)

    def _stream_a2a(self, msg: AgentMessage) -> None:
        with self._lock:
            if not self.state:
                return
            self.state.setdefault('stream', []).append(msg.to_stream_entry())
            self.state['stream'] = self.state['stream'][-200:]

    def _persist(self) -> None:
        runs = self.state.get('runs') or [{}]
        runs[0].update(
            workflow=dict(self.state.get('workflow', {})),
            summary=dict(self.state.get('summary', {})),
            hosts=list(self.state.get('hosts', [])),
            aap=dict(self.state.get('aap', {})),
        )
        self.state['runs'] = runs
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(self.state, indent=2))

    def _call(self, agent: str, action: str, payload: dict) -> dict:
        """Send over the A2A bus; surface errors as a degraded payload."""
        resp = self.bus.send(AgentMessage(
            sender=self.name, receiver=agent,
            msg_type=MessageType.REQUEST, action=action, payload=payload,
        ))
        if resp is None or resp.msg_type == MessageType.ERROR:
            err = (resp.payload.get('error') if resp else 'no response')
            self.log.warning('%s.%s failed: %s', agent, action, err)
            self.degraded.append(f'{agent}.{action}')
            return {'error': err, 'degraded': True}
        self.degraded.extend(resp.payload.get('degraded_inputs') or [])
        return resp.payload

    def _notify(self, text: str, severity: str = 'info', ticket: bool = False, **extra) -> None:
        self._call('communication', 'notify',
                   {'text': text, 'severity': severity, 'ticket': ticket, **extra})

    # --------------------------------------------------------------- run

    def on_run_flow(self, msg: AgentMessage) -> AgentMessage:
        cve_id = msg.payload['cve_id']
        try:
            result = self.run(cve_id, triggered_at=msg.payload.get('triggered_at'))
            return msg.reply({'message': f'Flow complete for {cve_id}', 'result': result})
        except Exception as exc:
            self.log.exception('Flow failed for %s', cve_id)
            self._fail(str(exc))
            return msg.error(str(exc))

    def run(self, cve_id: str, triggered_at: str | None = None) -> dict:
        """Run up to the approval gate, then stop. resume() continues after."""
        self.reset()
        triggered_at = triggered_at or now_iso()
        self.state = self._base_state(cve_id, triggered_at)
        self._persist()

        # --- C1/C2: common code, not an agent -------------------------
        self._stage('loading_cve', f'Loading {cve_id} from Insights')
        import intake
        detail = intake.fetch_cve_detail(cve_id)
        if detail['degraded']:
            self.degraded.append('cve_intake')
        self.state['summary'].update(
            cvss=detail['cvss'], affected_count=detail['count'],
            cve_summary=detail['description'])
        self.state['hosts'] = list(detail['hosts'])
        self._stage('loading_cve_done',
                    f'{cve_id} — CVSS {detail["cvss"]}, {detail["count"]} systems affected')

        # --- Agent 1: info -------------------------------------------
        self._stage('scoring_hosts', 'Supervisor → Info Agent: enrich and score hosts')
        info = self._call('info', 'gather', {
            'cve_id': cve_id, 'cvss': detail['cvss'], 'hosts': detail['hosts'],
        })
        if info.get('error'):
            raise RuntimeError(f'Info agent failed: {info["error"]}')

        self.state['hosts'] = info['hosts']
        dry_run = info['dry_run']
        self.state['summary'].update(
            dry_run=dry_run, maintenance_window=info['maintenance_window'],
            degraded_inputs=sorted(set(self.degraded)))
        self._stage('scoring_hosts_done',
                    f'{dry_run["hosts_review"]} of {dry_run["hosts_total"]} hosts need review '
                    f'(risk source: {dry_run["risk_source"]})')
        self._stage('analyzing_history', 'Dry-run report ready')

        # --- Agent 2: build ------------------------------------------
        self._stage('lightspeed_assist', 'Supervisor → Patching Agent: generate playbook')
        build = self._call('patching', 'build', {'cve_id': cve_id, 'hosts': info['hosts']})
        if build.get('error'):
            raise RuntimeError(f'Build failed: {build["error"]}')

        tpl = build['templates']
        self.state['summary'].update(
            playbook_path=build['playbook_path'],
            lightspeed={'reason': build.get('lightspeed_reason')},
            job_template_url=tpl.get('job_template_url'),
            workflow_template_url=tpl.get('workflow_template_url'))
        self.state['aap'] = {
            'enabled': build.get('aap_live', False),
            'base_url': os.environ.get('AAP_BASE_URL'),
            'job_template_id': tpl.get('job_template_id'),
            'workflow_template_id': tpl.get('workflow_template_id'),
            'latest_workflow_job': build.get('workflow_job') or {'id': 1001, 'status': 'pending'},
        }
        self._stage('creating_aap_templates',
                    f'AAP templates ready (workflow {tpl.get("workflow_template_id")})')

        # --- Step 5: env gate ----------------------------------------
        gate = self._call('patching', 'env_gate', {
            'environment': os.environ.get('TARGET_ENV', 'prod'),
            'degraded_inputs': sorted(set(self.degraded)),
        })
        if gate.get('requires_approval', True):
            self._notify(
                f'{cve_id}: {dry_run["hosts_review"]} hosts need review — awaiting approval',
                severity='warning')
            self._stage('awaiting_aap', 'Awaiting approval before execution',
                        approval_state='pending_review')
            return {'status': 'pending_review', 'dry_run': dry_run}

        self.log.info('Env gate: %s — continuing without approval', gate.get('reason'))
        return self.resume()

    def resume(self) -> dict:
        """Continue after approval — phased execution with the self-healing loop."""
        if not self.state:
            self.state = json.loads(STATE_FILE.read_text())
        self._stage('approved', 'Approved — starting phased rollout',
                    approval_state='approved_in_progress')

        hosts = [h['host'] for h in self.state.get('hosts', [])]
        phases = self._split_phases(hosts)
        aborted = False

        for phase_name, phase_hosts in phases:
            if not phase_hosts:
                continue
            self.phase_failures = 0
            self._stage(f'executing_{phase_name}',
                        f'Phase: {phase_name} — {len(phase_hosts)} hosts')
            if not self._run_phase(phase_name, phase_hosts):
                aborted = True
                break

        cve_id = self.state['workflow']['cve']
        patched = sum(1 for v in self.outcomes.values() if v == 'patched')
        if aborted:
            self._stage('patch_failure', 'Rollout aborted — operator escalation required',
                        approval_state='flow_failed')
        else:
            self._stage('rollout_complete',
                        f'Rollout complete — {patched}/{len(self.outcomes)} systems patched')

        # --- Agent 4: results ----------------------------------------
        self._stage('workflow_complete', 'Supervisor → Results Agent: recording outcomes')
        self._call('results', 'publish', {
            'cve_id': cve_id,
            'outcomes': self.outcomes,
            'attempts': self.attempts,
            'remediations': self.remediations,
            'degraded_inputs': sorted(set(self.degraded)),
            'exits': self._exit_summary(),
        })
        self.state['summary']['final_summary'] = {
            'systems_patched': sum(1 for v in self.outcomes.values() if v == 'patched'),
            'actual_failures': sum(1 for v in self.outcomes.values() if v != 'patched'),
            'automatic_rollbacks': len(self.remediations),
            'training_events_generated': len(self.outcomes),
        }
        # --- Agent 3: communication ----------------------------------
        # Final summary goes out after the outcome is recorded, so a dropped
        # notification can never leave the run unrecorded.
        self._stage('notifying', 'Supervisor → Communication Agent: sending run summary')
        if aborted:
            notice = self._call('communication', 'notify', {
                'text': f'{cve_id}: rollout ABORTED — {patched}/{len(self.outcomes)} patched, '
                        f'operator escalation required',
                'severity': 'error', 'ticket': True,
            })
        else:
            notice = self._call('communication', 'notify', {
                'text': f'{cve_id}: rollout complete — {patched}/{len(self.outcomes)} systems patched',
                'severity': 'info', 'ticket': False,
            })
        self.state['summary']['notifications'] = {
            'delivered': notice.get('delivered') or [],
            'ticket_id': notice.get('ticket_id'),
            'degraded': notice.get('degraded_inputs') or [],
        }
        # Completion is set here rather than on a trailing workflow_complete,
        # which would walk the pipeline indicator back to LEARN.
        self._stage('notify_complete',
                    'Flow complete — notified via '
                    + (', '.join(notice.get('delivered') or []) or 'local spool only'),
                    approval_state='flow_failed' if aborted else 'approved_and_completed')
        return {'status': 'aborted' if aborted else 'complete',
                'outcomes': self.outcomes, 'exits': self._exit_summary()}

    # ------------------------------------------------- self-healing loop

    def _run_phase(self, phase: str, hosts: list[str]) -> bool:
        """Returns False on EXIT C (abort the whole rollout)."""
        for host in hosts:
            exit_path = self._patch_with_healing(host)
            if exit_path == EXIT_ABORTED:
                return False
        return True

    def _patch_with_healing(self, host: str) -> str:
        """The loop. Bounded: both counters increment inside it."""
        self.attempts[host] = 1
        self.tried_fixes.setdefault(host, set())
        fix: dict | None = None
        cve_id = self.state['workflow']['cve']

        while True:
            result = self._call('patching', 'patch_host', {
                'host': host, 'fix': fix, 'attempt': self.attempts[host],
            })

            if result.get('ok'):
                self.outcomes[host] = 'patched'
                return EXIT_HEALED

            error = result.get('error') or 'unknown failure'
            self._stage('patch_failure', f'ALERT: {host} health check FAILED',
                        failure={'host': host, 'check': 'POST-PATCH HEALTH CHECK',
                                 'status': 'FAILED'})

            # Rollback — a failure here is EXIT C, not a retry.
            rb = self._call('patching', 'rollback', {'host': host})
            if not rb.get('ok'):
                self.outcomes[host] = 'rollback_failed'
                self._notify(f'{cve_id}: ROLLBACK FAILED on {host} — host may be half-patched',
                             severity='error', ticket=True, host=host)
                return EXIT_ABORTED
            self._stage('rollback', f'Rollback successful on {host} — healthy, patch not applied',
                        failure={'host': host, 'check': 'POST-PATCH HEALTH CHECK',
                                 'status': 'FAILED', 'rollback_status': 'SUCCESS',
                                 'app_status': 'HEALTHY', 'patch_status': 'NOT APPLIED'})

            self.phase_failures += 1
            if self.phase_failures > MAX_FAILED_PER_PHASE:
                self.outcomes[host] = 'abandoned'
                self._notify(
                    f'{cve_id}: {self.phase_failures} hosts failed — aborting phase',
                    severity='error', ticket=True)
                return EXIT_ABORTED

            if self.attempts[host] >= MAX_ATTEMPTS_PER_HOST:
                return self._abandon(host, 'attempts exhausted')

            self._notify(f'{cve_id}: {host} rolled back, diagnosing', severity='warning')

            # Info agent — diagnose
            self._stage('analyzing_failure', f'Supervisor → Info Agent: diagnose {host}')
            diag = self._call('info', 'diagnose', {
                'host': host, 'error': error, 'cve_id': cve_id,
                'tried_fixes': sorted(self.tried_fixes[host]),
            })
            fix = diag.get('fix')
            if not fix:
                reason = ('no new remediation — all known fixes tried'
                          if diag.get('exhausted') else 'no known remediation')
                return self._abandon(host, reason)

            if fix['proposed_change'] in self.tried_fixes[host]:
                return self._abandon(host, 'diagnosis repeated an already-tried fix')
            self.tried_fixes[host].add(fix['proposed_change'])

            self._stage('remediation_proposed',
                        f'Remediation for {host}: {fix["proposed_change"]} '
                        f'({fix.get("from_value")} → {fix.get("to_value")})',
                        remediation={**fix, 'status': 'proposed'})

            gate = self._call('patching', 'env_gate', {
                'environment': os.environ.get('TARGET_ENV', 'prod'),
                'degraded_inputs': sorted(set(self.degraded)),
            })
            if gate.get('requires_approval', True) and not self._await_remediation_approval(host, fix):
                return self._abandon(host, 'remediation approval denied')

            self.attempts[host] += 1
            self.remediations.append({'host': host, **fix})
            self._stage('remediation_executing',
                        f'Retrying {host} (attempt {self.attempts[host]}) with {fix["proposed_change"]}',
                        remediation={**fix, 'status': 'executing'})

    def _abandon(self, host: str, reason: str) -> str:
        self.outcomes[host] = 'abandoned'
        cve_id = self.state['workflow']['cve']
        self._stage('remediation_proposed',
                    f'{host} abandoned — {reason}. Healthy and unpatched; rollout continues.')
        self._notify(f'{cve_id}: {host} abandoned — {reason}. Host healthy but UNPATCHED.',
                     severity='error', ticket=True, host=host)
        return EXIT_ABANDONED

    def _await_remediation_approval(self, host: str, fix: dict) -> bool:
        """Auto-approve remediation in prod only when explicitly allowed.

        Defaults to False: an unattended loop applying its own fixes to
        production is exactly what the approval gate exists to prevent.
        """
        if os.environ.get('AUTO_APPROVE_REMEDIATION', '').lower() in ('1', 'true', 'yes'):
            self._stage('remediation_approved',
                        f'Remediation auto-approved for {host} (AUTO_APPROVE_REMEDIATION)')
            return True
        self.log.info('Remediation for %s requires approval and none granted', host)
        return False

    # ----------------------------------------------------------- helpers

    @staticmethod
    def _split_phases(hosts: list[str]) -> list[tuple[str, list[str]]]:
        if not hosts:
            return []
        n = len(hosts)
        test = max(1, n // 5)
        canary = max(1, n // 4)
        return [
            ('test', hosts[:test]),
            ('canary', hosts[test:test + canary]),
            ('production', hosts[test + canary:]),
        ]

    def _exit_summary(self) -> dict[str, int]:
        return {
            'healed': sum(1 for v in self.outcomes.values() if v == 'patched'),
            'abandoned': sum(1 for v in self.outcomes.values() if v == 'abandoned'),
            'rollback_failed': sum(1 for v in self.outcomes.values() if v == 'rollback_failed'),
        }

    def _base_state(self, cve_id: str, triggered_at: str) -> dict:
        return {
            'active_flow': {'cve': cve_id, 'pid': os.getpid(), 'triggered_at': triggered_at},
            'workflow': {
                'name': f'{cve_id} remediation workflow', 'cve': cve_id,
                'status': 'in_progress', 'flow_stage': 'workflow_start',
                'last_updated': triggered_at, 'triggered_at': triggered_at,
                'polling': 'flow_in_progress',
            },
            'summary': {
                'flow_stage': 'workflow_start', 'flow_message': 'Supervisor starting flow',
                'approval_state': 'flow_in_progress', 'last_workflow_status': 'not_started',
                'last_job_status': 'not_started', 'mode': 'supervisor',
            },
            'hosts': [], 'stream': [], 'aap': {'enabled': False, 'base_url': None}, 'runs': [{}],
        }

    def _fail(self, error: str) -> None:
        if not self.state:
            return
        self.state.setdefault('summary', {}).update(
            approval_state='flow_failed', workflow_error=error)
        self.state.setdefault('workflow', {})['status'] = 'failed'
        self._persist()
