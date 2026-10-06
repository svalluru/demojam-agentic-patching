"""Communication agent — Slack and ServiceNow.

Steps 11-12. Called by the Supervisor at pause, abandon and completion.

Never blocks the patch: if both channels are unreachable the message is spooled
locally and the loop continues. A notification outage must not stop a rollout,
but it must still show up in the final record.
"""
from __future__ import annotations

import json
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from a2a.messages import AgentMessage
from agents.base import BaseAgent

SPOOL = Path(os.environ.get('WORKSPACE', '.')) / 'cve_console' / 'notification_spool.jsonl'


class CommunicationAgent(BaseAgent):
    name = 'communication'

    def on_notify(self, msg: AgentMessage) -> AgentMessage:
        """Payload: text, severity (info|warning|error), cve_id, host, ticket."""
        text = msg.payload['text']
        severity = msg.payload.get('severity', 'info')
        wants_ticket = msg.payload.get('ticket', False)
        delivered: list[str] = []
        degraded: list[str] = []

        if self._slack(text, severity):
            delivered.append('slack')
        else:
            degraded.append('slack')

        ticket_id = None
        if wants_ticket:
            ticket_id = self._snow(text, msg.payload)
            if ticket_id:
                delivered.append(f'snow:{ticket_id}')
            else:
                degraded.append('snow')
                # Surface the pending ticket on whatever channel did work.
                if 'slack' in delivered:
                    self._slack(f'[TICKET-PENDING] {text}', severity)

        if not delivered:
            self._spool(text, severity, msg.payload)
            degraded.append('all_channels')

        return msg.reply({
            'message': (
                f'Communication Agent → Supervisor: notified via '
                f'{", ".join(delivered) if delivered else "local spool only"}'
            ),
            'delivered': delivered,
            'ticket_id': ticket_id,
            'degraded_inputs': degraded,
        })

    def _slack(self, text: str, severity: str) -> bool:
        webhook = os.environ.get('SLACK_WEBHOOK_URL', '').strip()
        if not webhook:
            return False
        icon = {'error': ':rotating_light:', 'warning': ':warning:'}.get(severity, ':information_source:')
        try:
            req = urllib.request.Request(
                webhook, method='POST',
                data=json.dumps({'text': f'{icon} {text}'}).encode(),
                headers={'Content-Type': 'application/json'},
            )
            urllib.request.urlopen(req, timeout=10)
            return True
        except Exception as exc:
            self.log.info('Slack delivery failed: %s', exc)
            return False

    def _snow(self, text: str, payload: dict[str, Any]) -> str | None:
        base = os.environ.get('SNOW_INSTANCE_URL', '').strip()
        token = os.environ.get('SNOW_TOKEN', '').strip()
        if not (base and token):
            return None
        body = {
            'short_description': text[:160],
            'description': json.dumps(payload, indent=2),
            'category': 'security_patching',
            'urgency': '1' if payload.get('severity') == 'error' else '3',
        }
        try:
            req = urllib.request.Request(
                f'{base.rstrip("/")}/api/now/table/incident', method='POST',
                data=json.dumps(body).encode(),
                headers={'Content-Type': 'application/json',
                         'Authorization': f'Bearer {token}'},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read()).get('result', {}).get('number')
        except Exception as exc:
            self.log.info('ServiceNow ticket creation failed: %s', exc)
            return None

    def _spool(self, text: str, severity: str, payload: dict[str, Any]) -> None:
        entry = {
            'time': datetime.now(timezone.utc).isoformat(),
            'severity': severity, 'text': text, 'payload': payload,
        }
        try:
            SPOOL.parent.mkdir(parents=True, exist_ok=True)
            with open(SPOOL, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(entry) + '\n')
        except OSError as exc:
            self.log.warning('Notification spool write failed: %s', exc)
