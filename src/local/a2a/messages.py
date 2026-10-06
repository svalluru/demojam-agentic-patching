from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class MessageType(str, Enum):
    REQUEST = 'request'
    RESPONSE = 'response'
    EVENT = 'event'
    ERROR = 'error'


@dataclass
class AgentMessage:
    sender: str
    receiver: str
    msg_type: MessageType
    action: str
    payload: dict[str, Any] = field(default_factory=dict)
    msg_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    correlation_id: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'))

    def reply(self, payload: dict[str, Any], msg_type: MessageType = MessageType.RESPONSE) -> AgentMessage:
        return AgentMessage(
            sender=self.receiver,
            receiver=self.sender,
            msg_type=msg_type,
            action=self.action,
            payload=payload,
            correlation_id=self.msg_id,
        )

    def error(self, error: str) -> AgentMessage:
        return self.reply({'error': error}, msg_type=MessageType.ERROR)

    def to_stream_entry(self) -> dict[str, Any]:
        return {
            'time': self.timestamp,
            'event': 'a2a_message',
            'msg_id': self.msg_id,
            'from': self.sender,
            'to': self.receiver,
            'type': self.msg_type.value,
            'action': self.action,
            'message': self.payload.get('message', f'{self.sender} → {self.receiver}: {self.action}'),
            'detail': {k: v for k, v in self.payload.items() if k != 'message'},
        }

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d['msg_type'] = self.msg_type.value
        return d
