from __future__ import annotations

import logging
from typing import Any

from a2a.bus import MessageBus
from a2a.messages import AgentMessage, MessageType


class BaseAgent:
    """Base class for all AIP agents."""

    name: str = 'base'

    def __init__(self, bus: MessageBus):
        self.bus = bus
        self.log = logging.getLogger(f'agent.{self.name}')
        bus.register(self.name, self.handle)

    def handle(self, msg: AgentMessage) -> AgentMessage | None:
        method = getattr(self, f'on_{msg.action}', None)
        if method is None:
            return msg.error(f'{self.name} does not handle action {msg.action!r}')
        return method(msg)

    def ask(self, receiver: str, action: str, payload: dict[str, Any] | None = None) -> AgentMessage | None:
        msg = AgentMessage(
            sender=self.name,
            receiver=receiver,
            msg_type=MessageType.REQUEST,
            action=action,
            payload=payload or {},
        )
        return self.bus.send(msg)

    def emit(self, action: str, payload: dict[str, Any] | None = None) -> None:
        msg = AgentMessage(
            sender=self.name,
            receiver='*',
            msg_type=MessageType.EVENT,
            action=action,
            payload=payload or {},
        )
        self.bus.broadcast(msg)
