from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

from .messages import AgentMessage, MessageType

LOG = logging.getLogger('a2a.bus')

MessageHandler = Callable[[AgentMessage], AgentMessage | None]


class MessageBus:
    """In-process message router with state.json stream logging."""

    def __init__(self, state_file: Path | None = None):
        self._handlers: dict[str, MessageHandler] = {}
        self._listeners: dict[str, list[Callable[[AgentMessage], None]]] = defaultdict(list)
        self._log: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._state_file = state_file

    def register(self, agent_name: str, handler: MessageHandler) -> None:
        self._handlers[agent_name] = handler

    def on_message(self, event: str, callback: Callable[[AgentMessage], None]) -> None:
        self._listeners[event].append(callback)

    def send(self, msg: AgentMessage) -> AgentMessage | None:
        self._record(msg)
        self._notify(msg)

        handler = self._handlers.get(msg.receiver)
        if handler is None:
            LOG.warning('No handler registered for agent %r (message from %s)', msg.receiver, msg.sender)
            return msg.error(f'Agent {msg.receiver!r} not registered')

        try:
            response = handler(msg)
        except Exception as exc:
            LOG.exception('Agent %s failed handling %s from %s', msg.receiver, msg.action, msg.sender)
            response = msg.error(str(exc))

        if response is not None:
            self._record(response)
            self._notify(response)

        return response

    def broadcast(self, msg: AgentMessage) -> None:
        self._record(msg)
        self._notify(msg)

    @property
    def message_log(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._log)

    def flush_to_state(self) -> None:
        if not self._state_file or not self._state_file.exists():
            return
        with self._lock:
            entries = [m for m in self._log]
        if not entries:
            return
        try:
            state = json.loads(self._state_file.read_text())
            stream = state.get('stream', [])
            stream.extend(entries)
            state['stream'] = stream[-200:]
            self._state_file.write_text(json.dumps(state, indent=2))
        except Exception:
            LOG.exception('Failed to flush A2A messages to state.json')

    def _record(self, msg: AgentMessage) -> None:
        entry = msg.to_stream_entry()
        with self._lock:
            self._log.append(entry)
        LOG.info(
            'A2A %s %s→%s action=%s',
            msg.msg_type.value,
            msg.sender,
            msg.receiver,
            msg.action,
        )

    def _notify(self, msg: AgentMessage) -> None:
        for cb in self._listeners.get('*', []):
            try:
                cb(msg)
            except Exception:
                LOG.exception('Listener error on wildcard')
        for cb in self._listeners.get(msg.action, []):
            try:
                cb(msg)
            except Exception:
                LOG.exception('Listener error on %s', msg.action)
