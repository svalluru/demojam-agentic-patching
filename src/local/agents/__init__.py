"""AIP agents — Supervisor plus four specialist agents.

Wiring:

    from agents import build_system
    supervisor = build_system()
    supervisor.run('CVE-2020-25681')
"""
from __future__ import annotations

from pathlib import Path

from a2a.bus import MessageBus

from agents.base import BaseAgent
from agents.communication import CommunicationAgent
from agents.info import InfoAgent
from agents.patching import PatchingAgent
from agents.results import ResultsAgent
from agents.supervisor import SupervisorAgent

__all__ = [
    'BaseAgent', 'MessageBus', 'build_system',
    'SupervisorAgent', 'InfoAgent', 'PatchingAgent',
    'CommunicationAgent', 'ResultsAgent',
]


def build_system(state_file: Path | None = None) -> SupervisorAgent:
    """Instantiate the bus and all five agents; return the Supervisor.

    Agents self-register on the bus in BaseAgent.__init__, so constructing
    them is enough to make them reachable by name.
    """
    import cve_flow_demo

    bus = MessageBus(state_file=state_file)
    InfoAgent(bus, flow_module=cve_flow_demo)
    PatchingAgent(bus, flow_module=cve_flow_demo)
    CommunicationAgent(bus)
    ResultsAgent(bus)
    return SupervisorAgent(bus, flow_module=cve_flow_demo)
