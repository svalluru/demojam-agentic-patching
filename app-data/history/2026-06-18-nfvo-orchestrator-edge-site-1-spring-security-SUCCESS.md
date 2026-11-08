# App patch record — nfvo-orchestrator on edge-site-1 (node2) — 2026-06-18

SYNTHETIC RECORD for the Applications v2 telco demo. Not a real change.

App: nfvo-orchestrator   Site: edge-site-1   Server: node2   Environment: LIVE
Change: spring-security-web 5.7.10 -> 5.7.11 (library swap, service restart)
Result: SUCCESS

What happened:
edge-site-1 manages 120 network elements over NETCONF. Sessions were drained first;
the orchestrator was back in 28 seconds and re-established all NETCONF sessions in 2 minutes.

Lessons:
Drain NETCONF sessions before a restart at edge-site-1. Allow 2 minutes for sessions to come back.
