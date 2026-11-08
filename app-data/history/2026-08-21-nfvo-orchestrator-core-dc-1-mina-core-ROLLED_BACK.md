# App patch record — nfvo-orchestrator on core-dc-1 (node3) — 2026-08-21

SYNTHETIC RECORD for the Applications v2 telco demo. Not a real change.

App: nfvo-orchestrator   Site: core-dc-1   Server: node3   Environment: LIVE
Change: mina-core 2.2.4 -> 2.2.5 (library swap, service restart)
Result: ROLLED BACK

What happened:
core-dc-1 manages 340 network elements. The health check gave up after 30 seconds while
NETCONF sessions were still reconnecting; the jar was rolled back. A retry the next night with
a 60 second health window succeeded.

Lessons:
Only in the 00:00-04:00 network change window. Use a 60 second health window on core-dc-1.
A compromise of the NETCONF library here reaches every network element it configures.
