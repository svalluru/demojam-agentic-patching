# App patch record — workflow-engine on edge-site-1 (node2) — 2026-09-30

SYNTHETIC RECORD for the Applications v2 telco demo. Not a real change.

App: workflow-engine   Site: edge-site-1   Server: node2   Environment: LIVE
Change: mina-core 2.2.4 -> 2.2.5 (library swap, service restart)
Result: SUCCESS, DEGRADED FOR 12 MINUTES

What happened:
The orchestrator came back healthy in 29 seconds, but inventory-service on the same server was
itself restarting for an unrelated change, so the orchestrator started on a stale topology feed.
Six configuration pushes to network elements were rejected as out of date until the feed
recovered 12 minutes later.

Lessons:
Check inventory-service is healthy (and not mid-change) before restarting workflow-engine:
the orchestrator depends on its topology feed. Never change both on the same server at once.
