# App patch record — inventory-service on core-dc-1 (node3) — 2026-05-09

SYNTHETIC RECORD for the Applications v2 telco demo. Not a real change.

App: inventory-service   Site: core-dc-1   Server: node3   Environment: LIVE
Change: org.json 20211205 -> 20220320 (library swap, service restart)
Result: SUCCESS

What happened:
inventory-service feeds network topology to workflow-engine. Restart took 20 seconds; the
orchestrator showed stale topology for 40 seconds until the first sync.

Lessons:
Patch after any workflow-engine change has settled, so the window never runs with both down.
