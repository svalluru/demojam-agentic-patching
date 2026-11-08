# App patch record — oss-inventory on core-dc-1 (node3) — 2026-05-09

SYNTHETIC RECORD for the Applications v2 telco demo. Not a real change.

App: oss-inventory   Site: core-dc-1   Server: node3   Environment: LIVE
Change: postgresql 42.3.2 -> 42.3.3 (JDBC driver swap, service restart)
Result: SUCCESS

What happened:
oss-inventory feeds network topology to nfvo-orchestrator. Restart took 20 seconds; the
orchestrator showed stale topology for 40 seconds until the first sync.

Lessons:
Patch after any nfvo-orchestrator change has settled, so the window never runs with both down.
