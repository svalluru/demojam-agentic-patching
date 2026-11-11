# App patch record — workflow-engine on core-dc-1 (node3) — 2026-07-14

SYNTHETIC RECORD for the Applications v2 telco demo. Not a real change.

App: workflow-engine   Site: core-dc-1   Server: node3   Environment: LIVE
Change: zookeeper 3.5.8 -> 3.5.9 (library swap, service restart)
Result: SUCCESS

What happened:
Restart at 01:10 inside the 00:00-04:00 window, back in 31 seconds. While it was down the
service-order portal queued 214 northbound orders (none lost, all processed within 4 minutes),
assurance paused 3 closed-loop corrective actions, and inventory-service's topology sync waited
and caught up. The zookeeper ensemble had quorum throughout; the orchestrator re-elected its
leader in 6 seconds.

Lessons:
Tell the service-order portal team before the restart: orders queue, they are not lost.
Confirm zookeeper quorum first. Expect closed-loop automation to pause for about 3 minutes.
