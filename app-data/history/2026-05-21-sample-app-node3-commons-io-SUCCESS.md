# App patch record — sample-app on node3 (Prod) — 2026-05-21

SYNTHETIC RECORD for the Applications v2 demo. Not a real change.

App: sample-app   Server: node3   Environment: Prod
Change: commons-io 2.11.0 -> 2.11.0.rhlw-00007 (library swap, service restart)
Result: SUCCESS

What happened:
Patched in the 22:00 maintenance window. Restart and health check in 18 seconds.
node3 is the standby node for sample-app and takes traffic only when node2 is down.

Lessons:
node3 is low risk: patch it before node2 so a problem shows up on the standby first.
