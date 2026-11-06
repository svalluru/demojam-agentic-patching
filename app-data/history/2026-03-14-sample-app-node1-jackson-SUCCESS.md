# App patch record — sample-app on node1 (QA) — 2026-03-14

SYNTHETIC RECORD for the Applications v2 demo. Not a real change.

App: sample-app   Server: node1   Environment: QA
Change: jackson-databind 2.15.2 -> 2.15.2.rhlw-00003 (library swap, service restart)
Result: SUCCESS

What happened:
The jar swap and restart took 22 seconds end to end. The health check answered
on the second probe. No traffic on QA at the time.

Lessons:
QA restarts are quick and safe to run in business hours. node1 also hosts
orders-api; the two services restart independently.
