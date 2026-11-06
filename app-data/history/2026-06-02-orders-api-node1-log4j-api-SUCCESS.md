# App patch record — orders-api on node1 (QA) — 2026-06-02

SYNTHETIC RECORD for the Applications v2 demo. Not a real change.

App: orders-api   Server: node1   Environment: QA
Change: log4j-api 2.23.1 -> 2.24.3 (library upgrade, service restart)
Result: SUCCESS

What happened:
orders-api shares node1 with sample-app. Both were restarted in the same
window; orders-api took 9 seconds to answer its health check on port 8081.

Lessons:
orders-api is a small service with no state. It is the safest app to try a new
library build on first.
