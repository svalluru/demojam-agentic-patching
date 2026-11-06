# App patch record — orders-api on node1 (QA) — 2026-09-30

SYNTHETIC RECORD for the Applications v2 demo. Not a real change.

App: orders-api   Server: node1   Environment: QA
Change: log4j-core 2.24.1 -> 2.24.3 with log4j-api left at 2.24.1
Result: FAILED, rolled back

What happened:
The service failed to start: log4j-core 2.24.3 needs a matching log4j-api.
The playbook rolled log4j-core back and the service came up on the old jar.

Lessons:
Swap log4j-core only when log4j-api is already on the same version. orders-api
now runs log4j-api 2.24.3, so a 2.24.3 Lightwell build of log4j-core is safe.
