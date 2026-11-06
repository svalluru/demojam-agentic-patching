# App patch record — sample-app on node2 (Prod) — 2026-08-09

SYNTHETIC RECORD for the Applications v2 demo. Not a real change.

App: sample-app   Server: node2   Environment: Prod
Change: jackson-databind 2.15.2 -> 2.15.2.rhlw-00003 (library swap, service restart)
Result: ROLLED BACK

What happened:
After the restart the health check returned 503 for 45 seconds while the JVM
warmed its caches. The playbook's health check gave up after 30 seconds and
rolled the jar back. A second attempt with a 60 second health window succeeded
the same evening.

Lessons:
On node2 allow at least 60 seconds for the health check after a restart.
Patch outside 09:00-17:00: node2 carries live order traffic in business hours.
