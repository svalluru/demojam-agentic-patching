# App patch record — workflow-engine on core-dc-1 (node3) — 2026-08-21

SYNTHETIC RECORD for the Applications v2 telco demo. Not a real change.

App: workflow-engine   Site: core-dc-1   Server: node3   Environment: LIVE
Change: spring-webmvc 5.3.16 -> 5.3.17 (library swap, service restart)
Result: ROLLED BACK

What happened:
core-dc-1 manages 340 network elements. The health check gave up after 30 seconds while
the REST API was still warming up and NETCONF sessions were reconnecting; the jar was rolled back. A retry the next night with
a 60 second health window succeeded.

Lessons:
Only in the 00:00-04:00 network change window. Use a 60 second health window on core-dc-1.
The northbound REST API here is the path every order takes to 340 network elements.
