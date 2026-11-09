# App patch record — inventory-service on lab (node1) — 2026-03-03

SYNTHETIC RECORD for the Applications v2 telco demo. Not a real change.

App: inventory-service   Site: lab   Server: node1   Environment: LAB
Change: mina-core upgrade evaluated, not applied
Result: SKIPPED

What happened:
inventory-service pins mina-core 2.1.6 for its SFTP export; 2.2.x changed the API it uses.

Lessons:
mina-core fixes for 2.2.x do not apply to inventory-service: moving to 2.2 breaks its SFTP export. Patch releases on the
2.1 line (2.1.x) keep the API it uses and are safe to take.
