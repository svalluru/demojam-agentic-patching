# App patch record — inventory-service on lab (node1) — 2026-03-03

SYNTHETIC RECORD for the Applications v2 telco demo. Not a real change.

App: inventory-service   Site: lab   Server: node1   Environment: LAB
Change: json-path 2.9.0 upgrade evaluated, not applied
Result: SKIPPED

What happened:
inventory-service runs json-path 2.8.0 for its topology queries; 2.9.0 changed the default JSON provider and
how missing paths are reported, which broke three of its topology queries in the lab.

Lessons:
Stay on json-path 2.8.x: moving to 2.9 needs the topology queries re-tested. A fixed build of 2.8.0 (same
version) keeps the behaviour the queries rely on and is safe to take.
