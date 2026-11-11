# App note — workflow-engine dependencies and consumers — 2026-10-20

SYNTHETIC RECORD for the Applications v2 telco demo. Not a real change.

App: workflow-engine (NFVO / MANO)
Sites: lab (node1), edge-site-1 (node2), core-dc-1 (node3)
Type: NOTE (service map, reviewed with the network operations team)

Who depends on it:
- service-order portal (northbound API): orders queue during a restart, none are lost
- assurance and closed-loop automation: automated corrective actions pause until it is back
- inventory-service: topology sync pauses and catches up afterwards

What it depends on:
- zookeeper ensemble for leader election: needs quorum before a restart
- inventory-service topology feed: must be healthy, or the orchestrator starts on stale topology
- orders database (PostgreSQL)

During a restart:
NETCONF sessions to every managed network element drop and reconnect (0 on lab, 120 on
edge-site-1, 340 on core-dc-1). Live sites change only in the 00:00-04:00 window.
