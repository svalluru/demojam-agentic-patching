# Host profile — pay-app-07.acme.internal

Environment: PRODUCTION
Business criticality: Tier 1 (payment processing)
Role: Payments application server, part of the pay-app cluster
OS: RHEL 9.4
Owner: Payments Platform team
Change window: Saturday 02:00-06:00 UTC
DBA on-call required: yes, for any patch requiring a service restart

Runtime characteristics:
- Carries long-lived client connections through a connection pool.
- Steady-state memory utilisation runs high, typically 75-80%.
- The application must be drained before restart or in-flight payment
  transactions are dropped.
- Historical patch success rate: 6 of 10 on first attempt, 10 of 10 after
  remediation.

Known sensitivities:
- Drain timeouts below 120 seconds have repeatedly failed on this host.
- /var fills quickly; package extraction needs a free-space pre-check.
- The payments service takes up to 90 seconds to report healthy after restart.
