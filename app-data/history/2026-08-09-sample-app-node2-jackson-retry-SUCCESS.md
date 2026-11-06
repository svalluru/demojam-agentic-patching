# App patch record — sample-app on node2 (Prod) — 2026-08-09 (retry)

SYNTHETIC RECORD for the Applications v2 demo. Not a real change.

App: sample-app   Server: node2   Environment: Prod
Change: retry of jackson-databind 2.15.2.rhlw-00003 with a 60 second health window
Result: SUCCESS

What happened:
Health answered after 41 seconds. No errors in the application log after the swap.

Lessons:
The 60 second health window is enough on node2. Keep it for future library swaps.
