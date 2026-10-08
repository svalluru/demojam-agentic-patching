# demojam-agentic-patching

Agentic CVE patching: a **Supervisor agent** orchestrating specialist agents per
CVE, with a console UI, an XGBoost risk model on OpenShift, a Milvus + Llama
Stack RAG store, and remediation executed by an Ansible Orchestrator workflow.

## Architecture

![architecture](multi-agent/architecture.jpg)

```
Common code (not an agent)      CVE list + affected hosts from Insights
        │  for each CVE
        ▼
   Supervisor Agent             owns control flow + per-CVE state
        │
        ├─▶ 1 cve-gather-info-agent   RAG history · scheduler · risk · dry-run
        ├─▶ 2 Patching Agent          triggers the AO workflow, per host
        ├─▶ 3 Communication Agent     not implemented
        └─▶ 4 Results Agent           not implemented
```

### Status

| Agent | State |
|---|---|
| Common code (CVE list / detail) | done — Insights REST |
| 1 cve-gather-info-agent | done — RAG, risk model, dry-run report |
| 2 Patching Agent | done — triggers AO workflow per host, approve/reject |
| 3 Communication Agent | not started |
| 4 Results Agent | not started |

Steps 5–10 of the architecture (env gate, playbook, git, AAP sync, schedule,
remediation) are **not** in this repo — they are the Ansible Orchestrator
workflow `DemoJam Agentic Patching`. Agent 2 is a client of that workflow.

## Layout

```
agentic-patching.py        everything server-side: common code, Supervisor,
                           Info agent, Patching agent, HTTP backend
frontend/
  index.html               two-frame console: assess a CVE · CVE list · patch runs
  server.py                dev server — serves the UI, proxies /api/* to :8787
ao-setup/
  create-ao-objects.sh     creates AO credentials + integrations from .env
  playbooks/               AAP playbooks the AO workflow calls, and steps
rag-setup/
  deploy.sh                Milvus + Llama Stack as plain Pods (no RHOAI)
  ingest.py                load/verify the RAG vector store
  data/                    sample per-host patch history
risk_score/
  training/ serving/       XGBoost model
  openshift/               Deployment + Service + Route, deploy script
multi-agent/
  architecture.jpg/.html   architecture diagram (editable source)
```

## Setup

Copy the template and fill in credentials — `.env` is gitignored:

```bash
cp .env.example .env     # then edit
```

Deploy the backing services (each is independent):

```bash
./rag-setup/deploy.sh                          # Milvus + Llama Stack
./rag-setup/ingest.py --route https://$ROUTE --dir ./rag-setup/data --ensure
./risk_score/openshift/deploy-risk-score.sh    # XGBoost model
./ao-setup/create-ao-objects.sh                # AO credentials + integrations
```

## Run

Two processes. The backend holds the agents; the frontend serves the UI and
proxies to it.

```bash
# terminal 1 — agents + API on :8787
./agentic-patching.py serve

# terminal 2 — UI on :8788
cd frontend && python3 server.py --env ../.env
```

Open <http://127.0.0.1:8788>, pick a CVE, **Assess CVE Impact**, review the
dry-run, then **Start Patch**. Hosts routed to the approval branch show
Approve / Reject buttons. **Patch runs** lists past executions read live from AO.

### CLI

```bash
./agentic-patching.py list                     # CVE list
./agentic-patching.py detail CVE-2026-12405    # CVE + affected hosts
./agentic-patching.py run    CVE-2026-12405    # Supervisor -> Info agent
./agentic-patching.py patch  CVE-2026-12405    # ... -> Patching agent
```

### Switches

| Variable | Effect |
|---|---|
| `HOSTS_FILTER=pay-app-07` | restrict to matching hosts |
| `HOSTS_LIMIT=3` | cap host count |
| `REVIEW_THRESHOLD=30` | risk score above which a host needs approval |
| `AO_WORKFLOW_NAME` | workflow to trigger (default `DemoJam Agentic Patching`) |
| `AO_DECIDE_WAIT=90` | seconds to wait for a run to settle after approve/reject |
| `LAB_TAG` | passed to the workflow as `lab_tag` |
| `INSIGHTS_VERIFY_TLS=false` | if this machine cannot verify the sso.redhat.com chain |
| `RISK_VERIFY_TLS=false` | for sandbox cluster certificates |

## Design notes

**No fabricated data.** Every external call either succeeds or raises
`BackendUnavailable` naming the service and how to fix it. The dry-run report is
what a human approves against, so a fallback that quietly substitutes made-up
numbers is worse than a failure.

**The Supervisor owns state**; agents are stateless. Counters and stop decisions
live in one place.

**Risk scoring is batched** — one call for all hosts. Calling the model per host
turned a 59-host CVE into 59 sequential round trips.

**Status is re-read, never trusted.** An approved AO run can fail seconds after
the console stops polling, so non-terminal rows keep polling until they settle
and a failed activity marks the run failed even before AO finishes marking it.

## Known gaps

- Agents 3 and 4 (Communication, Results) are not implemented.
- The AAP job templates the AO workflow calls — `CVE - Fetch and Commit` and
  `CVE - Sync and Deploy Remediation` — do not exist in AAP yet, so an approved
  run fails at `fetch_and_commit_prod`. See `ao-setup/playbooks/`.
- The risk model scores every host of a given CVE almost identically, because
  three of its four inputs describe the CVE rather than the host. Threshold
  tuning or retraining is needed before the score is useful as triage.
- A Llama Stack restart silently empties the vector store registry — searches
  return no hits with no error. Run `ingest.py --ensure` after any restart; see
  `rag-setup/README.md`.
- No scheduler service exists; the maintenance window is configuration.
