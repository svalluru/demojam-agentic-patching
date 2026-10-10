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
        ├─▶ 1 cve-gather-info-agent   RAG history · scheduler · risk · patch plan
        ├─▶ 2 Patching Agent          triggers the AO workflow, per host
        ├─▶ 3 Communication Agent     not implemented
        └─▶ 4 Results Agent           not implemented
```

### Status

| Agent | State |
|---|---|
| Common code (CVE list / detail) | done — Insights REST |
| 1 cve-gather-info-agent | done — RAG, risk model, patch plan |
| 2 Patching Agent | done — triggers AO workflow per host, approve/reject |
| 3 Communication Agent | not started |
| 4 Results Agent | not started |

Steps 5–10 of the architecture (env gate, playbook, git, AAP sync, schedule,
remediation) are **not** in this repo — they are the Ansible Orchestrator
workflow `DemoJam Agentic Patching`. Agent 2 is a client of that workflow.

## Layout

```
QUICKSTART.md              clone-to-running guide for a new joiner
demo.sh                    start the console — offline by default, --live for real
agentic-patching.py        everything server-side: common code, Supervisor,
                           Info agent, Patching agent, HTTP backend
fallbacks.py               every stored default, in one editable file
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

## Try it — one command, no setup

```bash
./demo.sh
```

New to this? Start with **[QUICKSTART.md](QUICKSTART.md)** — clone-to-running
in a minute, with a walkthrough of both demo CVEs.

Opens <http://127.0.0.1:8788>. No cluster, no `.env`, no network: every step
serves stored defaults and the console labels all of them. **Nothing is
patched** — approving a host resolves a simulated run that exists in no AO
instance. Ctrl-C to stop.

```bash
./demo.sh --live     # real backends from .env, per-step fallback if one is down
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

`./demo.sh` wraps this. The two processes, if you want them separately — the
backend holds the agents, the frontend serves the UI and proxies to it:

```bash
# terminal 1 — agents + API on :8787
./agentic-patching.py serve

# terminal 2 — UI on :8788
cd frontend && python3 server.py --env ../.env
```

Open <http://127.0.0.1:8788>, hit **Assess** on a CVE row, review the patch
plan, then dispatch it. The dispatch button is labelled from the plan's
verdict — *Patch N hosts* in red when the press really does patch them
unattended, *Send N for approval* in black when every host will halt at the
gate instead. Hosts routed to the approval branch show Approve / Reject
buttons, and once approved the row tracks its execution through the remaining
workflow nodes to *Patched*. **Patch runs** lists past executions read live
from AO.

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
| `REVIEW_THRESHOLD=30` | risk score above which a host needs approval — model scores only |
| `HEURISTIC_THRESHOLD=55` | the same gate for heuristic scores, which are not on the same scale. This is the one in play whenever the risk model is unreachable, so it governs the whole offline demo |
| `AO_WORKFLOW_NAME` | workflow to trigger (default `DemoJam Agentic Patching`) |
| `AO_DECIDE_WAIT=90` | seconds to wait for a run to settle after approve/reject |
| `LAB_TAG` | passed to the workflow as `lab_tag` |
| `INSIGHTS_VERIFY_TLS=false` | if this machine cannot verify the sso.redhat.com chain |
| `RISK_VERIFY_TLS=false` | for sandbox cluster certificates |
| `INSIGHTS_TIMEOUT` / `RISK_TIMEOUT` / `RAG_TIMEOUT` / `AO_TIMEOUT` | per-service read budgets (15 / 8 / 20 / 10s) |

See **Offline / fallback mode** below for `STRICT` and `FALLBACK_PATCH`.

### Settings panel

The gear in the top right opens every one of these, grouped, with its built-in
default shown until something overrides it. A row is chipped `.env` when it was
set before startup and `changed` when this panel set it.

Changes take effect on the next assessment and are **in-memory only** — they
are lost on restart, and `.env` stays the durable place. The two passwords are
write-only: the panel never reads them back, and leaving one blank keeps the
current value. `BACKEND_HOST` / `BACKEND_PORT` are shown but not editable; the
socket is already open by the time the panel can reach the process.

## Offline / fallback mode

Every step has a stored default, so the whole console can be demonstrated with
no cluster at all. All defaults live in one file, [`fallbacks.py`](fallbacks.py).

| Step | Backend | Fallback |
|---|---|---|
| C1 CVE list | Insights | 2 real CVEs with real CVSS |
| C2 affected hosts | Insights | 5 hosts for CVE-2024-3094, 2 for CVE-2024-1086 |
| 1 patch history | Llama Stack / Milvus | canned per-host summaries |
| 3 risk score | XGBoost on OpenShift | heuristic, threshold 55 not 30 |
| 5–10 remediation | Ansible Orchestrator | simulated run, local to this console |

The two CVEs route differently on purpose: CVE-2024-3094 at CVSS 10.0 sends all
five hosts to the approval gate, CVE-2024-1086 at 7.8 auto-patches both of its
two. One demo covers each branch.

**Nothing is ever actually patched by the fallback.** A simulated run pauses at
the approval gate and resolves to `patched` or `rejected` locally, so the
approval path stays demonstrable, but no host is touched and the execution
exists in no AO instance.

**Where the labelling goes depends on the mode**, because the reader's question
differs:

- *Offline* — the whole session is fabricated, so one banner across the top of
  the page says so and the frames are left to read as a normal flow. Per-step
  labels would be noise repeated on every row.
- *Live, with one backend down* — there is no banner, and a single step that
  quietly fell back is exactly what a reviewer needs told before approving a
  production patch. So the plan shows a `degraded` panel naming the step,
  the service and the fix, and any simulated row is chipped `SIMULATED`.

The API always carries the truth either way: `degraded` on the plan and
`simulated: true` on affected runs, whatever the console chooses to draw.

| Variable | Effect |
|---|---|
| `OFFLINE=1` | what `./demo.sh` sets — stored defaults only, no network at all |
| `STRICT=true` | disable all fallbacks; raise the real error instead |
| `FALLBACK_PATCH=unavailable` | report "not dispatched" rather than simulating |
| `CONNECT_TIMEOUT=3` | reachability budget per service |
| `CIRCUIT_TTL=30` | how long a service stays tripped after failing |
| `DEMO_LATENCY=0.35` | offline-only pause per agent step; `0` disables |

Simulated runs persist to `runs/simulated.json` so the Patch runs page survives
a restart. Real runs need no such thing — AO is their store. Delete the file to
reset the demo.

## Design notes

**Fail fast on reachability, be patient on answers.** Every call TCP-connects
first with a short budget, because a stopped pod leaves its Route resolving
with nothing behind it and the socket hangs for the full read timeout. A
service that fails is then tripped for `CIRCUIT_TTL`, so a dead backend costs
one probe per run rather than one per host. Together these took a patch plan
against stopped backends from 76s to under 7s; `OFFLINE=1` skips the probe
entirely and opens no socket at all.

**Degrade on reads, fail closed on writes.** A missing risk score can be
estimated; a patch cannot be assumed. That asymmetry is why `FALLBACK_PATCH`
exists and why the simulator never reports a host as patched without an
operator clicking Approve.

**The Supervisor owns state**; agents are stateless. Counters and stop decisions
live in one place.

**Risk scoring is batched** — one call for all hosts. Calling the model per host
turned a 59-host CVE into 59 sequential round trips.

**Status is re-read, never trusted.** An approved AO run can fail seconds after
the console stops polling, so non-terminal rows keep polling until they settle
and a failed activity marks the run failed even before AO finishes marking it.

**Progress is measured, never animated.** A row's bar is the fraction of that
execution's workflow nodes that have reported finished, so it stalls exactly
when the run stalls — which is the one thing the operator watching it needs to
be able to see. The only clock involved is the CSS transition between two real
step counts. In the simulated path the pacing comes from the simulator walking
its nodes under `DEMO_LATENCY`, not from the console.

## Known gaps

- Agents 3 and 4 (Communication, Results) are not implemented.
- The AAP job templates the AO workflow calls — `CVE - Fetch and Commit` and
  `CVE - Sync and Deploy Remediation` — do not exist in AAP yet, so an approved
  run fails at `fetch_and_commit_prod` against a live AO. See
  `ao-setup/playbooks/`. The simulated path is unaffected.
- The risk model scores every host of a given CVE almost identically, because
  three of its four inputs describe the CVE rather than the host. Threshold
  tuning or retraining is needed before the score is useful as triage.
- A Llama Stack restart silently empties the vector store registry — searches
  return no hits with no error. Run `ingest.py --ensure` after any restart; see
  `rag-setup/README.md`.
- No scheduler service exists; the maintenance window is configuration.
