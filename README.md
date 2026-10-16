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
        ├─▶ 3 Communication Agent     PDF status report (Slack/SNOW pending)
        └─▶ 4 Results Agent           RAG record + risk-model training row
```

### Status

| Agent | State |
|---|---|
| Common code (CVE list / detail) | done — Insights REST |
| 1 cve-gather-info-agent | done — RAG, risk model, patch plan |
| 2 Patching Agent | done — triggers AO workflow per host, approve/reject |
| 3 Communication Agent | done as scoped — PDF status report (Slack/SNOW deferred) |
| 4 Results Agent | done — writes RAG records and risk-model training rows |

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
communication.py           agent 3 — renders the patch status report
results.py                 agent 4 — feeds outcomes back to RAG + training data
pdf.py                     minimal stdlib PDF writer (no reportlab)
frontend/
  index.html               two-frame console: assess a CVE · CVE list · patch runs
  server.py                dev server — serves the UI, proxies /api/* to :8787
ao-setup/
  create-ao-objects.sh     creates AO credentials + integrations from .env
  agentic_patching_workflow.json  the AO workflow, exported from AO
aap-setup/
  create-aap-objects.sh    AAP projects, credentials and job templates
  create-ao-workflow.sh    creates + publishes a one-node test workflow
  run-test.sh              launch one job template and show its artifacts
  playbooks/               fetch-and-commit · sync-and-deploy · verify
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

Fill in credentials in `.env`, which is gitignored. `./demo.sh --live` creates
it from `.env.example` if it is missing and starts regardless — an empty one
just means every step falls back, which the console labels. To make it
yourself:

```bash
cp .env.example .env     # then edit
```

Deploy the backing services (each is independent):

```bash
./rag-setup/deploy.sh                          # Milvus + Llama Stack
./rag-setup/ingest.py --route https://$ROUTE --dir ./rag-setup/data --ensure
./risk_score/openshift/deploy-risk-score.sh    # XGBoost model
./ao-setup/create-ao-objects.sh                # AO credentials + integrations
./aap-setup/create-aap-objects.sh              # AAP projects, credentials, job templates
```

Live mode additionally needs a **target host**, and the requirement is
stricter than it looks: one machine registered in the same Insights
organisation as your `LIGHTSPEED_*` credentials *and* reachable over SSH from
AAP. Most hosts satisfy one or the other — the console cannot assess what it
cannot see, and cannot patch what AAP cannot reach. See
[docs/EC2_TARGET_HOST.md](docs/EC2_TARGET_HOST.md) for building one from
scratch, including Insights registration and the AAP wiring.

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
plan, then dispatch it. **Find a CVE…** in the list header searches by id or
description — server-side, because a live estate runs to thousands of CVEs
over hundreds of pages and filtering the twenty on screen would report
"nothing found" for almost all of them. Results are cached per query, so
clearing the box or going back to an earlier search costs nothing. The dispatch button is labelled from the plan's
verdict — *Patch N hosts* in red when the press really does patch them
unattended, *Send N for approval* in black when every host will halt at the
gate instead. Hosts routed to the approval branch show Approve / Reject
buttons, and once approved the row tracks its execution through the remaining
workflow nodes to *Patched*. **Calculate ROI** costs that run out against doing
the same work by hand. **Patch runs** lists past executions read live from AO.

### The left panel

The right frame moves between the plan, the run history and the ROI report. The
left one stays, so it carries what you need regardless of which of those is up:

| | |
|---|---|
| **State chip** | One word beside the heading — *Assessing*, *Needs review*, *5 at the gate*, *Patching*, *Complete*, *Failed*. The stage bar in the header says the same thing in more detail; this has to make sense on its own once the right frame has moved on. |
| **Agent architecture** | The diagram above — who is in the system, and which of them have talked to which so far in this run. |
| **Agent trace** | Every supervisor↔agent hop, numbered, with elapsed seconds off the events' own clock. |

The diagram is the same shape as the one at the top of this file, drawn live. A
box that has been called in this run goes black; the rest stay grey, so the
picture starts as the whole system and fills in with the part of it this CVE
actually used. Agents 3 and 4 are dashed and stay dashed — they are not
implemented, and leaving them off would make the diagram claim a system that is
smaller than the design. While a run is moving, the most recent hop is drawn
solid with the dashes flowing from caller to callee and a pulse on both boxes,
which is the only place the console shows direction *as it happens* rather than
after the fact.

**Every lit edge is a logged hop.** The diagram reads `state.events` — the same
list the trace below it prints — so the console cannot draw a conversation that
did not take place. There is exactly one derived edge, Patching → Ansible
Orchestrator, lit from the patch result existing, because AO is the only
backing service the Supervisor does not trace a hop to.

**Red needs `LABEL_SOURCES=1`.** A service that fell back to `fallbacks.py`
turns red in the diagram, matching the `degraded` panel on the plan — but only
with source labelling on, which it is not by default. See *What the page shows
about its sources* below. The node still turns black the moment something calls
it either way, so the picture animates identically whether the call was
answered or substituted.

The plan carries `history_source` (`rag` / `fallback` / `skipped`) as a field
for the same reason. A step that was never reached — no host needed review, so
the RAG store was never queried — leaves no `degraded` entry, which makes it
indistinguishable from one that succeeded unless the plan says so outright.

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
| `AO_WORKFLOW_NAME` | workflow to trigger (default `DemoJam Agentic Patching`) |
| `AO_DECIDE_WAIT=90` | seconds to wait for a run to settle after approve/reject |
| `LAB_TAG` | passed to the workflow as `lab_tag` |
| `INSIGHTS_VERIFY_TLS=false` | if this machine cannot verify the sso.redhat.com chain |
| `RISK_VERIFY_TLS=false` | for sandbox cluster certificates |
| `INSIGHTS_TIMEOUT` / `RISK_TIMEOUT` / `RAG_TIMEOUT` / `AO_TIMEOUT` | per-service read budgets (15 / 8 / 20 / 10s) |

See **Modes** below for what `MODE` changes, and
**ROI** for the `ROI_*` baseline.

### Settings panel

The gear in the top right opens every one of these, grouped, with its built-in
default shown until something overrides it. A row is chipped `.env` when it was
set before startup and `changed` when this panel set it.

Changes take effect on the next assessment and are **in-memory only** — they
are lost on restart, and `.env` stays the durable place. The two passwords are
write-only: the panel never reads them back, and leaving one blank keeps the
current value. `BACKEND_HOST` / `BACKEND_PORT` are shown but not editable; the
socket is already open by the time the panel can reach the process.

### Text size

The one row in that panel that is not a process setting. **Display → Text size**
offers Small, Medium (the default) and Large, and it belongs to the browser: it
goes nowhere near `/api/settings`, survives a restart of the backend, and
changes nothing for anyone else looking at the same console. Small is exactly
what the console was before the control existed.

It works by one custom property. Every `font-size` on the page is written
`calc(Npx * var(--ts))`, and `--ts` is `1` / `1.1` / `1.24`, so the whole type
scale moves together and keeps its proportions. Padding and borders deliberately
do not scale — at Large the text grows into whitespace that was already there,
which is what somebody asking for bigger text is asking for.

Two sets of labels opt out: the architecture diagram's node text and the ROI
chart's axis and bar labels. Those are drawn inside an SVG `viewBox`, where a
px is a share of the drawing rather than a size on screen — scaling them pushes
the text out of boxes that stayed the same width. `ANSIBLE ORCH` overflows its
node at Large; the diagram already grows with the panel it sits in.

The choice is applied by a small script in `<head>`, before first paint, rather
than from the main script at the bottom — otherwise the console renders at
medium and visibly jumps. It is stored in `localStorage` under
`ap-text-size`, and a privacy mode that refuses to store it falls back to the
default rather than failing.

### Demo guide

The book icon beside the gear opens the run of show: a seven-beat script with
the thing to click and the line to say kept apart, the questions that actually
get asked with answers to them, and a **Do not say** list of the claims this
repo cannot back — the ROI figures as a measured saving, the risk score as
host-level triage, agents 3 and 4 as imminent.

It is static markup rather than a fetch, because it has to still be readable
when every backend is down and nobody opening it thirty seconds before walking
into a room should be waiting on the network. The one live part is the note at
the top, which names the mode the console is actually in: the script is written
for the offline demo, so opened in live mode it says so rather than letting a
presenter claim the wrong one. A backend it cannot reach reads as *unknown*,
never as live.

## Modes

One setting, `MODE`, and deliberately nothing between its two ends:

| | |
|---|---|
| **demo** (default) | Every step runs on staged data and no endpoint is contacted. The whole flow can be shown without Insights, the risk model, the RAG store or Ansible Orchestrator. Nothing is patched. |
| **live** | Real endpoints only, with no fallback at any step. An unreachable service fails the run and names itself. |

There is no third mode mixing real endpoints with stored defaults. That
combination produces the one artefact an operator must not be handed: a patch
plan that looks measured but is partly fabricated.

All staged data lives in one file, [`fallbacks.py`](fallbacks.py).

| Step | Backend | Fallback |
|---|---|---|
| C1 CVE list | Insights | 2 real CVEs with real CVSS |
| C2 affected hosts | Insights | 5 hosts for CVE-2024-3094, 2 for CVE-2024-1086 |
| 1 patch history | Llama Stack / Milvus | canned per-host summaries |
| 3 risk score | XGBoost on OpenShift | heuristic; gated at 55 rather than the model's 30, since the two are not on the same scale — both live in `fallbacks.py` |
| 5–10 remediation | Ansible Orchestrator | simulated run, local to this console |

The two CVEs route differently on purpose: CVE-2024-3094 at CVSS 10.0 sends all
five hosts to the approval gate, CVE-2024-1086 at 7.8 auto-patches both of its
two. One demo covers each branch.

**Nothing is ever actually patched by the fallback.** A simulated run pauses at
the approval gate and resolves to `patched` or `rejected` locally, so the
approval path stays demonstrable, but no host is touched and the execution
exists in no AO instance.

### What the page shows about its sources

**By default the page says nothing.** Every value renders the same whether it
was measured or stood in for: no demo banner, no `degraded` panel, no
`SIMULATED` chips, no red nodes in the diagram, no `(heuristic)` beside a risk
score. That is a demo decision. A banner reading *running on fallback data* is
the thing a room fixates on, and a demo that half-fails mid-flow should not
announce it from the screen.

**Nothing is suppressed, only moved.** Three channels carry it regardless of
the setting:

- **The backend log** — `degrade()` prints every substitution to
  `/tmp/demo-backend.log` with the step, the service, the reason and the fix,
  the first time each one happens. It prints whether or not the page is going
  to show it; a record that depends on a display setting is not a record.
- **The agent trace**, left-hand panel, on screen while the run is: `risk-model
  : unreachable — heuristic for 2 host(s)`, `rag : unreachable — stored history
  for <host>`, `<host>: SIMULATED patched — AO unreachable`.
- **The API** — `degraded` on the plan, `source` / `risk_source` /
  `history_source` on the values, `simulated: true` on affected runs,
  `illustrative` on the ROI report. These are untouched by the setting.

**`LABEL_SOURCES=1` puts the marks back on the page**, and anyone pointing this
at real infrastructure wants that: the patch plan is what a human approves
against, and unlabelled a fabricated risk score looks exactly like a measured
one. It restores the offline banner, the `degraded` panel naming step, service
and fix, the `SIMULATED` row chips, the red diagram nodes, the *Risk source*
tile, the ROI caveat, and the per-step plan notes. It is also a toggle in the
gear panel, taking effect on the next render.

Two things stay visible either way, because neither is a source label. Live mode
keeps its banner: it means the opposite — no fallback will be used and an
unreachable service fails the run outright, which someone needs to know before
they start. And the risk gate number itself is always shown, because the score
and the threshold it was judged against are real properties of the run; only
the `(heuristic)` that names where the score came from is hidden.

| Variable | Effect |
|---|---|
| `MODE=demo` | the default, and what `./demo.sh` sets — staged data for every step, no endpoint contacted |
| `MODE=live` | what `./demo.sh --live` sets — real endpoints only, no fallback anywhere |
| `LABEL_SOURCES=1` | in demo mode, mark staged values on the page rather than only in the banner |
| `CONNECT_TIMEOUT=3` | reachability budget per service |
| `CIRCUIT_TTL=30` | how long a service stays tripped after failing |
| `DEMO_LATENCY=0.35` | offline-only pause per agent step; `0` disables |
| `PATCHED_WITHIN_MINUTES=10080` | how recently a host must have been patched for this CVE to be left out of a re-assessment. 10080 is seven days; `0` turns the guard off, which is what lets you run the same demo CVE twice |

Simulated runs persist to `runs/simulated.json` so the Patch runs page survives
a restart. Real runs need no such thing — AO is their store. Delete the file to
reset the demo.

## ROI

**Calculate ROI** on the remediation view (`GET /api/roi`) compares the run that
is on screen against doing the same work by hand. Two kinds of number meet
there and the page keeps them apart, because they carry very different
warranties:


- **Measured** — host count, how many stopped at the gate, how long the
  assessment took, how long each execution ran. This run's own clock — but a
  clock only measures patching if something was patched. Offline it is
  `DEMO_LATENCY` rather than work; live with Ansible Orchestrator unreachable
  it is real wall time spent failing over, and `measured.simulated` counts the
  hosts nothing touched. Either way the report sets `illustrative` and
  `illustrative_reason` says which of the two (`offline` or `simulated`). Both
  fields are in the response always; the page leads with a banner naming the
  cause only under `LABEL_SOURCES=1`.
- **Assumed** — the manual baseline, every bit of it. None of it is measurable
  from here: the manual run never happened, so there is no clock to read it
  off. It lives in `fallbacks.py` with the rest of the fabricated data, is
  itemised in the response, and is listed on the page with the setting key
  beside each figure.

The comparison counts the operator's review time **against** the automated
side. An approval gate is not free, and a chart that treats it as free is a
sales slide. Machine time is not priced at all: an engineer-hour and a
container-second do not convert, and the compute would be a rounding error
against the labour either way.

Time-to-remediation is reported as two durations rather than a ratio, and it is
withheld entirely until a host actually reaches *Patched* — quoting the
dispatch time instead would drop the wait at the approval gate, which is most
of the figure. That wait counts: it is not automation working, but the host is
exploitable throughout it.

### What the page shows

| Card | What it answers |
|---|---|
| **Assumptions** | A slider per assumption. Move one and everything below recomputes. |
| Headline | Labour saved, engineer time saved, the effort ratio, how many hosts needed a person. |
| Where the effort goes | Both paths broken down by activity, on one scale. |
| How it scales | The same CVE across more hosts, at this run's approval rate. |
| How wrong could this be | Break-even: how far the assumptions have to move before the conclusion flips. |
| Time to remediation | Exposure window, measured, stated against the policy deadline. |
| What this is up against | The remediation clock to scale, and the day-7 ceiling as a hundred dots. The one inverted card on the page — nothing on it is ours. |
| Measured, not modelled | The rest of the published record, each figure chipped with who measured it, plus the sliders scored against it. |
| How the industry sees this | Where supervised agentic remediation sits, including the case against it. Numbered sources. |
| Across every run so far | The same arithmetic over the whole run store, not just this CVE. |
| Paying for itself | Hosts to cover `ROI_PLATFORM_COST`, and how much is recovered. |

**The sliders are the argument, not a disclaimer.** `POST /api/roi` with
`{"overrides": {"ROI_PREP_MIN": 3}}` returns the whole report recomputed
against those values; the GET form uses the stored ones. Overrides are clamped
to a sane range, applied per request, and **never written anywhere** — the
server is threaded and one person asking "what if" must not change the page
anyone else is looking at. The arithmetic lives only on the server, so there is
one implementation of it rather than a second copy in the browser drifting from
the first.

**Published figures are the outside check.** Everything else on the page is
this run's clock and this reader's sliders, which is a closed loop: the page
sets the baseline and then scores itself against it. `ROI_SOURCES`,
`ROI_BENCHMARKS` and `ROI_STANCE` in `agentic-patching.py` hold eight measured
figures and three analyst positions, each carrying a publisher, a title, a year
and the basis of the measurement, rendered as numbered citations. Two of the
eight carry a `feature` key, which lifts them out of the grid and into a
drawing of their own — the remediation clock and the day-7 dot matrix. Moving
the emphasis is a one-word edit in that tuple; the frontend filters on the key
rather than hard-coding which two are special. They are
static by necessity — the console makes no network calls at runtime — which
makes the year on each entry load-bearing. **Re-check them when a report's next
edition lands.**

Two of them are wired to the sliders rather than merely printed. The manual
baseline is scored against the Verizon DBIR's published median time to
remediate a known-exploited vulnerability, in whichever direction it lands:
at the default 72 hours the page says out loud that it is crediting the manual
path with being 14.3× faster than the industry manages, and therefore
understating its own saving. The deadline slider is scored against CISA BOD
26-04's tiers. Both sliders now reach far enough to be set to the published
numbers — a slider that cannot reach the figure the card beneath it cites is an
invitation to argue that goes nowhere.

Nothing multiplies a breach cost by a probability and books the result as a
saving. IBM's $4.99M average is on the page for scale and is in no total.

**Break-even is stated instead of a confidence claim.** The page says how much
smaller the manual baseline would have to be, and what per-host handling time
would make doing it by hand cheaper, so the reader can check those against
their own experience rather than take the total on faith. The hourly rate is
excluded from that deliberately: it multiplies both sides equally, so it moves
the money and never the verdict.

**A range, not a point.** `ROI_BAND_PCT` puts a band either side of the manual
baseline and the saving is quoted as a span. Seven stacked guesses quoted to
the cent is making a promise it cannot keep.

**Serial time and wall clock are separated.** Hosts patch concurrently, so the
page reports machine time summed across hosts *and* the wall clock the run
actually took. By hand they queue; that difference is part of the saving and
pretending otherwise understates it.

**Exposure is measured against policy, not converted into money.** The run is
checked against `ROI_SLA_HOURS` and reported as inside or outside the deadline.
Pricing an exposure window needs a breach probability and a breach cost
multiplied together, both unknowable — that would put the biggest number on the
page on the weakest footing of anything in the repo.

**The lifetime card is deliberately conservative.** Only runs that reached
`patched` count toward the saving. Runs still waiting, still running, failed,
rejected or never dispatched are counted separately and shown as the
difference, so the gap between "runs in the store" and "runs counted" is always
visible. Triage counts once per distinct CVE rather than once per dispatch,
which undercounts a CVE patched in two waves — in the same direction as
everything else here. Under-reporting a saving is recoverable; over-reporting
one is not.

| Variable | Default | Manual baseline |
|---|---|---|
| `ROI_TRIAGE_MIN` | 45 | read the advisory and scope it — once per CVE |
| `ROI_PREP_MIN` | 15 | per host: adapt the playbook, raise the change, book the window |
| `ROI_EXEC_MIN` | 10 | per host: run it, watch it, confirm the service came back |
| `ROI_APPROVAL_MIN` | 20 | per gated host: assemble the request, chase the approver |
| `ROI_REWORK_PCT` | 12 | share of hosts done twice by hand — the patch does not take and the window is lost |
| `ROI_REVIEW_MIN` | 2 | per gated host, charged to the **automated** side: read the plan, press Approve |
| `ROI_HOURLY_RATE` | 85 | fully loaded, not salary |
| `ROI_CURRENCY` | `$` | display only, no conversion |
| `ROI_LEAD_HOURS` | 72 | elapsed hours to remediation by hand — wall clock, mostly queueing |
| `ROI_SLA_HOURS` | 48 | the remediation deadline to report exposure against — policy, not physics |
| `ROI_BAND_PCT` | 30 | how wrong the manual baseline might be, either way |
| `ROI_PLATFORM_COST` | 25000 | one-off build cost for the payback card; set `0` to drop the card |

Rework is applied to the manual side only, and that asymmetry is deliberate
rather than generous: an automated run that fails never reaches `patched`, so
the lifetime total drops it entirely. The manual equivalent leaves no such
record, which is why it has to be estimated. `ROI_PLATFORM_COST` is the weakest
number on the page and is labelled as such — nothing in this repo can source
it, but refusing to answer is not neutral, since whoever holds the budget will
assume a figure and the one they assume is usually worse.

The defaults are deliberately unflattering to the automation; a baseline that
assumes four unattended hours per host produces a wonderful number and
convinces nobody. Every one of them is both a slider on the page and a row in
the settings panel — the slider to argue with it now, the panel to make it
stick. The report is computed on demand rather than stored on the run, so it
always reflects the assumptions as they are now.

## The learning loop (agent 4)

After a run settles, agent 4 writes to two places:

```
rag-setup/data/runs/<date>-<cve>-<host>-<result>-<time>.md   searchable history
risk_score/training/observed/outcomes.csv                    one row per host
```

Feed them back:

```bash
# RAG — the new records sit under data/, so the usual ingest picks them up
./rag-setup/ingest.py --route $LLAMA_STACK_URL --dir ./rag-setup/data --ensure

# risk model — merge observed outcomes with the synthetic baseline, then train
./risk_score/training/build_dataset.py        # writes training/data.csv
cd risk_score/training && python save_model.py
```

**Simulated runs are excluded from training by default.** In offline mode every
run is simulated, so without that a few demo runs would silently become ground
truth. They are still written, marked `simulated=true`, and
`build_dataset.py --include-simulated` lets them through for pipeline testing.

**The label comes from the outcome, never from the prediction.** Writing the
model's own score back as truth is self-training — it would only ever confirm
itself. `OBSERVED_RISK` in `results.py` is the mapping, deliberately crude and
in one place so it is easy to argue with.

Generated records go in `data/runs/` rather than beside the ten curated
records, which are authored and reviewed; `ingest.py` recurses, so both are
picked up.

**Re-assessing a CVE skips hosts already patched for it.** Within
`PATCHED_WITHIN_MINUTES` they are dropped before agent 1 runs, so scoring, RAG
lookups and operator review go to outstanding work only — and they are listed
in the plan, because quietly showing fewer hosts than the CVE affects is
indistinguishable from missing some. Only runs provable to have reached
`patched` count: the execution list cannot tell an approved run from a
rejected one, so anything ambiguous is resolved with `run_detail` first.
Hiding a host that was never patched is worse than patching one twice.

## Design notes

**Fail fast on reachability, be patient on answers.** Every call TCP-connects
first with a short budget, because a stopped pod leaves its Route resolving
with nothing behind it and the socket hangs for the full read timeout. A
service that fails is then tripped for `CIRCUIT_TTL`, so a dead backend costs
one probe per run rather than one per host. Together these took a patch plan
against stopped backends from 76s to under 7s; demo mode skips the probe
entirely and opens no socket at all.

**Degrade on reads, fail closed on writes.** A missing risk score can be
estimated; a patch cannot be assumed. That asymmetry is why demo mode
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

## Deliberately deferred

These differ from `multi-agent/architecture.jpg` by decision, not by oversight.
Listed so they are not re-raised as bugs.

| Diagram | Decision |
|---|---|
| 11 Slack · 12 ServiceNow | The PDF report **is** the implementation for now. Agent 3 renders the summary those channels would carry; nothing is sent. When a channel is wanted, it should format *that* summary rather than build its own, so the three cannot drift apart. |
| 14 Observability store | Skipped. Stays on the diagram for the architecture story; not planned as code. |
| Self-healing loop | Later. The guards (`MAX_ATTEMPTS_PER_HOST`, `MAX_FAILED_PER_PHASE`, `tried_fixes`) are declared on the Supervisor but **not enforced** — see below. |
| C2 via Insights MCP | Later. Currently the Insights REST API, which returns the same hosts. |
| 13 fallback: JSONL to PVC | Later. Currently CSV on local disk. |

## Known gaps

- **The self-healing loop is not implemented.** `Supervisor.reset()` declares
  `attempts`, `tried_fixes` and `phase_failures`, and nothing reads or writes
  them — `patch()` counts failures but never stops early. So EXIT A/B/C,
  `diagnose()`, the post-patch health check, rollback, and phased
  test→canary→prod are all absent. Deferred deliberately; the dead state is
  left in place as the shape to build into.
- Agent 4's training label is a judgement call, not a measurement. The model
  predicts a risk score; a patch produces success or failure. `OBSERVED_RISK`
  in `results.py` maps one to the other, and those numbers want tuning against
  real runs before anyone retrains on them. The one thing it never does is
  write the model's own prediction back as the label.
- The risk model scores every host of a given CVE almost identically, because
  three of its four inputs describe the CVE rather than the host. Threshold
  tuning or retraining is needed before the score is useful as triage.
- **The model's observed output range is 36.6–100, and `REVIEW_THRESHOLD`
  defaults to 30.** Nothing it emits falls below the gate, so every host
  routes to approval and the auto-patch branch is unreachable. Set the
  threshold to where this model's scores actually separate — 65 split a real
  host cleanly, CVSS ≤4 scoring ~57 and CVSS 8+ scoring ~92. That is a
  calibration against this distribution, not a measurement.
- Live mode needs a host registered in the **same Insights organisation** as
  the console's credentials *and* reachable over SSH from AAP. Most hosts
  satisfy one or the other; see [docs/EC2_TARGET_HOST.md](docs/EC2_TARGET_HOST.md).
- `CVE - Verify Patch` is created by hand rather than by
  `aap-setup/create-aap-objects.sh`.
- A Llama Stack restart silently empties the vector store registry — searches
  return no hits with no error. Run `ingest.py --ensure` after any restart; see
  `rag-setup/README.md`.
- No scheduler service exists; the maintenance window is configuration.
