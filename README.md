# demojam-agentic-patching

Agentic CVE patching: a **Supervisor agent** orchestrating four specialist
agents per CVE, with a dark-themed console, an XGBoost risk model on OpenShift,
and a Milvus + Llama Stack RAG store.

Extracted from `agentic-ai-patching` — this repo holds the multi-agent work and
the console modules it needs to run.

## Architecture

![architecture](multi-agent/architecture.jpg)

```
Common code (not an agent)      CVE list + affected hosts from Insights
        │  for each CVE
        ▼
   Supervisor Agent             owns control flow + per-CVE state
        │                       attempts · phase_failures · tried_fixes
        ├─▶ 1 Info Agent        RAG history, scheduler, risk score, dry-run
        ├─▶ 2 Patching Agent    env gate, playbook, git, AAP, remediation
        ├─▶ 3 Communication     Slack + ServiceNow
        └─▶ 4 Results           training data + observability
```

The **self-healing loop** lives in the Supervisor because it spans three agents:
Patching reports a failure, Info diagnoses it from RAG history, Patching retries.
Bounded by `MAX_ATTEMPTS_PER_HOST=2`, `MAX_FAILED_PER_PHASE=2`, and a
`tried_fixes` set so the same fix is never attempted twice.

Three exits: **A** healed · **B** host abandoned, rollout continues ·
**C** phase aborted, nothing half-applied.

## Layout

```
src/local/
  agents/          supervisor, info, patching, communication, results
  a2a/             in-process message bus (bus.py, messages.py)
  intake.py        CVE list + detail — common code, not an agent
  cve_console.py   HTTP server, serves the UI, wires the Supervisor
  cve_flow.py      Insights / AAP / Llama Stack primitives
  cve_flow_demo.py try_real() real-or-fallback wrappers + demo data
frontend/
  index.html       console UI — pipeline bar, agent sidebar, stage cards
  server.py        standalone dev server (CVE list only)
multi-agent/
  architecture.jpg + .html   architecture diagram (editable source)
  rag-setup/                 Milvus + Llama Stack as plain Pods
risk_score/
  training/ serving/         XGBoost model
  openshift/                 Deployment + Service + Route
  Dockerfile                 no KServe, no RHOAI
```

## Run the console locally

```bash
cd src/local
export LIGHTSPEED_CLIENT_ID=... LIGHTSPEED_CLIENT_SECRET=...   # Insights
CVE_CONSOLE_CVE_LIST_SOURCE=rest \
RISK_URL="https://risk-score-<ns>.apps.<cluster>/v1/models/risk-score:predict" \
RISK_VERIFY_TLS=false \
LLAMA_STACK_URL=http://127.0.0.1:8321 \
VECTOR_DB_ID=vs_... \
DEFAULT_LLM_MODEL=vllm-inference/llama-scout-17b \
TARGET_ENV=prod \
python3 cve_console.py
```

Then open <http://127.0.0.1:8787>, click **Patch** on a CVE, approve at the gate.

### Useful switches

| Variable | Effect |
|---|---|
| `STRICT_MODE=true` | every fallback becomes a hard failure — shows which backends are really wired |
| `HOSTS_FILTER=pay-app-07` | restrict the run to matching hosts |
| `HOSTS_LIMIT=1` | cap host count (the risk model is called once per host) |
| `CVE_DETAIL_SOURCE=rest` | fetch CVE detail over REST instead of MCP |
| `AUTO_APPROVE_REMEDIATION=true` | let the self-heal loop apply its own fix without a second approval |

## Deploy the pieces

```bash
./risk_score/openshift/deploy-risk-score.sh    # XGBoost model
./multi-agent/rag-setup/deploy.sh              # Milvus + Llama Stack
./multi-agent/rag-setup/ingest.py --route https://<llamastack-route> --dir ./data
```

## Design notes

**Fallbacks are labelled, never silent.** Every degraded result carries
`source` and `degraded: true`, and the dry-run report names which inputs were
degraded *before* anyone approves. A fallback that works but tells nobody is a
bug — the original `risk_score()` silently substituted arithmetic for the model
and reported it as live.

**Degrade on reads, fail closed on writes.** Missing history or a heuristic
score is fine to proceed with. Approval, AAP project sync and rollback are not.

## Known gaps

- The risk model is called **once per host, sequentially** — a 59-host CVE takes
  ~15 minutes. The model accepts a batch; the client does not use it yet.
- `REASON` and `ROI` segments in the pipeline bar map to nothing in this
  architecture; they are leftovers from an earlier six-stage design.
- The pipeline bar tracks one run. With several in flight it follows the most
  recent and shows an amber `(+n more)` warning.
- Remediation approval has no UI path — in prod it needs
  `AUTO_APPROVE_REMEDIATION=true` or the heal ends at exit B.
- `etcd` in the RAG setup uses an `emptyDir`; a restart drops Milvus collection
  metadata.
