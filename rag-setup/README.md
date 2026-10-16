# RAG setup — Milvus + Llama Stack as plain Pods

Vector store for the agentic patching RAG, deployed as ordinary Deployments.
**No RHOAI operator, no `LlamaStackDistribution` CR** — just Pods, Services, PVCs
and a Route.

```
                    ┌──────────────────────────────────────┐
  ingest.py  ──────▶│  Route: llamastack  (edge TLS)       │
  (outside)         └──────────────────┬───────────────────┘
                                       │ :8321
                    ┌──────────────────▼───────────────────┐
                    │  llamastack  (quay.io/opendatahub/   │
                    │               llama-stack:odh)       │
                    │  • remote::vllm      → LLM           │
                    │  • sentence-transf.  → embeddings    │
                    │  • remote::milvus    ──────────┐     │
                    └────────────────────────────────┼─────┘
                                                     │ :19530
                    ┌────────────────────────────────▼─────┐
                    │  milvus-standalone  ──▶ etcd-service │
                    │  (local storage, PVC)                │
                    └──────────────────────────────────────┘
```

## Deploy

```bash
oc login <api-url>
cd multi-agent/rag-setup
./deploy.sh
```

Reads inference settings from `src/openshift/.env.openshift` if present. The
namespace defaults to `agentic-patching`; override with `NAMESPACE=... ./deploy.sh`.

First start downloads the `ibm-granite/granite-embedding-125m-english` embedding
model (~500 MB) into a PVC, so allow several minutes. Subsequent restarts reuse
the cache.

## Verify

```bash
ROUTE=$(oc get route llamastack -n agentic-patching -o jsonpath='{.spec.host}')
curl -sk https://$ROUTE/v1/health
curl -sk https://$ROUTE/v1/models
```

## Ingest

```bash
cd rag-setup      # the paths below are relative to this directory
./ingest.py --route https://$ROUTE --name patch_history --dir ./data --ensure
./ingest.py --route https://$ROUTE --name patch_history --file notes.md
./ingest.py --route https://$ROUTE --name patch_history --query "drain timeout"
./ingest.py --route https://$ROUTE --list
```

`ingest.py` creates the vector store if absent, uploads each file to
`/v1/files`, attaches it to the store, and searches via
`/v1/vector_stores/{id}/search`. The embedding model is discovered from
`/v1/models` rather than hardcoded. Standard library only.

## etcd holds the catalogue, and it used to be on an emptyDir

Milvus keeps vectors on `milvus-pvc`, but its *metadata* — which collections
exist, their schemas, where their segments live — lives in etcd. etcd was
deployed on an `emptyDir`, so every restart threw the catalogue away and left
20Gi of vectors that nothing knew about.

The symptom is the same silent one described below, which is why it took so
long to find: the store lists with its files and search returns nothing. It
cost three full re-ingests in one day across twelve restarts before anyone
checked where etcd kept its data.

`etcd-pvc.yaml` fixes it, and etcd now carries resource requests so the
kubelet stops evicting it first under node pressure. Verified by restarting
etcd and Milvus together — the sequence that used to wipe it — and getting
the same three hits before and after.

## After a Llama Stack restart — run `--ensure`

Separate problem from the etcd one above, and not fixed by it: here it is
Llama Stack's own registry that goes stale, not Milvus's catalogue.

**A restart silently breaks search.** Llama Stack 0.7.1 does not rehydrate its
vector-store registry on startup: the store keeps appearing in
`/v1/vector_stores` (that reads the kvstore, which does persist) and Milvus
still holds every row, but `search` reports the store missing and returns an
**empty result set rather than an error**. Nothing looks broken — you just get
no hits.

`--ensure` detects exactly that and rebuilds. It is idempotent, so it is safe
to run on every deploy or before a demo:

```
# healthy — no-op
  "patch_history" healthy -> vs_07db7af6-... (10 files)

# broken after a restart
  "patch_history" present but NOT searchable (10 files) — rebuilding vs_e2f2a011-...
    delete -> HTTP 200
  created vector store "patch_history" -> vs_07db7af6-...
  ...
  searchable after rebuild: True
```

**The store id changes when it rebuilds**, so re-read `VECTOR_DB_ID` from the
output and update whatever consumes it.

The liveness probe is deliberately slack (`periodSeconds: 60`,
`failureThreshold: 10` — ten minutes unresponsive before a kill) to make
restarts rare. `/v1/health` shares the event loop with embedding work and can
stall for minutes under load; the pod was previously killed with exit 137
while using only 689 MB of an 8 GB limit, so it was the probe, not memory.

## Point the console at it

```bash
oc set env deployment/cve-console -n agentic-patching \
  LLAMA_STACK_URL=http://llamastack:8321 \
  VECTOR_DB_ID=patch_history
```

Running the console locally instead:

```bash
oc port-forward svc/llamastack 8321:8321 -n agentic-patching
# then: LLAMA_STACK_URL=http://127.0.0.1:8321 VECTOR_DB_ID=patch_history
```

That clears the `history` entry from the Info agent's `degraded_inputs`.

## What differs from `src/openshift/llamastack/`

| | `src/openshift/llamastack/` | here |
|---|---|---|
| Deployment | `LlamaStackDistribution` CR (operator) | plain `Deployment` |
| Image | operator resolves `rh-dev` | `quay.io/opendatahub/llama-stack:odh` (0.2.10) |
| Metadata store | PostgreSQL | SQLite on a PVC |
| Vector store | `remote::milvus` | `remote::milvus` (same) |
| External access | none | Route |

`run.yaml` is adapted from the config shipped inside the image. Two changes:
`vector_io` switched from `inline::milvus` (embedded file store) to
`remote::milvus` (the Milvus pod), and the providers whose backends we do not
run — trustyai safety, trustyai eval, huggingface datasetio, braintrust
scoring — are removed along with their `apis` entries, so startup cannot fail
on a service that was never deployed.

## Files

```
deploy.sh              preflight → secrets → apply → wait
ingest.py              register vector DB, chunk, insert, query
kustomization.yaml     ties milvus/ and llamastack/ together
milvus/                etcd + Milvus standalone + PVC + Services
llamastack/            run.yaml → ConfigMap, Deployment, Service, Route, PVCs
```

## Notes

- Milvus runs `COMMON_STORAGETYPE=local`, so no MinIO/S3 is needed.
- `etcd` is on its own PVC (`etcd-pvc.yaml`). It holds Milvus's catalogue, and
  it is not rebuilt from the Milvus PVC — see the section above for what
  happened when it was on an `emptyDir`.
- The Route carries `haproxy.router.openshift.io/timeout: 300s`; embedding a
  large batch can exceed the 30s default.
- The pod needs egress to HuggingFace on first start. Air-gapped clusters should
  pre-seed the `llamastack-hf-cache` PVC.
