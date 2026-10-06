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
./ingest.py --route https://$ROUTE --vector-db patch_history --dir ./data
./ingest.py --route https://$ROUTE --vector-db patch_history --file notes.md
./ingest.py --route https://$ROUTE --vector-db patch_history --query "drain timeout"
```

`ingest.py` registers the vector DB if absent, chunks on paragraph boundaries
(~1200 chars), and inserts via `/v1/vector-io/insert`. Standard library only.

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
- `etcd` uses an `emptyDir` — it holds Milvus metadata that is rebuilt from the
  Milvus PVC, but a restart will drop collection metadata. Switch it to a PVC if
  you need the store to survive node moves.
- The Route carries `haproxy.router.openshift.io/timeout: 300s`; embedding a
  large batch can exceed the 30s default.
- The pod needs egress to HuggingFace on first start. Air-gapped clusters should
  pre-seed the `llamastack-hf-cache` PVC.
