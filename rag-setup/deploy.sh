#!/usr/bin/env bash
# Deploy Milvus + Llama Stack as plain Pods for the RAG vector store.
# No RHOAI operator, no LlamaStackDistribution CR.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="${NAMESPACE:-agentic-patching}"
# The repo .env. This pointed at src/openshift/.env.openshift, a path from
# a layout that no longer exists — so it silently fell through to the
# placeholder branch and baked VLLM_URL=http://localhost:8000/v1 into the
# secret, which inside the pod means the pod itself.
ENV_FILE="${ENV_FILE:-${ROOT}/../.env}"

step() { echo ""; echo "=== $* ==="; }
info() { echo "  $*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }

step "Preflight"
. "$ROOT/../lib/ocp-check.sh"
ocp_check_cluster "$ENV_FILE" || fail "refusing to deploy — see above"
# Created if missing, skipped if present. Checked with 'oc get project'
# rather than 'oc get namespace': a user without cluster-scoped read can see
# their own projects but may not be allowed to read the namespace object,
# and would be told a project they own does not exist.
if oc get project "$NAMESPACE" >/dev/null 2>&1; then
  info "namespace: $NAMESPACE (exists)"
else
  oc new-project "$NAMESPACE" --skip-config-write >/dev/null 2>&1 \
    || oc create namespace "$NAMESPACE" >/dev/null \
    || fail "could not create namespace '$NAMESPACE'"
  info "namespace: $NAMESPACE (created)"
fi

step "Secrets"
# Milvus root password — only consumed when Milvus auth is enabled, but the
# Deployment references it, so it must exist.
oc create secret generic milvus-secret -n "$NAMESPACE" \
  --from-literal=root-password="${MILVUS_ROOT_PASSWORD:-milvus}" \
  --dry-run=client -o yaml | oc apply -f - >/dev/null
info "milvus-secret applied"

# Inference endpoint for the LLM. Embeddings run in-process and do not need it,
# so RAG ingest still works with a placeholder here.
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a; source "$ENV_FILE"; set +a
  info "loaded inference settings from $ENV_FILE"
else
  info "no env file at $ENV_FILE — using placeholders"
fi
# run.yaml registers the LLM as summary-<served name> (why: see run.yaml).
# The served name is the part after any prefix, so the older
# "llama-17b/llama-scout-17b" form still works.
INFERENCE_MODEL="${INFERENCE_MODEL:-deepseek-r1-distill-qwen-14b}"
LLM_MODEL_ID="${INFERENCE_MODEL##*/}"
LLM_MODEL_ALIAS="summary-$LLM_MODEL_ID"
info "LLM model: $LLM_MODEL_ID, registered as vllm-inference/$LLM_MODEL_ALIAS"
if [[ -n "${DEFAULT_LLM_MODEL:-}" && "$DEFAULT_LLM_MODEL" != "vllm-inference/$LLM_MODEL_ALIAS" ]]; then
  info "WARNING: .env has DEFAULT_LLM_MODEL=$DEFAULT_LLM_MODEL — the console needs vllm-inference/$LLM_MODEL_ALIAS"
fi
oc create secret generic llamastack-inference-secret -n "$NAMESPACE" \
  --from-literal=INFERENCE_MODEL="$INFERENCE_MODEL" \
  --from-literal=LLM_MODEL_ID="$LLM_MODEL_ID" \
  --from-literal=LLM_MODEL_ALIAS="$LLM_MODEL_ALIAS" \
  --from-literal=VLLM_URL="${VLLM_URL:-http://localhost:8000/v1}" \
  --from-literal=VLLM_API_TOKEN="${VLLM_API_TOKEN:-fake}" \
  --from-literal=VLLM_TLS_VERIFY="${VLLM_TLS_VERIFY:-false}" \
  --dry-run=client -o yaml | oc apply -f - >/dev/null
info "llamastack-inference-secret applied"

step "Apply manifests"
oc apply -k "$ROOT" -n "$NAMESPACE"

step "Wait for etcd"
oc rollout status deployment/etcd-deployment -n "$NAMESPACE" --timeout=180s

step "Wait for Milvus"
oc rollout status deployment/milvus-standalone -n "$NAMESPACE" --timeout=420s

step "Wait for Llama Stack"
# First start downloads the embedding model, so allow plenty of time.
if ! oc rollout status deployment/llamastack -n "$NAMESPACE" --timeout=900s; then
  echo "" >&2
  echo "Llama Stack did not become ready. Recent logs:" >&2
  oc logs -n "$NAMESPACE" -l app=llamastack --tail=60 >&2 || true
  fail "llamastack rollout failed"
fi

step "Done"
ROUTE="$(oc get route llamastack -n "$NAMESPACE" -o jsonpath='{.spec.host}' 2>/dev/null || true)"
echo "  Milvus (in-cluster) : milvus-service:19530"
echo "  Llama Stack (in-cl) : llamastack:8321"
[[ -n "$ROUTE" ]] && echo "  Llama Stack (route) : https://${ROUTE}"
echo ""
echo "  Verify:"
echo "    curl -sk https://${ROUTE}/v1/health"
echo "    curl -sk https://${ROUTE}/v1/models | head -c 400"
echo ""
echo "  Ingest — run from the repo root, not from here:"
echo "    ./rag-setup/ingest.py --route https://${ROUTE} \\"
echo "        --name patch_history --dir ./rag-setup/data --ensure"
echo ""
echo "  It prints a vs_... id. That is VECTOR_DB_ID for .env."
echo "  Re-run the same line after any Llama Stack restart: the store is"
echo "  still listed but empty, and searches return nothing with no error."
