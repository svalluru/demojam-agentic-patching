#!/usr/bin/env bash
# Deploy Milvus + Llama Stack as plain Pods for the RAG vector store.
# No RHOAI operator, no LlamaStackDistribution CR.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="${NAMESPACE:-agentic-patching}"
ENV_FILE="${ENV_FILE:-${ROOT}/../../src/openshift/.env.openshift}"

step() { echo ""; echo "=== $* ==="; }
info() { echo "  $*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }

step "Preflight"
command -v oc >/dev/null 2>&1 || fail "oc not found on PATH"
oc whoami >/dev/null 2>&1 || fail "not logged in — run: oc login <api-url>"
info "cluster:   $(oc whoami --show-server)"
oc get namespace "$NAMESPACE" >/dev/null 2>&1 || fail "namespace '$NAMESPACE' not found"
info "namespace: $NAMESPACE"

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
oc create secret generic llamastack-inference-secret -n "$NAMESPACE" \
  --from-literal=INFERENCE_MODEL="${INFERENCE_MODEL:-llama-17b/llama-scout-17b}" \
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
echo "  Ingest:"
echo "    ./ingest.py --route https://${ROUTE} --vector-db patch_history --dir ./data"
