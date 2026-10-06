#!/usr/bin/env bash
# Deploy the XGBoost risk-score model to OpenShift as a plain application.
# Automates Part B of risk_score/XGBOOST_OPENSHIFT_AI_SERVING.md — no RHOAI,
# no KServe: a binary build plus Deployment, Service and Route.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # risk_score/
REPO_ROOT="$(cd "${ROOT}/.." && pwd)"
NAMESPACE="${NAMESPACE:-agentic-patching}"
MANIFEST="${ROOT}/openshift/risk-score.yaml"
CONSOLE_CONFIGMAP="cve-console-config"

SKIP_TRAIN=false
RETRAIN=false
SKIP_CONSOLE=false
SKIP_VERIFY=false
NO_ROUTE=false

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Deploy the risk-score model to OpenShift (Part B — no RHOAI dependency).

Steps: train (B1) -> build (B3) -> deploy (B4) -> verify (B5) -> wire console (B6)

Options:
  -n, --namespace NAME   Target namespace (default: ${NAMESPACE})
      --retrain          Re-run save_model.py even if model.joblib exists
      --skip-train       Never train; fail if model.joblib is missing
      --skip-console     Do not set RISK_URL on the cve-console ConfigMap
      --skip-verify      Do not run the post-deploy prediction check
      --no-route         Do not create the external Route
  -h, --help             Show this help

Requires: oc (logged in). Training additionally requires python3 + pip.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--namespace) NAMESPACE="$2"; shift 2 ;;
    --retrain)      RETRAIN=true; shift ;;
    --skip-train)   SKIP_TRAIN=true; shift ;;
    --skip-console) SKIP_CONSOLE=true; shift ;;
    --skip-verify)  SKIP_VERIFY=true; shift ;;
    --no-route)     NO_ROUTE=true; shift ;;
    -h|--help)      usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

step() { echo ""; echo "=== $* ==="; }
info() { echo "  $*"; }
warn() { echo "  WARNING: $*" >&2; }
fail() { echo "ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------- preflight

step "Preflight"

command -v oc >/dev/null 2>&1 || fail "oc not found on PATH"

if ! oc whoami >/dev/null 2>&1; then
  fail "Not logged in to a cluster. Run: oc login <api-url>"
fi
info "Cluster: $(oc whoami --show-server)"
info "User:    $(oc whoami)"

if ! oc get namespace "${NAMESPACE}" >/dev/null 2>&1; then
  fail "Namespace '${NAMESPACE}' does not exist. Create it or pass -n <namespace>."
fi
info "Namespace: ${NAMESPACE}"

[[ -f "${MANIFEST}" ]] || fail "Manifest not found: ${MANIFEST}"
[[ -f "${ROOT}/Dockerfile" ]] || fail "Dockerfile not found: ${ROOT}/Dockerfile"
[[ -f "${ROOT}/serving/requirements-ocp.txt" ]] || fail "Missing serving/requirements-ocp.txt"
[[ -f "${ROOT}/serving/run_local.py" ]] || fail "Missing serving/run_local.py"
info "Build inputs present"

# ------------------------------------------------------- B1: train the model

step "B1: Model artifact"

MODEL="${ROOT}/training/model.joblib"

if [[ "${RETRAIN}" == true ]] || [[ ! -f "${MODEL}" ]]; then
  if [[ "${SKIP_TRAIN}" == true ]]; then
    fail "model.joblib missing and --skip-train was given: ${MODEL}"
  fi
  if [[ "${RETRAIN}" == true ]]; then
    info "Retraining (--retrain)"
  else
    info "model.joblib not found — training"
  fi
  command -v python3 >/dev/null 2>&1 || fail "python3 required to train; or supply model.joblib yourself"
  ( cd "${ROOT}/training" \
    && python3 -m pip install --quiet --disable-pip-version-check \
         pandas scikit-learn xgboost joblib \
    && python3 save_model.py )
  [[ -f "${MODEL}" ]] || fail "Training finished but ${MODEL} was not created"
fi

info "Model: ${MODEL} ($(wc -c <"${MODEL}" | tr -d ' ') bytes)"

# ------------------------------------------------- B3: build image in-cluster

step "B3: Build image in-cluster"

if oc get buildconfig risk-score -n "${NAMESPACE}" >/dev/null 2>&1; then
  info "BuildConfig 'risk-score' already exists — reusing"
else
  info "Creating binary BuildConfig"
  oc new-build --name=risk-score --binary --strategy=docker -n "${NAMESPACE}" >/dev/null
fi

info "Uploading build context from ${ROOT} (this takes a few minutes)"
oc start-build risk-score --from-dir="${ROOT}" --follow -n "${NAMESPACE}"

IMAGE_TAG="$(oc get istag risk-score:latest -n "${NAMESPACE}" \
  -o jsonpath='{.image.dockerImageReference}' 2>/dev/null || true)"
if [[ -z "${IMAGE_TAG}" ]]; then
  fail "Build finished but ImageStreamTag risk-score:latest was not produced"
fi
info "Image: ${IMAGE_TAG}"

# ---------------------------------------------- B4: Deployment/Service/Route

step "B4: Deploy Deployment + Service + Route"

# The manifest hardcodes 'agentic-patching' in both the namespace fields and
# the internal registry image path; rewrite both when targeting another one.
RENDERED="$(mktemp -t risk-score-manifest)"
trap 'rm -f "${RENDERED}"' EXIT
sed "s/agentic-patching/${NAMESPACE}/g" "${MANIFEST}" > "${RENDERED}"

if [[ "${NO_ROUTE}" == true ]]; then
  info "Skipping Route (--no-route)"
  python3 - "${RENDERED}" <<'PY'
import sys
path = sys.argv[1]
docs = open(path).read().split('\n---\n')
kept = [d for d in docs if 'kind: Route' not in d]
open(path, 'w').write('\n---\n'.join(kept))
PY
fi

oc apply -f "${RENDERED}" -n "${NAMESPACE}"

info "Waiting for rollout"
if ! oc rollout status deployment/risk-score -n "${NAMESPACE}" --timeout=300s; then
  echo "" >&2
  warn "Rollout did not complete. Recent pod events:"
  oc get pods -n "${NAMESPACE}" -l app=risk-score >&2 || true
  oc logs -n "${NAMESPACE}" -l app=risk-score --tail=40 >&2 || true
  fail "Deployment failed to become ready"
fi

# ------------------------------------------------------------- B5: verify

if [[ "${SKIP_VERIFY}" == false ]]; then
  step "B5: Verify the endpoint"

  POD="$(oc get pods -n "${NAMESPACE}" -l app=risk-score \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [[ -n "${POD}" ]] || fail "No risk-score pod found"

  # Exercised over Service DNS rather than localhost, so this also proves the
  # Service and its endpoints resolve. The image has python but no curl.
  VERIFY_PY='
import json, urllib.request
body = json.dumps({"instances": [
    {"cvss": 9.8, "age_days": 47, "affected_hosts": 12, "type": "security"}
]}).encode()
req = urllib.request.Request(
    "http://risk-score:8080/v1/models/risk-score:predict",
    data=body, headers={"Content-Type": "application/json"}, method="POST")
print(urllib.request.urlopen(req, timeout=30).read().decode())
'
  RESPONSE="$(oc exec -n "${NAMESPACE}" "${POD}" -- python -c "${VERIFY_PY}" 2>/dev/null || true)"

  if [[ "${RESPONSE}" != *'"predictions"'* ]]; then
    warn "Unexpected response from the model: ${RESPONSE:-<empty>}"
    fail "Verification failed — check: oc logs -n ${NAMESPACE} ${POD}"
  fi
  info "Service DNS + prediction OK: ${RESPONSE}"
fi

# ---------------------------------------------------- B6: wire up the console

if [[ "${SKIP_CONSOLE}" == false ]]; then
  step "B6: Point the console at the model"

  RISK_URL="http://risk-score:8080/v1/models/risk-score:predict"

  if oc get configmap "${CONSOLE_CONFIGMAP}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    CURRENT="$(oc get configmap "${CONSOLE_CONFIGMAP}" -n "${NAMESPACE}" \
      -o jsonpath='{.data.RISK_URL}' 2>/dev/null || true)"
    if [[ "${CURRENT}" == "${RISK_URL}" ]]; then
      info "RISK_URL already set correctly"
    else
      oc patch configmap "${CONSOLE_CONFIGMAP}" -n "${NAMESPACE}" --type merge \
        -p "{\"data\":{\"RISK_URL\":\"${RISK_URL}\"}}" >/dev/null
      info "Set RISK_URL=${RISK_URL}"
    fi

    if oc get deployment cve-console -n "${NAMESPACE}" >/dev/null 2>&1; then
      if [[ "${CURRENT}" != "${RISK_URL}" ]]; then
        info "Restarting cve-console to pick up the new value"
        oc rollout restart deployment/cve-console -n "${NAMESPACE}" >/dev/null
        oc rollout status deployment/cve-console -n "${NAMESPACE}" --timeout=300s
      fi
    else
      warn "Deployment 'cve-console' not found — ConfigMap updated, nothing to restart"
    fi
  else
    warn "ConfigMap '${CONSOLE_CONFIGMAP}' not found — deploy the console first,"
    warn "then set: RISK_URL=${RISK_URL}"
  fi
fi

# ------------------------------------------------------------------ summary

step "Done"
echo "  Namespace : ${NAMESPACE}"
echo "  Image     : ${IMAGE_TAG}"
echo "  Service   : risk-score:8080 (in-cluster)"
if [[ "${NO_ROUTE}" == false ]]; then
  ROUTE_HOST="$(oc get route risk-score -n "${NAMESPACE}" \
    -o jsonpath='{.spec.host}' 2>/dev/null || true)"
  [[ -n "${ROUTE_HOST}" ]] && echo "  Route     : https://${ROUTE_HOST}"
fi
echo ""
echo "  Confirm the console is really calling the model (not the fallback"
echo "  heuristic) by starting a patch run and watching for one request per host:"
echo "    oc logs -f deployment/risk-score -n ${NAMESPACE}"
echo ""
echo "  Note: the Settings panel shows a stale placeholder RISK_URL by design."
echo "  See Part B, Step B6 in ${REPO_ROOT}/risk_score/XGBOOST_OPENSHIFT_AI_SERVING.md"
