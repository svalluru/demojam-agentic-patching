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
REBUILD=false
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
      --rebuild          Build the image even if one exists for these exact sources
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
    --rebuild)      REBUILD=true; shift ;;
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

. "${REPO_ROOT}/lib/ocp-check.sh"
ocp_check_cluster "${REPO_ROOT}/.env" || fail "refusing to deploy — see above"

# Created if missing, skipped if present. Checked with 'oc get project'
# rather than 'oc get namespace': a user without cluster-scoped read can see
# their own projects but may not be allowed to read the namespace object,
# and would be told a project they own does not exist.
if oc get project "${NAMESPACE}" >/dev/null 2>&1; then
  info "namespace: ${NAMESPACE} (exists)"
else
  oc new-project "${NAMESPACE}" --skip-config-write >/dev/null 2>&1 \
    || oc create namespace "${NAMESPACE}" >/dev/null \
    || fail "could not create namespace '${NAMESPACE}'"
  info "namespace: ${NAMESPACE} (created)"
fi

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

# Skip the build when the image already exists for these exact sources.
#
# Re-running setup.sh rebuilt the image every time — minutes of uploading and
# pip installing to produce what was already in the registry. "An image
# exists" is not enough to skip on, though: a retrained model or edited
# server must still rebuild. So the inputs the image is made from are
# fingerprinted, the fingerprint is recorded on the BuildConfig after a
# successful build, and a matching fingerprint with the image still present
# is the only thing that skips.
#
# These four are everything the Dockerfile copies or installs from. If it
# starts copying something else, add it here, or a change to it will not
# trigger a rebuild.
SOURCES=(Dockerfile serving/requirements-ocp.txt serving/run_local.py training/model.joblib)
SOURCE_SHA="$(cd "${ROOT}" && cat "${SOURCES[@]}" 2>/dev/null | shasum -a 256 | cut -c1-16)"
BUILT_SHA="$(oc get buildconfig risk-score -n "${NAMESPACE}" \
  -o jsonpath='{.metadata.annotations.agentic-patching/source-sha}' 2>/dev/null || true)"
HAVE_IMAGE="$(oc get istag risk-score:latest -n "${NAMESPACE}" \
  -o jsonpath='{.image.dockerImageReference}' 2>/dev/null || true)"

if [[ "${REBUILD}" != true && -n "${HAVE_IMAGE}" && "${BUILT_SHA}" == "${SOURCE_SHA}" ]]; then
  info "Image already built from these sources (${SOURCE_SHA}) — skipping"
  info "Pass --rebuild to build anyway"
else
  if [[ "${REBUILD}" == true ]]; then info "Rebuilding (--rebuild)"
  elif [[ -z "${HAVE_IMAGE}" ]]; then info "No image yet — building"
  elif [[ -z "${BUILT_SHA}" ]]; then info "Image exists but its sources were not recorded — building once to record them"
  else info "Sources changed since the last build (${BUILT_SHA} -> ${SOURCE_SHA}) — building"
  fi
  info "Uploading build context from ${ROOT} (this takes a few minutes)"
  oc start-build risk-score --from-dir="${ROOT}" --follow -n "${NAMESPACE}"
  # Recorded only after the build succeeded — set -e stops before this
  # otherwise — so a failed build never looks current.
  oc annotate buildconfig risk-score -n "${NAMESPACE}" \
    "agentic-patching/source-sha=${SOURCE_SHA}" --overwrite >/dev/null
fi

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
