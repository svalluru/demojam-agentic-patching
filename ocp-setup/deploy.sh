#!/usr/bin/env bash
# Deploy the console to OpenShift, with .env as the single source of config.
#
#   ./ocp-setup/deploy.sh                 build, configure, deploy
#   ./ocp-setup/deploy.sh --config-only   update config and restart, no build
#   ./ocp-setup/deploy.sh --external      keep .env's Route URLs for RAG/risk
#   ./ocp-setup/deploy.sh --delete        remove everything this creates
#
# Config comes from .env rather than a second copy kept in step by hand.
# Four keys go into a Secret and the rest into a ConfigMap, by an explicit
# allowlist — classifying by guesswork is how a credential ends up readable
# in a ConfigMap.
#
# What it does not deploy: Milvus, Llama Stack and the risk model. Those are
# rag-setup/deploy.sh and risk_score/openshift/, and this assumes they are
# already up — it checks.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERE="$ROOT/ocp-setup"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"
APP=cve-console

CONFIG_ONLY=false; DELETE=false; IN_CLUSTER=true
for a in "$@"; do
  case "$a" in
    --config-only) CONFIG_ONLY=true ;;
    --external)    IN_CLUSTER=false ;;
    --delete)      DELETE=true ;;
    -h|--help)     sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 1 ;;
  esac
done

step() { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '  \033[31m✗\033[0m %s\n' "$*"; exit 1; }

command -v oc >/dev/null || die "oc not found"
oc whoami >/dev/null 2>&1 || die "not logged in — run 'oc login' first"
NS="$(oc project -q)"

if $DELETE; then
  step "Deleting"
  oc delete all,configmap,secret,pvc -l "app=$APP" -n "$NS" --ignore-not-found
  oc delete bc,is "$APP" -n "$NS" --ignore-not-found 2>/dev/null || true
  ok "removed from $NS"
  exit 0
fi

[[ -f "$ENV_FILE" ]] || die "no $ENV_FILE — the config comes from it"

step "Target"
ok "cluster   $(oc whoami --show-server)"
ok "namespace $NS"

# -- the services this one talks to ----------------------------------------
step "Backing services"
for svc in llamastack risk-score; do
  if oc get svc "$svc" -n "$NS" >/dev/null 2>&1; then
    ok "$svc is up"
  else
    warn "$svc not found in $NS — live mode will fail on that step"
  fi
done

# -- config ----------------------------------------------------------------
step "Config from $(basename "$ENV_FILE")"

# Explicit, because the cost of being wrong is one-directional: a secret in
# a ConfigMap is readable by anything that can read ConfigMaps.
SECRET_KEYS="LIGHTSPEED_CLIENT_SECRET AO_PASSWORD AAP_TOKEN VLLM_API_TOKEN"

tmp_cm="$(mktemp)"; tmp_sec="$(mktemp)"
trap 'rm -f "$tmp_cm" "$tmp_sec"' EXIT

SECRET_KEYS="$SECRET_KEYS" IN_CLUSTER="$IN_CLUSTER" \
CM_OUT="$tmp_cm" SEC_OUT="$tmp_sec" python3 - "$ENV_FILE" <<'PY'
import os, pathlib, sys

secret_keys = set(os.environ['SECRET_KEYS'].split())
in_cluster = os.environ['IN_CLUSTER'] == 'true'
cm, sec = {}, {}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    line = line.strip()
    if not line or line.startswith('#') or '=' not in line:
        continue
    k, v = line.split('=', 1)
    k, v = k.strip(), v.strip().strip('"').strip("'")
    if not k.isupper():
        continue
    (sec if k in secret_keys else cm)[k] = v

# Inside the cluster these are Services, not Routes. Going out to the router
# and back costs latency and a TLS handshake to reach a pod three metres
# away, and it fails entirely if the Route is down while the Service is fine.
if in_cluster:
    if cm.get('LLAMA_STACK_URL'):
        cm['LLAMA_STACK_URL'] = 'http://llamastack:8321'
    if cm.get('RISK_URL'):
        cm['RISK_URL'] = 'http://risk-score:8080/v1/models/risk-score:predict'

# The frontend defaults to 127.0.0.1, which answers nothing from a Service.
cm['FRONTEND_HOST'] = '0.0.0.0'
# The backend deliberately does not: only the sibling container may reach it.
cm['BACKEND_HOST'] = '127.0.0.1'

for path, data in ((os.environ['CM_OUT'], cm), (os.environ['SEC_OUT'], sec)):
    pathlib.Path(path).write_text(
        '\n'.join(f'{k}={v}' for k, v in sorted(data.items())) + '\n')

print(f'  configmap keys : {len(cm)}')
print(f'  secret keys    : {len(sec)}  ({", ".join(sorted(sec))})')
missing = [k for k in secret_keys if k not in sec]
if missing:
    print(f'  \033[33m!\033[0m not set, so not stored: {", ".join(missing)}')
if in_cluster:
    print('  endpoints      : rewritten to in-cluster Services '
          '(--external keeps the Route URLs)')
PY

oc create configmap "$APP-config" --from-env-file="$tmp_cm" -n "$NS" \
  --dry-run=client -o yaml | oc apply -f - >/dev/null
oc create secret generic "$APP-secrets" --from-env-file="$tmp_sec" -n "$NS" \
  --dry-run=client -o yaml | oc apply -f - >/dev/null
oc label configmap "$APP-config" "app=$APP" -n "$NS" --overwrite >/dev/null
oc label secret "$APP-secrets" "app=$APP" -n "$NS" --overwrite >/dev/null
ok "configmap and secret applied"

# -- build -----------------------------------------------------------------
if ! $CONFIG_ONLY; then
  step "Image"
  if ! oc get bc "$APP" -n "$NS" >/dev/null 2>&1; then
    # Binary build: the cluster never needs to reach GitHub, and there is no
    # registry to authenticate to. It builds what is on this disk, which is
    # also what you have been testing.
    #
    # dockerfilePath is not optional. The whole repo is uploaded as the
    # build context so the Containerfile can COPY the sources, but the
    # docker strategy then looks for ./Dockerfile at the root of it and
    # fails with "no such file or directory" naming a path that was never
    # going to exist.
    oc new-build --name="$APP" --binary --strategy=docker -n "$NS" >/dev/null
    oc patch bc "$APP" -n "$NS" --type=merge -p \
      '{"spec":{"strategy":{"dockerStrategy":{"dockerfilePath":"ocp-setup/Containerfile"}}}}' >/dev/null
    ok "created buildconfig"
  fi
  # No output suppression and no fallback: a build that fails here produced
  # no image, and the deployment that follows would sit in ImagePullBackOff
  # pulling a tag that does not exist. Better to stop at the real error.
  oc start-build "$APP" -n "$NS" --from-dir="$ROOT" --follow \
    || die "build failed — see 'oc logs build/$APP-<n>'"
  ok "image built"
fi

# -- deploy ----------------------------------------------------------------
step "Deploy"
oc apply -f "$HERE/manifests/service-route-pvc.yaml" -n "$NS" >/dev/null
IMAGE="$(oc get is "$APP" -n "$NS" -o jsonpath='{.status.dockerImageRepository}' 2>/dev/null)"
[[ -n "$IMAGE" ]] || die "no imagestream $APP — run without --config-only first"
sed "s#image: cve-console:latest#image: ${IMAGE}:latest#g" \
  "$HERE/manifests/deployment.yaml" | oc apply -n "$NS" -f - >/dev/null
ok "manifests applied"

# Config changes do not restart pods on their own, and a pod holding last
# week's VECTOR_DB_ID looks healthy while returning no RAG hits at all.
oc rollout restart deployment/"$APP" -n "$NS" >/dev/null
oc rollout status deployment/"$APP" -n "$NS" --timeout=300s

URL="https://$(oc get route "$APP" -n "$NS" -o jsonpath='{.spec.host}')"
step "Done"
echo "  $URL"
echo
echo "  logs:    oc logs -f deployment/$APP -c backend -n $NS"
echo "  config:  ./ocp-setup/deploy.sh --config-only   (after editing .env)"
