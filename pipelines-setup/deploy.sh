#!/usr/bin/env bash
# Applications v2 "test in a pod": OpenShift Pipelines, the app-v2-test Pipeline, and the account AAP starts it with.
#
#   ./pipelines-setup/deploy.sh
#
# 1. Installs the Red Hat OpenShift Pipelines operator (operator.yaml) if the Tekton CRDs are missing, and waits.
# 2. In NAMESPACE (from .env, default agentic-patching): the ConfigMap app-v2-healthserver (the sample app's
#    HealthServer.java), the Tasks and Pipeline in pipeline.yaml, and the ServiceAccount app-v2-runner with edit
#    rights here only, whose token AAP uses to create PipelineRuns.
# 3. Writes APPV2_PIPELINE_TOKEN (the token) and APPV2_PIPELINE_NAMESPACE to .env, for
#    aap-setup/create-app-v2-objects.py. The token is never printed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"
NS="$(grep -E '^NAMESPACE=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d "'\"" || true)"
NS="${NS:-agentic-patching}"

say() { printf '  %s\n' "$*"; }

if ! oc get crd pipelines.tekton.dev >/dev/null 2>&1; then
  echo "OpenShift Pipelines"
  oc apply -f "$HERE/operator.yaml"
  say "operator subscribed; waiting for Tekton"
  until oc get crd pipelines.tekton.dev >/dev/null 2>&1; do sleep 10; done
fi
until oc get tasks.tekton.dev buildah -n openshift-pipelines >/dev/null 2>&1; do
  say "waiting for the openshift-pipelines buildah task"; sleep 15
done

echo "Pipeline in $NS"
oc create configmap app-v2-healthserver -n "$NS" \
  --from-file=HealthServer.java="$ROOT/aap-setup/playbooks/files/HealthServer.java" \
  --dry-run=client -o yaml | oc apply -f -
oc apply -n "$NS" -f "$HERE/pipeline.yaml"

echo "Account for AAP"
oc create serviceaccount app-v2-runner -n "$NS" --dry-run=client -o yaml | oc apply -f -
oc create rolebinding app-v2-runner-edit -n "$NS" --clusterrole=edit --serviceaccount="$NS:app-v2-runner" \
  --dry-run=client -o yaml | oc apply -f -
cat <<YAML | oc apply -n "$NS" -f -
apiVersion: v1
kind: Secret
metadata:
  name: app-v2-runner-token
  annotations:
    kubernetes.io/service-account.name: app-v2-runner
type: kubernetes.io/service-account-token
YAML
TOKEN=""
for _ in $(seq 1 20); do
  TOKEN="$(oc get secret app-v2-runner-token -n "$NS" -o jsonpath='{.data.token}' 2>/dev/null | base64 -d || true)"
  [ -n "$TOKEN" ] && break; sleep 2
done
[ -n "$TOKEN" ] || { echo "no token for app-v2-runner" >&2; exit 1; }

python3 - "$ENV_FILE" "$TOKEN" "$NS" <<'PY'
import re, sys
path, token, ns = sys.argv[1:]
text = open(path).read() if __import__('os').path.exists(path) else ''
for k, v in (('APPV2_PIPELINE_TOKEN', token), ('APPV2_PIPELINE_NAMESPACE', ns)):
    line = f'{k}={v}'
    text = re.sub(rf'^{k}=.*$', line, text, flags=re.M) if re.search(rf'^{k}=', text, re.M) else text.rstrip('\n') + '\n' + line + '\n'
open(path, 'w').write(text)
PY
say "APPV2_PIPELINE_TOKEN and APPV2_PIPELINE_NAMESPACE written to .env"
echo
echo "Next: ./aap-setup/create-app-v2-objects.py   (adds the Test in a Pod job template and its credential)"
