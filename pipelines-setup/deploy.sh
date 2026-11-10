#!/usr/bin/env bash
# Applications v2 "test in a pod": OpenShift Pipelines, the app-v2-test and app-v2-build Pipelines, and the account
# AAP starts them with. Run after nexus-setup/deploy.sh (it reads NEXUS_ADMIN_PASSWORD).
#
#   ./pipelines-setup/deploy.sh
#
# 1. Installs the Red Hat OpenShift Pipelines operator (operator.yaml) if the Tekton CRDs are missing, and waits.
# 2. In NAMESPACE (from .env, default agentic-patching): the ConfigMap app-v2-healthserver (the sample app's
#    HealthServer.java), the ConfigMap app-v2-tools (apply_dependency_changes.py, for Rebuild from source), the
#    Secret app-v2-nexus (uploads the built bundle), the Tasks and Pipelines in pipeline.yaml, the ServiceAccount app-v2-runner with edit
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
oc create configmap app-v2-tools -n "$NS" \
  --from-file=apply_dependency_changes.py="$ROOT/aap-setup/playbooks/files/apply_dependency_changes.py" \
  --dry-run=client -o yaml | oc apply -f -
# Rebuild from source uploads the built bundle to Nexus maven-releases.
NEXUS_PW="$(grep -E '^NEXUS_ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2- | tr -d "'\"")"
[ -n "$NEXUS_PW" ] && oc create secret generic app-v2-nexus -n "$NS" --from-literal=username=admin \
  --from-literal=password="$NEXUS_PW" --dry-run=client -o yaml | oc apply -f - >/dev/null && say "secret app-v2-nexus applied"
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
echo "Next: ./aap-setup/create-app-v2-objects.py --seed-repos   (Test in a Pod and Seed App Repos templates, the Gitea app repos)"
