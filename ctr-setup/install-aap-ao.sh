#!/usr/bin/env bash
# Minimal Ansible Automation Platform and Automation Orchestrator for the Containers side, on the cluster in
# OCP_API_URL. Idempotent: every step applies or keeps what is there.
#
#   ./ctr-setup/install-aap-ao.sh
#
#   aap   AAP operator (stable-2.6, namespace-scoped) and an AnsibleAutomationPlatform with only the gateway and the
#         controller (no Hub, EDA, Lightspeed), low requests. Route aap-aap.apps.<domain>.
#   ao    AO operator (AllNamespaces only: subscribed in openshift-operators), one PostgreSQL 15 in namespace ao
#         (databases ao, temporal, temporal_visibility), and an AutomationOrchestrator with one replica per
#         component. Route ao-ao.apps.<domain>.
#
# Afterwards: upload the AAP subscription manifest (AAP runs no job without one), then
#   ./aap-setup/create-ctr-objects.py and DEF_FILE=ao-setup/ctr_workflow.json WF_NAME="Container Patch" ./ao-setup/create-ao-workflow.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
want="$(grep -E '^OCP_API_URL=' "$ROOT/.env" | cut -d= -f2- | tr -d "'\"")"
have="$(oc whoami --show-server 2>/dev/null || true)"
[ -n "$want" ] && [ "$have" = "$want" ] || { echo "oc is on '${have:-nothing}', .env says '$want': log in to the right cluster first" >&2; exit 1; }

wait_csv() {   # namespace, name prefix
  for _ in $(seq 1 60); do
    p="$(oc -n "$1" get csv -o jsonpath='{range .items[*]}{.metadata.name}={.status.phase}{"\n"}{end}' 2>/dev/null | grep "^$2" | cut -d= -f2 | head -1)"
    [ "$p" = Succeeded ] && return 0; sleep 10
  done
  echo "operator $2 in $1 did not install (phase: ${p:-none})" >&2; return 1
}

echo "=== AAP ==="
oc apply -f "$HERE/aap/aap-operator.yaml"
wait_csv aap aap-operator
oc apply -f "$HERE/aap/aap.yaml"

echo "=== AO ==="
oc apply -f "$HERE/ao/ao-operator.yaml"
wait_csv openshift-operators automation-orchestrator-operator
python3 - <<'PY'
import base64, json, secrets, subprocess
def run(*a, **k): return subprocess.run(a, capture_output=True, **k)
def secret(name, data):
    if run('oc', '-n', 'ao', 'get', 'secret', name).returncode == 0:
        print('  kept', name); return
    obj = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': name, 'namespace': 'ao'}, 'stringData': data}
    subprocess.run(['oc', 'apply', '-f', '-'], input=json.dumps(obj).encode(), check=True, stdout=subprocess.DEVNULL)
    print('  created', name)
secret('ao-postgres', {'username': 'ao', 'password': secrets.token_urlsafe(24), 'admin-password': secrets.token_urlsafe(24)})
pw = base64.b64decode(json.loads(run('oc', '-n', 'ao', 'get', 'secret', 'ao-postgres', '-o', 'json', check=True).stdout)['data']['password']).decode()
secret('ao-backend-db', {'database': 'ao', 'username': 'ao', 'password': pw})
secret('ao-temporal-db', {'database': 'temporal', 'username': 'ao', 'password': pw})
PY
oc apply -f "$HERE/ao/postgres.yaml"
oc -n ao rollout status statefulset/ao-postgres --timeout=300s
oc apply -f "$HERE/ao/ao.yaml"

echo "=== Wait ==="
for _ in $(seq 1 60); do
  r="$(oc -n ao get automationorchestrator ao -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)"
  w="$(oc -n aap get deploy aap-controller-web -o jsonpath='{.status.readyReplicas}' 2>/dev/null)"
  [ "$r" = True ] && [ "${w:-0}" -ge 1 ] && break; sleep 15
done
echo "  AO ready: ${r:-no}   AAP controller web ready: ${w:-0}"
echo "  AAP: https://$(oc -n aap get route aap -o jsonpath='{.spec.host}')   (admin password: secret aap-admin-password in aap)"
echo "  AO:  https://$(oc -n ao get route ao -o jsonpath='{.spec.host}')"
