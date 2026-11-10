#!/usr/bin/env bash
# Deploy Sonatype Nexus Repository (Community Edition) for Applications v2 and configure it to proxy the Lightwell
# Network Java repository, following Red Hat's "Configure Nexus to use the Lightwell Network repository":
# a Maven2 proxy on https://packages.redhat.com/lightwell/java/remediated/, Layout Policy Strict, and the registry
# service account (LIGHTWELL_REGISTRY_USER / _TOKEN) as its username and password.
#
#   ./nexus-setup/deploy.sh            deploy (or update) and configure
#   ./nexus-setup/deploy.sh --delete   remove Nexus, its route and its volume
#
# Writes NEXUS_URL, NEXUS_ADMIN_PASSWORD and NEXUS_WEBHOOK_SECRET to .env. With the console on a laptop (the usual
# setup) set NEXUS_EVENTS=poller and NEXUS_POLL_SECONDS: the console polls Nexus. The webhook this creates calls the
# console's Service in the same namespace (http://cve-console:8788/api/v2/webhook) and only reaches a console
# deployed there (./console-app-ocp-setup/deploy.sh).
#
# .env is read with Python, never sourced: LIGHTWELL_REGISTRY_USER contains a '|'.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"
step() { echo ""; echo "=== $* ==="; }
info() { echo "  $*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }

envget() { python3 - "$ENV_FILE" "$1" <<'PY'
import sys
path, key = sys.argv[1], sys.argv[2]
val = ''
try:
    for raw in open(path):
        line = raw.strip()
        if line.startswith(key + '='):
            val = line.split('=', 1)[1].strip().strip('"').strip("'")
except OSError:
    pass
print(val)
PY
}

NAMESPACE="${NAMESPACE:-$(envget NAMESPACE)}"; NAMESPACE="${NAMESPACE:-agentic-patching}"
IMAGE="${NEXUS_IMAGE:-$(envget NEXUS_IMAGE)}"; IMAGE="${IMAGE:-docker.io/sonatype/nexus3:latest}"

step "Preflight"
. "$ROOT/lib/ocp-check.sh"
ocp_check_cluster "$ENV_FILE" || fail "refusing to deploy — see above"
oc get project "$NAMESPACE" >/dev/null 2>&1 || fail "namespace $NAMESPACE does not exist — run ./setup.sh first"
info "namespace: $NAMESPACE   image: $IMAGE"

if [[ "${1:-}" == "--delete" ]]; then
  step "Delete"
  oc delete deployment/nexus service/nexus route/nexus pvc/nexus-data -n "$NAMESPACE" --ignore-not-found
  info "removed. NEXUS_* lines in .env are left; clear them by hand."
  exit 0
fi

step "Apply"
oc apply -n "$NAMESPACE" -f - >/dev/null <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata: { name: nexus-data, labels: { app: nexus } }
spec:
  accessModes: [ReadWriteOnce]
  resources: { requests: { storage: ${NEXUS_STORAGE:-10Gi} } }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: nexus, labels: { app: nexus } }
spec:
  replicas: 1
  # Recreate: one RWO volume, and Nexus refuses to start on a data directory another instance holds.
  strategy: { type: Recreate }
  selector: { matchLabels: { app: nexus } }
  template:
    metadata: { labels: { app: nexus } }
    spec:
      containers:
        - name: nexus
          image: ${IMAGE}
          ports: [{ containerPort: 8081, name: http }]
          env:
            # Sized for a lab. Java prefs go to the volume: the image's default location is not writable under
            # OpenShift's arbitrary uid.
            - name: INSTALL4J_ADD_VM_PARAMS
              value: "-Xms1g -Xmx1g -XX:MaxDirectMemorySize=1g -Djava.util.prefs.userRoot=/nexus-data/javaprefs"
          volumeMounts: [{ name: data, mountPath: /nexus-data }]
          readinessProbe:
            httpGet: { path: /service/rest/v1/status, port: 8081 }
            initialDelaySeconds: 60
            periodSeconds: 10
            failureThreshold: 30
          livenessProbe:
            httpGet: { path: /service/rest/v1/status, port: 8081 }
            initialDelaySeconds: 240
            periodSeconds: 30
            failureThreshold: 6
          resources:
            requests: { cpu: 500m, memory: 2Gi }
            limits:   { cpu: "2",  memory: 3Gi }
      volumes: [{ name: data, persistentVolumeClaim: { claimName: nexus-data } }]
---
apiVersion: v1
kind: Service
metadata: { name: nexus, labels: { app: nexus } }
spec:
  selector: { app: nexus }
  ports: [{ name: http, port: 8081, targetPort: 8081 }]
---
apiVersion: route.openshift.io/v1
kind: Route
metadata: { name: nexus, labels: { app: nexus } }
spec:
  to: { kind: Service, name: nexus }
  port: { targetPort: http }
  tls: { termination: edge, insecureEdgeTerminationPolicy: Redirect }
EOF
info "applied"

step "Wait for Nexus (first start takes a few minutes)"
if ! oc rollout status deployment/nexus -n "$NAMESPACE" --timeout=900s; then
  oc logs -n "$NAMESPACE" -l app=nexus --tail=40 >&2 || true
  fail "nexus did not become ready"
fi
HOST="$(oc get route nexus -n "$NAMESPACE" -o jsonpath='{.spec.host}')"
NEXUS_URL="https://$HOST"
info "$NEXUS_URL"

step "Configure"
# The generated admin password exists only until it is changed, so read it once; configure.py replaces it and
# stores the new one in .env.
INITIAL="$(oc exec -n "$NAMESPACE" deploy/nexus -- cat /nexus-data/admin.password 2>/dev/null || true)"
NEXUS_URL="$NEXUS_URL" NEXUS_INITIAL_PASSWORD="$INITIAL" \
NEXUS_WEBHOOK_TARGET="${NEXUS_WEBHOOK_TARGET:-http://cve-console:8788/api/v2/webhook}" \
  python3 "$HERE/configure.py" --env "$ENV_FILE"
