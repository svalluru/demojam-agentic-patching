#!/usr/bin/env bash
# Remove what setup.sh and the console deploy created — and nothing else.
#
#   ./cleanup.sh --dry-run              show what would go, change nothing
#   ./cleanup.sh                        remove it, after you confirm
#   ./cleanup.sh --keep-data            keep the volumes: vector store, model cache
#   ./cleanup.sh --skip-openshift --skip-aap --skip-ao    pick stages
#   ./cleanup.sh --delete-namespace     also delete NAMESPACE itself
#   ./cleanup.sh --yes                  no confirmation prompt
#
# What it removes:
#
#   openshift   the console (cve-console), the risk model (risk-score), and
#               the RAG stack (Milvus, etcd, Llama Stack) with its two
#               secrets — in NAMESPACE from .env
#   aap         CVE - Verify Patch and its project, DJ - Agentic Patching
#   ao          the Demo Jam workflow, then the aap-credential and aap
#               integration it uses
#
# What it never touches: the lab's own AAP templates and projects, the lab's
# AO workflows and integrations, anything outside NAMESPACE, and .env.
# Each object is deleted by name; nothing is matched by pattern or deleted
# because of what it is near.
#
# The namespace is kept unless --delete-namespace is given. Deleting it
# removes everything inside it, including anything that is not ours.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"

DRY=false; YES=false; KEEP_DATA=false; DEL_NS=false
SKIP_OPENSHIFT=false; SKIP_AAP=false; SKIP_AO=false
for a in "$@"; do
  case "$a" in
    --dry-run)          DRY=true ;;
    --yes|-y)           YES=true ;;
    --keep-data)        KEEP_DATA=true ;;
    --delete-namespace) DEL_NS=true ;;
    --skip-openshift)   SKIP_OPENSHIFT=true ;;
    --skip-aap)         SKIP_AAP=true ;;
    --skip-ao)          SKIP_AO=true ;;
    -h|--help) sed -n '2,/^[^#]/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 1 ;;
  esac
done
$KEEP_DATA && $DEL_NS && { echo "--keep-data and --delete-namespace contradict each other" >&2; exit 1; }

step() { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '  \033[31m✗\033[0m %s\n' "$*"; exit 1; }

[[ -f "$ENV_FILE" ]] || die "no $ENV_FILE — cleanup reads NAMESPACE and the endpoints from it"
set -a; . "$ENV_FILE"; set +a
NS="${NAMESPACE:-agentic-patching}"

# Deleted by exact kind/name. The RAG list is what rag-setup/ applies, the
# risk list is risk-score.yaml plus the build objects, and the console's is
# what console-app-ocp-setup creates.
RAG_KEEPABLE=(pvc/etcd-pvc pvc/llamastack-hf-cache pvc/llamastack-pvc pvc/milvus-pvc)
RAG=(deployment/etcd-deployment deployment/llamastack deployment/milvus-standalone
     service/etcd-service service/llamastack service/milvus-service
     route/llamastack configmap/llamastack-config
     secret/milvus-secret secret/llamastack-inference-secret)
RISK=(deployment/risk-score service/risk-score route/risk-score
      buildconfig/risk-score imagestream/risk-score)
CONSOLE=(deployment/cve-console service/cve-console route/cve-console
         configmap/cve-console-config secret/cve-console-secrets
         buildconfig/cve-console imagestream/cve-console)
CONSOLE_KEEPABLE=(pvc/cve-console-state)

# ---------------------------------------------------------------- the plan

step "Plan"
if ! $SKIP_OPENSHIFT; then
  # The same check every deploy script makes, for the same reason: oc acts
  # on whichever cluster was last logged in to, and this deletes.
  . "$ROOT/lib/ocp-check.sh"
  ocp_check_cluster "$ENV_FILE" || die "refusing to delete anything — see above"
  echo "  OpenShift, namespace $NS:"
  echo "    console      ${CONSOLE[*]}"
  echo "    risk model   ${RISK[*]}"
  echo "    RAG stack    ${RAG[*]}"
  if $KEEP_DATA; then
    echo "    kept         ${RAG_KEEPABLE[*]} ${CONSOLE_KEEPABLE[*]}"
  else
    echo "    volumes      ${RAG_KEEPABLE[*]} ${CONSOLE_KEEPABLE[*]}"
    warn "the volumes hold the vector store and the ~500 MB embedding model cache"
  fi
  $DEL_NS && warn "then the namespace $NS itself, and everything else in it"
fi
$SKIP_AAP || echo "  AAP: CVE - Verify Patch, project DJ - Agentic Patching"
$SKIP_AO  || echo "  AO : workflow '${AO_WORKFLOW_NAME:-RHEL CVE Remediation - Intelligent Patching - Demo Jam}', credential aap-credential, integration aap"

if $DRY; then echo; echo "  --dry-run: nothing was changed."; exit 0; fi

if ! $YES; then
  echo
  printf '  Type the namespace (%s) to confirm: ' "$NS"
  read -r answer
  [[ "$answer" == "$NS" ]] || die "not confirmed — nothing was changed"
fi

FAILED=0
# --ignore-not-found makes a re-run, or a half-finished setup, a no-op
# rather than an error.
drop() { oc delete "$@" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || FAILED=$((FAILED+1)); }

# --------------------------------------------------------------- openshift

if ! $SKIP_OPENSHIFT; then
  step "OpenShift — $NS"
  drop "${CONSOLE[@]}";  ok "console removed"
  drop "${RISK[@]}";     ok "risk model removed"
  drop "${RAG[@]}";      ok "RAG stack removed"
  if ! $KEEP_DATA; then
    drop "${RAG_KEEPABLE[@]}" "${CONSOLE_KEEPABLE[@]}"; ok "volumes removed"
  fi
  if $DEL_NS; then
    oc delete project "$NS" --wait=false >/dev/null 2>&1 \
      && ok "namespace $NS deleted (finishes in the background)" \
      || { warn "could not delete namespace $NS"; FAILED=$((FAILED+1)); }
  fi
fi

# --------------------------------------------------------------------- aap

if ! $SKIP_AAP; then
  step "AAP"
  "$ROOT/aap-setup/create-verify-template.sh" --delete || FAILED=$((FAILED+1))
fi

# ---------------------------------------------------------------------- ao

if ! $SKIP_AO; then
  step "Automation Orchestrator"
  # Workflow first: it references the credential and integration, and they
  # cannot be removed while something still uses them.
  "$ROOT/ao-setup/create-ao-workflow.sh" --delete || FAILED=$((FAILED+1))
  "$ROOT/ao-setup/create-ao-objects.sh"  --delete || FAILED=$((FAILED+1))
fi

step "Done"
if [[ $FAILED -gt 0 ]]; then
  warn "$FAILED step(s) did not complete — re-running is safe"
  exit 1
fi
ok "cleaned up. .env is untouched; ./setup.sh rebuilds everything"
