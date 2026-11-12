#!/usr/bin/env bash
# Create the AAP objects the competition workflow needs from us: the project
# this repo's playbooks run from, and four job templates on it:
#
#   CVE - Verify Patch             is the CVE gone from the host?
#   CVE - Pre-patch Checkpoint     dnf transaction, kernel, running services before the patch
#   CVE - Post-patch Health Check  did the patch break anything? (decides the rollback route)
#   CVE - Rollback Patch           dnf history rollback to the checkpoint, old kernel, health again
#
# JT_NAME=... PLAYBOOK=... creates just that one template.
#
#   ./aap-setup/create-verify-template.sh
#   ./aap-setup/create-verify-template.sh --dry-run
#   ./aap-setup/create-verify-template.sh --delete
#
# Everything else the workflow calls belongs to the lab — CVE - Fetch and
# Commit, CVE - Sync and Deploy Remediation, the Lightspeed-Playbooks project
# behind them — and this script will not create, update or delete any of it.
#
# That is the point of it. The script it replaces matched objects by name and
# updated whatever it found, and its default names were the lab's own. Run
# from setup.sh it would have repointed the lab's Gitea project at a GitHub
# branch and swapped the lab's fetch template for a different playbook,
# breaking the workflow it was meant to be setting up.
#
# The project tracks the branch you are on, so the controller runs the
# playbooks as this checkout has them rather than as some other branch does.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"

REPO_URL="${REPO_URL:-https://github.com/svalluru/demojam-agentic-patching}"
BRANCH="${BRANCH:-$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo dj-comp)}"
PROJECT_NAME="${PROJECT_NAME:-DJ - Agentic Patching}"
# One template per line: name|playbook|extra_vars keys (comma-separated)|description.
TEMPLATES='CVE - Verify Patch|aap-setup/playbooks/cve_verify_patch.yml|target_host,cve_id|Confirms a CVE is no longer outstanding on the target. Never fails the run.
CVE - Pre-patch Checkpoint|aap-setup/playbooks/cve_checkpoint.yml|target_host,cve_id|Records the dnf transaction, kernel and running services before the patch, for the rollback. Changes nothing.
CVE - Post-patch Health Check|aap-setup/playbooks/cve_health_check.yml|target_host,checkpoint_json,force_fail|Checks every service running before the patch still runs. Never fails the run: the workflow decides.
CVE - Rollback Patch|aap-setup/playbooks/cve_rollback.yml|target_host,checkpoint_json|dnf history rollback to the checkpoint, the old kernel back, then the health check again.'
if [[ -n "${JT_NAME:-}" ]]; then
  TEMPLATES="$JT_NAME|${PLAYBOOK:-aap-setup/playbooks/cve_verify_patch.yml}|target_host,cve_id|Set up by create-verify-template.sh."
fi
JT_NAMES="$(printf '%s\n' "$TEMPLATES" | cut -d'|' -f1)"
INVENTORY="${TARGET_INVENTORY:-lab-inventory}"
CREDENTIAL="${MACHINE_CREDENTIAL:-lab-credential}"

# Names this script must never write to. Listed rather than inferred because
# the cost of getting it wrong falls on someone else's lab.
PROTECTED="Lightspeed-Playbooks|CVE - Fetch and Commit|CVE - Sync and Deploy Remediation"

DRY=false; DELETE=false
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=true ;;
    --delete)  DELETE=true ;;
    -h|--help) sed -n '2,/^[^#]/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 1 ;;
  esac
done

step() { printf '\n=== %s ===\n' "$*" >&2; }
info() { printf '  %s\n' "$*" >&2; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

while IFS= read -r n; do
  [[ "$n" =~ ^($PROTECTED)$ ]] && fail "'$n' is a lab object — refusing to write to it"
done <<< "$PROJECT_NAME
$JT_NAMES"

[[ -f "$ENV_FILE" ]] || fail "env file not found: $ENV_FILE"
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a
for v in AAP_BASE_URL AAP_TOKEN; do
  [[ -n "${!v:-}" ]] || fail "$v is empty in $ENV_FILE"
done

BASE="${AAP_BASE_URL%/}"
CURL=(-s --max-time 90 -H "Authorization: Bearer $AAP_TOKEN" -H "Content-Type: application/json")
[[ "${AAP_VERIFY_TLS:-true}" =~ ^(0|false|no)$ ]] && CURL+=(-k)
api()      { curl "${CURL[@]}" -X "$1" "$BASE$2" ${3:+-d "$3"}; }
api_code() { curl "${CURL[@]}" -o /dev/null -w '%{http_code}' -X "$1" "$BASE$2" ${3:+-d "$3"}; }

find_id() {  # $1 endpoint  $2 exact name
  curl "${CURL[@]}" --get --data-urlencode "name=$2" "$BASE$1" | WANT="$2" python3 -c "
import json,os,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for r in d.get('results',[]):
    if r.get('name') == os.environ['WANT']: print(r['id']); break"
}

step "Target"
info "controller : $BASE"
info "project    : $PROJECT_NAME  ←  $REPO_URL ($BRANCH)"
while IFS= read -r n; do info "template   : $n  on $INVENTORY / $CREDENTIAL"; done <<< "$JT_NAMES"
$DRY && info "mode       : DRY RUN — nothing will be changed"
code="$(api_code GET /ping/ || true)"   # curl's own failure (DNS, TLS) must reach the message below, not set -e
[[ "$code" == "200" ]] || fail "controller not reachable at $BASE (HTTP $code — 503 usually means restarting)"

if $DELETE; then
  step "Deleting"
  specs=(); while IFS= read -r n; do specs+=("/job_templates/:$n"); done <<< "$JT_NAMES"
  for spec in "${specs[@]}" "/projects/:$PROJECT_NAME"; do
    ep="${spec%%:*}"; name="${spec#*:}"; id="$(find_id "$ep" "$name")"
    if [[ -z "$id" ]]; then info "$name: not present"
    elif $DRY; then info "would delete $name ($id)"
    else info "$name ($id) -> HTTP $(api_code DELETE "$ep$id/")"; fi
  done
  exit 0
fi

INV_ID="$(find_id /inventories/ "$INVENTORY")"
CRED_ID="$(find_id /credentials/ "$CREDENTIAL")"
[[ -n "$INV_ID" ]]  || fail "no inventory named '$INVENTORY' — set TARGET_INVENTORY"
[[ -n "$CRED_ID" ]] || fail "no credential named '$CREDENTIAL' — set MACHINE_CREDENTIAL"
ORG_ID="$(api GET "/inventories/$INV_ID/" | python3 -c "import json,sys; print(json.load(sys.stdin).get('organization',''))")"

upsert() {  # $1 endpoint  $2 name  $3 payload  -> echoes id
  local id; id="$(find_id "$1" "$2")"
  if [[ -n "$id" ]]; then
    if $DRY; then info "would update $2 ($id)"; else
      code="$(api_code PATCH "$1$id/" "$3")"
      [[ "$code" =~ ^20 ]] || fail "updating $2 failed (HTTP $code)"
      info "updated $2 ($id)"
    fi
  else
    if $DRY; then info "would create $2"; id=DRYRUN; else
      id="$(api POST "$1" "$3" | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")"
      [[ -n "$id" ]] || fail "creating $2 failed"
      info "created $2 ($id)"
    fi
  fi
  printf '%s' "$id"
}

# Payloads are built on their own, from the environment, through a quoted
# heredoc — never as a python -c string nested inside another $( ).
# macOS's /bin/bash 3.2 loses track of quotes in that nesting: the dict's
# braces went unquoted, brace expansion split it at every comma, and each
# fragment reached python as a separate SyntaxError.
step "Project"
PROJ_PAYLOAD="$(P_NAME="$PROJECT_NAME" P_ORG="$ORG_ID" P_URL="$REPO_URL" P_BRANCH="$BRANCH" \
  python3 - <<'PY'
import json, os
print(json.dumps({
    'name': os.environ['P_NAME'], 'organization': int(os.environ['P_ORG']),
    'scm_type': 'git', 'scm_url': os.environ['P_URL'],
    'scm_branch': os.environ['P_BRANCH'], 'scm_update_on_launch': True,
    'description': 'The verify, checkpoint, health check and rollback playbooks, from this repo. Tracks the branch it was set up from.',
}))
PY
)"
PROJ_ID="$(upsert /projects/ "$PROJECT_NAME" "$PROJ_PAYLOAD")"

if ! $DRY; then
  # A template cannot name a playbook the project has not synced yet.
  upd="$(api POST "/projects/$PROJ_ID/update/" '{}' | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")"
  for _ in $(seq 1 40); do
    st="$(api GET "/project_updates/$upd/" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))")"
    [[ "$st" =~ ^(successful|failed|error|canceled)$ ]] && break
    sleep 3
  done
  [[ "$st" == "successful" ]] || fail "project sync $st — does branch '$BRANCH' exist on $REPO_URL?"
  info "synced $BRANCH"
fi

step "Job templates"
# Read from fd 3: the python heredoc and curl below would otherwise eat the
# loop's own stdin and stop it after the first template.
while IFS='|' read -r JT_NAME PLAYBOOK JT_KEYS JT_DESC <&3; do
  [[ -n "$JT_NAME" ]] || continue
  JT_PAYLOAD="$(P_NAME="$JT_NAME" P_INV="$INV_ID" P_PROJ="$PROJ_ID" P_BOOK="$PLAYBOOK" P_KEYS="$JT_KEYS" P_DESC="$JT_DESC" \
    python3 - <<'PY'
import json, os
proj = os.environ['P_PROJ']
defaults = {'force_fail': 'false'}
keys = [k for k in os.environ['P_KEYS'].split(',') if k]
print(json.dumps({
    'name': os.environ['P_NAME'], 'job_type': 'run',
    'inventory': int(os.environ['P_INV']),
    'project': int(proj) if proj.isdigit() else None,
    'playbook': os.environ['P_BOOK'], 'ask_variables_on_launch': True,
    'extra_vars': '\n'.join(f'{k}: {defaults.get(k, chr(34) * 2)}' for k in keys),
    'description': os.environ['P_DESC'],
}))
PY
  )"
  JT_ID="$(upsert /job_templates/ "$JT_NAME" "$JT_PAYLOAD")"

  if ! $DRY; then
    have="$(api GET "/job_templates/$JT_ID/credentials/" | python3 -c "
import json,sys; print(' '.join(str(c['id']) for c in json.load(sys.stdin).get('results',[])))")"
    if [[ " $have " != *" $CRED_ID "* ]]; then
      api_code POST "/job_templates/$JT_ID/credentials/" "{\"id\": $CRED_ID}" >/dev/null
      info "attached $CREDENTIAL to $JT_NAME"
    fi
  fi
done 3<<< "$TEMPLATES"

step "Done"
while IFS='|' read -r n b _ _; do info "$n runs $b from $BRANCH against $INVENTORY"; done <<< "$TEMPLATES"
