#!/usr/bin/env bash
# Create the one AAP object the competition workflow needs from us: the
# CVE - Verify Patch job template, and the project it runs from.
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
# The project tracks the branch you are on, so the controller runs the verify
# playbook as this checkout has it rather than as some other branch does.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"

REPO_URL="${REPO_URL:-https://github.com/svalluru/demojam-agentic-patching}"
BRANCH="${BRANCH:-$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo dj-comp)}"
PROJECT_NAME="${PROJECT_NAME:-DJ - Agentic Patching}"
JT_NAME="${JT_NAME:-CVE - Verify Patch}"
PLAYBOOK="aap-setup/playbooks/cve_verify_patch.yml"
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

for n in "$PROJECT_NAME" "$JT_NAME"; do
  [[ "$n" =~ ^($PROTECTED)$ ]] && fail "'$n' is a lab object — refusing to write to it"
done

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
info "template   : $JT_NAME  on $INVENTORY / $CREDENTIAL"
$DRY && info "mode       : DRY RUN — nothing will be changed"
code="$(api_code GET /ping/)"
[[ "$code" == "200" ]] || fail "controller not reachable at $BASE (HTTP $code — 503 usually means restarting)"

if $DELETE; then
  step "Deleting"
  for spec in "/job_templates/:$JT_NAME" "/projects/:$PROJECT_NAME"; do
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

step "Project"
PROJ_ID="$(upsert /projects/ "$PROJECT_NAME" "$(python3 -c "
import json; print(json.dumps({'name': '''$PROJECT_NAME''', 'organization': int('$ORG_ID'),
  'scm_type': 'git', 'scm_url': '''$REPO_URL''', 'scm_branch': '''$BRANCH''',
  'scm_update_on_launch': True,
  'description': 'The verify playbook, from this repo. Tracks the branch it was set up from.'}))")")"

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

step "Job template"
JT_ID="$(upsert /job_templates/ "$JT_NAME" "$(python3 -c "
import json; print(json.dumps({'name': '''$JT_NAME''', 'job_type': 'run',
  'inventory': int('$INV_ID'), 'project': int('$PROJ_ID') if '$PROJ_ID'.isdigit() else None,
  'playbook': '''$PLAYBOOK''', 'ask_variables_on_launch': True,
  'extra_vars': 'target_host: \"\"\ncve_id: \"\"',
  'description': 'Confirms a CVE is no longer outstanding on the target. Never fails the run.'}))")")"

if ! $DRY; then
  have="$(api GET "/job_templates/$JT_ID/credentials/" | python3 -c "
import json,sys; print(' '.join(str(c['id']) for c in json.load(sys.stdin).get('results',[])))")"
  if [[ " $have " != *" $CRED_ID "* ]]; then
    api_code POST "/job_templates/$JT_ID/credentials/" "{\"id\": $CRED_ID}" >/dev/null
    info "attached $CREDENTIAL"
  fi
fi

step "Done"
info "$JT_NAME runs $PLAYBOOK from $BRANCH against $INVENTORY"
