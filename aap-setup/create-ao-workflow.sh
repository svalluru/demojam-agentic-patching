#!/usr/bin/env bash
# Create (or update) the 'CVE Fetch and Commit' workflow in Ansible Orchestrator
# from test-workflow/cve_fetch_and_commit_workflow.json, publish it, and
# optionally run it.
#
# One node: accept a CVE and a host, call the AAP job template, stop. No
# approval gate, no risk scoring, no remediation run — this is the fetch-and-
# commit step on its own, so it can be proven before being wired into the main
# workflow.
#
# Usage:
#   ./create-ao-workflow.sh
#   ./create-ao-workflow.sh --run CVE-2026-88812 rdu-z16-l13
#   ./create-ao-workflow.sh --delete
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$(cd "$SCRIPT_DIR/.." && pwd)/.env}"
DEF_FILE="${DEF_FILE:-$SCRIPT_DIR/test-workflow/cve_fetch_and_commit_workflow.json}"
WF_NAME="${WF_NAME:-CVE Fetch and Commit}"

RUN=false; DELETE=false; RUN_CVE=""; RUN_HOST=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run)    RUN=true; RUN_CVE="${2:-}"; RUN_HOST="${3:-}"; shift 3 ;;
    --delete) DELETE=true; shift ;;
    -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

step() { printf '\n=== %s ===\n' "$*" >&2; }
info() { printf '  %s\n' "$*" >&2; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ -f "$ENV_FILE" ]] || fail "env file not found: $ENV_FILE"
[[ -f "$DEF_FILE" ]] || fail "workflow definition not found: $DEF_FILE"
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a
for v in AO_URL AO_USERNAME AO_PASSWORD; do
  [[ -n "${!v:-}" ]] || fail "$v is empty in $ENV_FILE"
done

AO="${AO_URL%/}"
TOKEN="$(curl -sk --max-time 25 -X POST "$AO/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$AO_USERNAME\",\"password\":\"$AO_PASSWORD\"}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))")"
[[ -n "$TOKEN" ]] || fail "AO login failed — check AO_USERNAME / AO_PASSWORD"
info "logged in to $AO"

api() { curl -sk --max-time 60 -X "$1" "$AO$2" \
          -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
          ${3:+--data-binary "$3"}; }

find_wf() {
  api GET /api/v1/workflows | python3 -c "
import json,sys
d=json.load(sys.stdin)
for w in d.get('resources', d if isinstance(d,list) else []):
    if w.get('name') == '''$WF_NAME''': print(w['id']); break"
}

WF_ID="$(find_wf)"

if $DELETE; then
  step "Deleting"
  if [[ -n "$WF_ID" ]]; then
    code="$(curl -sk -o /dev/null -w '%{http_code}' -X DELETE "$AO/api/v1/workflows/$WF_ID" \
            -H "Authorization: Bearer $TOKEN")"
    info "$WF_NAME ($WF_ID) -> HTTP $code"
  else
    info "$WF_NAME: not present"
  fi
  exit 0
fi

# The AO project the workflow belongs to. 'default' unless told otherwise.
PROJECT_ID="${AO_PROJECT_ID:-$(api GET /api/v1/projects | python3 -c "
import json,sys
d=json.load(sys.stdin)
for p in d.get('resources', d if isinstance(d,list) else []):
    if p.get('name') == 'default': print(p['id']); break")}"
[[ -n "$PROJECT_ID" ]] || fail "could not find the AO 'default' project"

PAYLOAD="$(DEF_FILE="$DEF_FILE" PROJECT_ID="$PROJECT_ID" WF_NAME="$WF_NAME" python3 -c "
import json, os
wd = json.load(open(os.environ['DEF_FILE']))
print(json.dumps({
    'name': os.environ['WF_NAME'],
    'description': wd.get('description', ''),
    'project_id': os.environ['PROJECT_ID'],
    'workflow_definition': wd,
}))")"

if [[ -n "$WF_ID" ]]; then
  step "Updating $WF_NAME ($WF_ID)"
  # A new version is created rather than the published one edited in place.
  out="$(api PUT "/api/v1/workflows/$WF_ID" "$PAYLOAD")"
else
  step "Creating $WF_NAME"
  out="$(api POST /api/v1/workflows "$PAYLOAD")"
  WF_ID="$(printf '%s' "$out" | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")"
fi
[[ -n "$WF_ID" ]] || fail "create/update failed: $(printf '%s' "$out" | head -c 400)"

issues="$(printf '%s' "$out" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('yes' if d.get('has_validation_issues') else 'no')")"
info "workflow id        : $WF_ID"
info "validation issues  : $issues"
[[ "$issues" == "no" ]] || fail "AO reported validation issues: $(printf '%s' "$out" \
  | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin).get('validation_result'))[:400])")"

# publish takes the version *number*, not the version uuid.
VER_NO="$(api GET "/api/v1/workflows/$WF_ID" | python3 -c "
import json,sys; print((json.load(sys.stdin).get('version') or {}).get('version',''))")"
step "Publishing version $VER_NO"
code="$(curl -sk -o /dev/null -w '%{http_code}' -X POST \
        "$AO/api/v1/workflows/$WF_ID/versions/$VER_NO/publish" \
        -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}')"
info "publish -> HTTP $code"

api GET "/api/v1/workflows/$WF_ID" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f\"  enabled: {d.get('is_enabled')}  published version: {d.get('published_version_number')}\", file=sys.stderr)"

if $RUN; then
  [[ -n "$RUN_CVE" && -n "$RUN_HOST" ]] || fail "--run needs a CVE and a host"
  step "Running"
  info "cve  : $RUN_CVE"
  info "host : $RUN_HOST"
  # Values go through the environment, not string interpolation: a host name
  # or CVE id spliced into a quoted python -c is one odd character away from
  # a syntax error, and the error surfaces as "could not start an execution".
  RUN_PAYLOAD="$(WF_ID="$WF_ID" RUN_CVE="$RUN_CVE" RUN_HOST="$RUN_HOST" python3 -c '
import json, os
print(json.dumps({
    "workflow_id": os.environ["WF_ID"],
    "trigger_node_id": "trigger_manual",
    "input_data": {
        "cve_id": os.environ["RUN_CVE"],
        "host": os.environ["RUN_HOST"],
        "github_branch": "generated-playbooks",
    },
}))')"
  EX="$(api POST /api/v1/executions "$RUN_PAYLOAD" \
        | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")"
  [[ -n "$EX" ]] || fail "could not start an execution"
  info "execution: $EX"
  for _ in $(seq 1 60); do
    st="$(api GET "/api/v1/executions/$EX" | python3 -c "
import json,sys; print(json.load(sys.stdin).get('status',''))")"
    case "$st" in completed|failed|error|cancelled) break ;; esac
    sleep 3
  done
  info "status: ${st:-unknown}"
  info ""
  info "AO reports the execution, not the commit. Confirm the result with:"
  info "  git fetch && git log --oneline origin/generated-playbooks -3"
  [[ "$st" == "completed" ]] || exit 1
fi

step "Done"
info "workflow : $WF_NAME ($WF_ID)"
info "run it   : ./create-ao-workflow.sh --run CVE-2026-88812 rdu-z16-l13"
