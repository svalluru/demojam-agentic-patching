#!/usr/bin/env bash
# Create (or update) the patching workflow in Ansible Orchestrator from
# demojam_lab_workflow.json, and publish it.
#
#   ./ao-setup/create-ao-workflow.sh
#   ./ao-setup/create-ao-workflow.sh --delete
#
# This is the workflow the console triggers — AO_WORKFLOW_NAME names it, and
# agent 2 resolves it by that name at dispatch. Without this the console
# starts, assesses, scores and plans, and then fails at the first dispatch
# with "workflow not found", which is a long way to go to discover a missing
# object.
#
# The definition is committed rather than built here because it was derived
# from the lab's own workflow by hand: the AI triage agent removed, since the
# console's risk score already decides the route, and a verification step
# added after each remediation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$(cd "$SCRIPT_DIR/.." && pwd)/.env}"
DEF_FILE="${DEF_FILE:-$SCRIPT_DIR/demojam_lab_workflow.json}"

DELETE=false
for a in "$@"; do
  case "$a" in
    --delete) DELETE=true ;;
    -h|--help) sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 1 ;;
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

# The name the console looks for. Taking it from .env rather than hardcoding
# means the two cannot disagree: whatever AO_WORKFLOW_NAME says is what gets
# created, so a console that starts is a console that can dispatch.
WF_NAME="${WF_NAME:-${AO_WORKFLOW_NAME:-RHEL CVE Remediation - Intelligent Patching - Demo Jam}}"

AO="${AO_URL%/}"
TOKEN="$(curl -sk --max-time 25 -X POST "$AO/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$AO_USERNAME\",\"password\":\"$AO_PASSWORD\"}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))")"
[[ -n "$TOKEN" ]] || fail "AO login failed — check AO_USERNAME / AO_PASSWORD"
info "logged in to $AO"

api() { curl -sk --max-time 90 -X "$1" "$AO$2" \
          -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
          ${3:+--data-binary "$3"}; }

find_wf() {
  api GET /api/v1/workflows | WANT="$WF_NAME" python3 -c "
import json,os,sys
d=json.load(sys.stdin)
for w in d.get('resources', d if isinstance(d,list) else []):
    if w.get('name') == os.environ['WANT']: print(w['id']); break"
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

PROJECT_ID="${AO_PROJECT_ID:-$(api GET /api/v1/projects | python3 -c "
import json,sys
d=json.load(sys.stdin)
for p in d.get('resources', d if isinstance(d,list) else []):
    if p.get('name') == 'default': print(p['id']); break")}"
[[ -n "$PROJECT_ID" ]] || fail "could not find the AO 'default' project"

# An exported workflow carries the credential and integration UUIDs of the
# instance it came from, and those mean nothing anywhere else — AO rejects
# the import with "One or more credential references are invalid or belong to
# a different project", which does not obviously mean "these ids are from a
# different AO". Resolved by name here and substituted in.
AO_CRED_NAME="${AO_CRED_NAME:-aap-credential}"
AO_INTEGRATION_NAME="${AO_INTEGRATION_NAME:-aap}"

find_by_name() {  # $1 = endpoint, $2 = name
  api GET "$1" | WANT="$2" python3 -c "
import json,os,sys
d=json.load(sys.stdin)
for r in d.get('resources', d if isinstance(d,list) else []):
    if r.get('name') == os.environ['WANT']: print(r['id']); break"
}
CRED_ID="$(find_by_name "/api/v1/projects/$PROJECT_ID/credentials" "$AO_CRED_NAME")"
INT_ID="$(find_by_name /api/v1/integrations "$AO_INTEGRATION_NAME")"
[[ -n "$CRED_ID" ]] || fail "no AO credential named '$AO_CRED_NAME' — run ./ao-setup/create-ao-objects.sh first"
[[ -n "$INT_ID"  ]] || fail "no AO integration named '$AO_INTEGRATION_NAME' — run ./ao-setup/create-ao-objects.sh first"
info "credential  : $AO_CRED_NAME ($CRED_ID)"
info "integration : $AO_INTEGRATION_NAME ($INT_ID)"

PAYLOAD="$(DEF_FILE="$DEF_FILE" PROJECT_ID="$PROJECT_ID" WF_NAME="$WF_NAME" \
           CRED_ID="$CRED_ID" INT_ID="$INT_ID" python3 -c "
import json, os, sys
wd = json.load(open(os.environ['DEF_FILE']))
wd['name'] = os.environ['WF_NAME']
swapped = ids = 0
for n in wd.get('nodes', []):
    p = n.get('parameters') or {}
    if 'credential_id' in p:
        p['credential_id'] = os.environ['CRED_ID']; swapped += 1
    if 'integration_id' in p:
        p['integration_id'] = os.environ['INT_ID']; swapped += 1
    # A job_template_id from another controller is worse than no id: AO
    # prefers it over the name and launches whatever happens to hold that
    # number here. The name is the portable reference.
    if p.pop('job_template_id', None) is not None:
        ids += 1
    # job_template_name is deliberately left alone. This workflow calls three
    # different templates — fetch, sync-and-deploy, verify — so forcing one
    # name across every node, as the single-node importer did, would point
    # the whole chain at the fetch template.
print(json.dumps({
    'name': os.environ['WF_NAME'],
    'description': wd.get('description', ''),
    'project_id': os.environ['PROJECT_ID'],
    'workflow_definition': wd,
}))
sys.stderr.write(f'  rewrote {swapped} credential/integration reference(s), '
                 f'dropped {ids} job_template_id(s)\n')
")"

if [[ -n "$WF_ID" ]]; then
  step "Updating $WF_NAME"
  # PATCH, not PUT: PUT is 405 on this API, and ignoring the response body
  # meant an update silently did nothing and then republished the version
  # that was already there.
  out="$(api PATCH "/api/v1/workflows/$WF_ID" "$PAYLOAD")"
else
  step "Creating $WF_NAME"
  out="$(api POST /api/v1/workflows "$PAYLOAD")"
  WF_ID="$(printf '%s' "$out" | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")"
fi
[[ -n "$WF_ID" ]] || fail "create/update failed: $(printf '%s' "$out" | head -c 400)"

issues="$(printf '%s' "$out" | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit('unreadable')
print('yes' if d.get('has_validation_issues') else 'no')")"
[[ "$issues" == "no" ]] || fail "AO reported validation issues: $(printf '%s' "$out" \
  | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin).get('validation_result'))[:400])")"
info "workflow id : $WF_ID"

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
print(f\"  enabled: {d.get('is_enabled')}  published version: {d.get('published_version_number')}\",
      file=sys.stderr)"

step "Done"
info "the console dispatches to this as AO_WORKFLOW_NAME=\"$WF_NAME\""
