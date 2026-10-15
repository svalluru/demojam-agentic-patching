#!/usr/bin/env bash
# Create the AAP objects the CVE remediation flow needs, via the controller API.
#
#   Credential types (custom)        Credentials              Injects
#   -------------------------        -----------              -------
#   GitHub Token                     github-token             GITHUB_TOKEN
#   Insights Lightspeed              insights-lightspeed      LIGHTSPEED_CLIENT_ID
#                                                             LIGHTSPEED_CLIENT_SECRET
#
#   Project                          Job template
#   -------                          ------------
#   DemoJam Agentic Patching         CVE - Fetch and Commit
#   <- GITHUB_REPO_URL, main            playbook: aap-setup/playbooks/
#                                                 cve_fetch_and_commit.yml
#
# Why custom credential types: AAP only exposes a credential to a playbook as an
# environment variable if its type declares an injector. The built-in Source
# Control type lets AAP *clone* a repository; it hands the playbook nothing. The
# playbook needs to authenticate to the GitHub API itself, so it needs this.
#
# Idempotent: objects are matched by name, created if absent and updated if
# present, so this is safe to re-run. Secrets are re-pushed every run because
# the API never discloses them for comparison.
#
# Usage:
#   ./create-aap-objects.sh              # create / update
#   ./create-aap-objects.sh --dry-run    # show what would happen, change nothing
#   ./create-aap-objects.sh --delete     # remove what this script creates
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$(cd "$SCRIPT_DIR/.." && pwd)/.env}"

GITHUB_REPO_URL="${GITHUB_REPO_URL:-https://github.com/svalluru/demojam-agentic-patching}"
PROJECT_BRANCH="${PROJECT_BRANCH:-main}"
PLAYBOOK_PATH="${PLAYBOOK_PATH:-aap-setup/playbooks/cve_fetch_and_commit.yml}"

PROJECT_NAME="${PROJECT_NAME:-DemoJam Agentic Patching}"
JT_NAME="${JT_NAME:-CVE - Fetch and Commit}"
GH_CRED_NAME="${GH_CRED_NAME:-github-token}"
LS_CRED_NAME="${LS_CRED_NAME:-insights-lightspeed}"
GH_TYPE_NAME="${GH_TYPE_NAME:-GitHub Token}"
LS_TYPE_NAME="${LS_TYPE_NAME:-Insights Lightspeed}"

DRY_RUN=false
DELETE=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --delete)  DELETE=true ;;
    -h|--help) sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 1 ;;
  esac
done

# Progress goes to stderr so that functions which echo an id to stdout can be
# captured with $( ) without their own chatter being swallowed into the value.
step() { printf '\n=== %s ===\n' "$*" >&2; }
info() { printf '  %s\n' "$*" >&2; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# -------------------------------------------------------------------- setup

command -v curl    >/dev/null || fail "curl not found"
command -v python3 >/dev/null || fail "python3 not found"
[[ -f "$ENV_FILE" ]] || fail "env file not found: $ENV_FILE"

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

for v in AAP_BASE_URL AAP_TOKEN GIT_HUB_TOKEN LIGHTSPEED_CLIENT_ID LIGHTSPEED_CLIENT_SECRET; do
  [[ -n "${!v:-}" ]] || fail "$v is empty in $ENV_FILE"
done

BASE="${AAP_BASE_URL%/}"
ORG_ID="${AAP_DEFAULT_ORGANIZATION_ID:-1}"
INVENTORY_ID="${AAP_DEFAULT_INVENTORY_ID:-1}"
EE_ID="${AAP_DEFAULT_EXECUTION_ENVIRONMENT_ID:-2}"

CURL_OPTS=(-s --max-time 90 -H "Authorization: Bearer $AAP_TOKEN"
           -H "Content-Type: application/json")
[[ "${AAP_VERIFY_TLS:-true}" =~ ^(0|false|no)$ ]] && CURL_OPTS+=(-k)

api()      { curl "${CURL_OPTS[@]}" -X "$1" "$BASE$2" ${3:+-d "$3"}; }
api_code() { curl "${CURL_OPTS[@]}" -o /dev/null -w '%{http_code}' -X "$1" "$BASE$2" ${3:+-d "$3"}; }

# Reads one dotted field from JSON on stdin. jq is not assumed.
jget() { python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
v=d
for k in '$1'.split('.'):
    v = v.get(k) if isinstance(v,dict) else None
print('' if v is None else v)
"; }

# id of the first result whose name matches exactly, else empty.
find_id() { # $1 endpoint  $2 name
  python3 -c "
import json,sys,urllib.parse
print(urllib.parse.quote('''$2'''))" >/dev/null
  curl "${CURL_OPTS[@]}" --get --data-urlencode "name=$2" "$BASE$1" | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for r in d.get('results',[]):
    if r.get('name') == '''$2''':
        print(r['id']); break
"
}

json() { python3 -c "
import json,sys
print(json.dumps(json.loads(sys.stdin.read())))
"; }

step "Target"
info "controller : ${BASE}"
info "org        : ${ORG_ID}   inventory: ${INVENTORY_ID}   exec env: ${EE_ID}"
info "repo       : ${GITHUB_REPO_URL} (${PROJECT_BRANCH})"
info "playbook   : ${PLAYBOOK_PATH}"
$DRY_RUN && info "mode       : DRY RUN — nothing will be changed"

code="$(api_code GET /ping/)"
[[ "$code" == "200" ]] || fail "controller not reachable at $BASE (HTTP $code)"
info "reachable  : HTTP $code"

# ------------------------------------------------------------------ delete

if $DELETE; then
  step "Deleting"
  for spec in "/job_templates/:$JT_NAME" "/projects/:$PROJECT_NAME" \
              "/credentials/:$GH_CRED_NAME" "/credentials/:$LS_CRED_NAME" \
              "/credential_types/:$GH_TYPE_NAME" "/credential_types/:$LS_TYPE_NAME"; do
    ep="${spec%%:*}"; name="${spec#*:}"
    id="$(find_id "$ep" "$name")"
    if [[ -n "$id" ]]; then
      if $DRY_RUN; then info "would delete $name ($ep$id)"
      else info "$name ($id) -> HTTP $(api_code DELETE "$ep$id/")"; fi
    else
      info "$name: not present"
    fi
  done
  exit 0
fi

# -------------------------------------------------------- credential types

create_or_update() { # $1 endpoint  $2 name  $3 payload-json  -> echoes id
  local ep="$1" name="$2" payload="$3" id
  id="$(find_id "$ep" "$name")"
  if [[ -n "$id" ]]; then
    if $DRY_RUN; then info "would update $name ($id)"; else
      code="$(api_code PATCH "$ep$id/" "$payload")"
      [[ "$code" =~ ^20 ]] || fail "updating $name failed (HTTP $code): $(api PATCH "$ep$id/" "$payload" | head -c 300)"
      info "updated $name ($id)"
    fi
  else
    if $DRY_RUN; then info "would create $name"; id="DRYRUN"; else
      local out; out="$(api POST "$ep" "$payload")"
      id="$(printf '%s' "$out" | jget id)"
      [[ -n "$id" ]] || fail "creating $name failed: $(printf '%s' "$out" | head -c 300)"
      info "created $name ($id)"
    fi
  fi
  printf '%s' "$id"
}

step "Credential types"

GH_TYPE_PAYLOAD="$(python3 -c "
import json
print(json.dumps({
  'name': '''$GH_TYPE_NAME''',
  'description': 'GitHub token exposed to the playbook as GITHUB_TOKEN',
  'kind': 'cloud',
  'inputs': {
    'fields': [{'id': 'github_token', 'label': 'GitHub Token',
                'type': 'string', 'secret': True}],
    'required': ['github_token'],
  },
  'injectors': {'env': {'GITHUB_TOKEN': '{{ github_token }}'}},
}))")"
GH_TYPE_ID="$(create_or_update /credential_types/ "$GH_TYPE_NAME" "$GH_TYPE_PAYLOAD")"

LS_TYPE_PAYLOAD="$(python3 -c "
import json
print(json.dumps({
  'name': '''$LS_TYPE_NAME''',
  'description': 'Red Hat Insights service account, as LIGHTSPEED_CLIENT_ID / _SECRET',
  'kind': 'cloud',
  'inputs': {
    'fields': [
      {'id': 'client_id', 'label': 'Client ID', 'type': 'string'},
      {'id': 'client_secret', 'label': 'Client Secret', 'type': 'string',
       'secret': True},
    ],
    'required': ['client_id', 'client_secret'],
  },
  'injectors': {'env': {
    'LIGHTSPEED_CLIENT_ID': '{{ client_id }}',
    'LIGHTSPEED_CLIENT_SECRET': '{{ client_secret }}',
  }},
}))")"
LS_TYPE_ID="$(create_or_update /credential_types/ "$LS_TYPE_NAME" "$LS_TYPE_PAYLOAD")"

# ------------------------------------------------------------- credentials

step "Credentials"

GH_CRED_PAYLOAD="$(GH_TYPE_ID="$GH_TYPE_ID" ORG_ID="$ORG_ID" python3 -c "
import json,os
print(json.dumps({
  'name': '''$GH_CRED_NAME''',
  'credential_type': int(os.environ['GH_TYPE_ID']) if os.environ['GH_TYPE_ID'].isdigit() else 0,
  'organization': int(os.environ['ORG_ID']),
  'inputs': {'github_token': os.environ['GIT_HUB_TOKEN']},
}))")"
GH_CRED_ID="$(create_or_update /credentials/ "$GH_CRED_NAME" "$GH_CRED_PAYLOAD")"

LS_CRED_PAYLOAD="$(LS_TYPE_ID="$LS_TYPE_ID" ORG_ID="$ORG_ID" python3 -c "
import json,os
print(json.dumps({
  'name': '''$LS_CRED_NAME''',
  'credential_type': int(os.environ['LS_TYPE_ID']) if os.environ['LS_TYPE_ID'].isdigit() else 0,
  'organization': int(os.environ['ORG_ID']),
  'inputs': {'client_id': os.environ['LIGHTSPEED_CLIENT_ID'],
             'client_secret': os.environ['LIGHTSPEED_CLIENT_SECRET']},
}))")"
LS_CRED_ID="$(create_or_update /credentials/ "$LS_CRED_NAME" "$LS_CRED_PAYLOAD")"

# ----------------------------------------------------------------- project

step "Project"

PROJECT_PAYLOAD="$(python3 -c "
import json
print(json.dumps({
  'name': '''$PROJECT_NAME''',
  'description': 'Playbooks for the agentic CVE patching demo',
  'organization': int('''$ORG_ID'''),
  'scm_type': 'git',
  'scm_url': '''$GITHUB_REPO_URL''',
  'scm_branch': '''$PROJECT_BRANCH''',
  # The repository is public, so no SCM credential is needed to clone it.
  # update_on_launch keeps a job from running last week's playbook.
  'scm_update_on_launch': True,
  'scm_clean': True,
  'scm_delete_on_update': False,
}))")"
PROJECT_ID="$(create_or_update /projects/ "$PROJECT_NAME" "$PROJECT_PAYLOAD")"

if ! $DRY_RUN; then
  info "syncing project ..."
  api POST "/projects/$PROJECT_ID/update/" '{}' >/dev/null || true
  for _ in $(seq 1 60); do
    status="$(api GET "/projects/$PROJECT_ID/" | jget status)"
    [[ "$status" == "successful" || "$status" == "failed" || "$status" == "error" ]] && break
    sleep 2
  done
  info "sync status: ${status:-unknown}"
  [[ "$status" == "successful" ]] || fail \
    "project sync did not succeed — check the branch exists and the playbook is pushed"
fi

# ------------------------------------------------------------ job template

step "Job template"

JT_PAYLOAD="$(python3 -c "
import json
print(json.dumps({
  'name': '''$JT_NAME''',
  'description': 'Fetch a remediation playbook from Insights, commit it to GitHub',
  'job_type': 'run',
  'organization': int('''$ORG_ID'''),
  'inventory': int('''$INVENTORY_ID'''),
  'project': int('''$PROJECT_ID''') if '''$PROJECT_ID'''.isdigit() else None,
  'playbook': '''$PLAYBOOK_PATH''',
  'execution_environment': int('''$EE_ID'''),
  # The orchestrator supplies cve_id and target_host per run; the rest are
  # defaults it can override.
  'ask_variables_on_launch': True,
  'extra_vars': json.dumps({
    'github_repo': '''$GITHUB_REPO_URL'''.rstrip('/').split('github.com/')[-1],
    'github_branch': 'generated-playbooks',
    'playbooks_dir': 'generated_playbooks',
  }),
  'verbosity': 0,
}))")"
JT_ID="$(create_or_update /job_templates/ "$JT_NAME" "$JT_PAYLOAD")"

if ! $DRY_RUN; then
  step "Attaching credentials to the job template"
  # Attaching is additive and idempotent: posting an already-attached
  # credential is accepted and changes nothing.
  for cid in "$GH_CRED_ID" "$LS_CRED_ID"; do
    code="$(api_code POST "/job_templates/$JT_ID/credentials/" "{\"id\": $cid}")"
    info "credential $cid -> HTTP $code"
  done
  attached="$(api GET "/job_templates/$JT_ID/credentials/" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(', '.join(r['name'] for r in d.get('results',[])) or 'none')")"
  info "attached: $attached"
fi

step "Done"
info "project      : $PROJECT_NAME ($PROJECT_ID)"
info "job template : $JT_NAME ($JT_ID)"
info ""
info "Launch a test run with:"
info "  ./run-test.sh CVE-2026-88812 rdu-z16-l13"
info ""
info "Point the console at the new project by setting in .env:"
info "  AAP_DEFAULT_PROJECT_ID=$PROJECT_ID"
