#!/usr/bin/env bash
# Create the Ansible Orchestrator objects the console needs
# via the AO REST API.
#
#   Credentials                            Integrations
#   -----------                            ------------
#   aap-credential  Ansible Automation     aap   Ansible Automation Platform
#                   Platform / OAuth2            base_url  <- AAP_BASE_URL
#                   token <- AAP_TOKEN           cred      <- aap-credential
#   llm-token       LLM Provider /         maas  LLM Provider
#                   API key <- VLLM_API_TOKEN    base_url  <- VLLM_URL
#                                                cred      <- llm-token
#
# Idempotent: existing objects are reused and their secrets refreshed, so this
# is safe to re-run in a pipeline.
#
# Usage:
#   ./create-ao-objects.sh              # create / update
#   ./create-ao-objects.sh --dry-run    # show what would happen
#   ./create-ao-objects.sh --delete     # remove the four objects
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$(cd "$SCRIPT_DIR/.." && pwd)/.env}"

# Which LLM family the maas endpoint belongs to. AO accepts:
#   red_hat_ai | openai | anthropic | gemini | custom
PROVIDER_HINT="${PROVIDER_HINT:-red_hat_ai}"

DRY_RUN=false
DELETE=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --delete)  DELETE=true ;;
    -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 1 ;;
  esac
done

step() { printf '\n=== %s ===\n' "$*"; }
info() { printf '  %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# -------------------------------------------------------------------- setup

command -v curl    >/dev/null || fail "curl not found"
command -v python3 >/dev/null || fail "python3 not found"
[[ -f "$ENV_FILE" ]] || fail "env file not found: $ENV_FILE"

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

for v in AO_URL AO_USERNAME AO_PASSWORD AAP_TOKEN AAP_BASE_URL VLLM_URL VLLM_API_TOKEN; do
  [[ -n "${!v:-}" ]] || fail "$v is empty in $ENV_FILE"
done

AO_URL="${AO_URL%/}"
# The integration wants the controller root, not the /api/controller/v2 path.
AAP_BASE="${AAP_BASE_URL%/api/controller/v2}"
AAP_BASE="${AAP_BASE%/}"

# jq is not assumed; this reads one field from a JSON object on stdin.
jget() { python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
v=d
for k in '$1'.split('.'):
    if isinstance(v,dict): v=v.get(k)
    else: v=None
print('' if v is None else v)
"; }

# Find an object by name in a {'resources':[...]} listing. Prints its id.
jfind() { python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for r in d.get('resources') or d.get('data') or []:
    if r.get('name')=='''$1''':
        print(r.get('id')); break
"; }

jerr() { python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: print('unparseable response'); sys.exit(0)
print(d.get('detail') or d.get('title') or json.dumps(d)[:300])
"; }

api() {  # api METHOD PATH [JSON]
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -sk --max-time 60 -X "$method" "$AO_URL$path" \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "$body"
  else
    curl -sk --max-time 60 -X "$method" "$AO_URL$path" -H "Authorization: Bearer $TOKEN"
  fi
}

api_code() {  # same, but prints only the HTTP status
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -sk --max-time 60 -o /dev/null -w '%{http_code}' -X "$method" "$AO_URL$path" \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "$body"
  else
    curl -sk --max-time 60 -o /dev/null -w '%{http_code}' -X "$method" "$AO_URL$path" \
      -H "Authorization: Bearer $TOKEN"
  fi
}

json_str() { python3 -c "import json,sys;print(json.dumps(sys.argv[1]))" "$1"; }

# ------------------------------------------------------------------- login

step "Connect"
info "AO        : $AO_URL"
info "env file  : $ENV_FILE"

TOKEN="$(curl -sk --max-time 30 -X POST "$AO_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":$(json_str "$AO_USERNAME"),\"password\":$(json_str "$AO_PASSWORD")}" \
  | jget access_token)"
[[ -n "$TOKEN" ]] || fail "login failed for user '$AO_USERNAME' — check AO_USERNAME / AO_PASSWORD"
info "logged in as $AO_USERNAME"

PROJECT_ID="$(api GET /api/v1/projects | python3 -c "
import json,sys
rs=json.load(sys.stdin).get('resources',[])
d=[p for p in rs if p.get('is_default')] or [p for p in rs if p.get('name')=='default']
print(d[0]['id'] if d else '')
")"
[[ -n "$PROJECT_ID" ]] || fail "could not find the default project"
info "project   : default ($PROJECT_ID)"

type_id() {  # credential type id by display name
  api GET /api/v1/credential_types | jfind "$1"
}
AAP_TYPE_ID="$(type_id 'Ansible Automation Platform')"
LLM_TYPE_ID="$(type_id 'LLM Provider')"
[[ -n "$AAP_TYPE_ID" ]] || fail "credential type 'Ansible Automation Platform' not found"
[[ -n "$LLM_TYPE_ID" ]] || fail "credential type 'LLM Provider' not found"

CRED_PATH="/api/v1/projects/$PROJECT_ID/credentials"

# ------------------------------------------------------------------ delete

if [[ "$DELETE" == true ]]; then
  step "Delete"
  for n in aap maas; do
    id="$(api GET /api/v1/integrations | jfind "$n")"
    if [[ -n "$id" ]]; then
      info "integration $n ($id) -> HTTP $(api_code DELETE "/api/v1/integrations/$id")"
    else
      info "integration $n: not present"
    fi
  done
  for n in aap-credential llm-token; do
    id="$(api GET "$CRED_PATH" | jfind "$n")"
    if [[ -n "$id" ]]; then
      info "credential $n ($id) -> HTTP $(api_code DELETE "$CRED_PATH/$id")"
    else
      info "credential $n: not present"
    fi
  done
  exit 0
fi

# ------------------------------------------------------------- credentials

step "Credentials"

# Sets the variable named by $4 to the credential id. Using an out-variable
# rather than command substitution keeps progress output on stdout instead of
# swallowing it into the caller's assignment.
ensure_credential() {  # name type_id inputs_json out_var
  local name="$1" type_id="$2" inputs="$3" out="$4" id resp code
  id="$(api GET "$CRED_PATH" | jfind "$name")"

  if [[ "$DRY_RUN" == true ]]; then
    info "[dry-run] credential '$name' would be $([[ -n "$id" ]] && echo updated || echo created)"
    printf -v "$out" '%s' "${id:-DRYRUN}"; return
  fi

  if [[ -n "$id" ]]; then
    # Refresh the secret so a rotated token in .env takes effect.
    code="$(api_code PATCH "/api/v1/credentials/$id" "{\"inputs\":$inputs}")"
    info "credential '$name' exists ($id) — secret refresh HTTP $code"
    printf -v "$out" '%s' "$id"; return
  fi

  resp="$(api POST "$CRED_PATH" \
    "{\"name\":$(json_str "$name"),\"credential_type_id\":\"$type_id\",\"inputs\":$inputs}")"
  id="$(printf '%s' "$resp" | jget id)"
  [[ -n "$id" ]] || fail "could not create credential '$name': $(printf '%s' "$resp" | jerr)"
  info "credential '$name' created ($id)"
  printf -v "$out" '%s' "$id"
}

ensure_credential 'aap-credential' "$AAP_TYPE_ID" \
  "{\"oauth_token\":$(json_str "$AAP_TOKEN")}" AAP_CRED_ID
ensure_credential 'llm-token' "$LLM_TYPE_ID" \
  "{\"api_key\":$(json_str "$VLLM_API_TOKEN")}" LLM_CRED_ID

# ------------------------------------------------------------ integrations

step "Integrations"

ensure_integration() {  # name type configuration_json credential_id
  local name="$1" itype="$2" cfg="$3" cred="$4" id resp
  id="$(api GET /api/v1/integrations | jfind "$name")"

  if [[ "$DRY_RUN" == true ]]; then
    info "[dry-run] integration '$name' ($itype) would be $([[ -n "$id" ]] && echo updated || echo created)"
    return
  fi

  if [[ -n "$id" ]]; then
    # integration_type is immutable — PATCH rejects it as an extra input.
    resp="$(api PATCH "/api/v1/integrations/$id" \
      "{\"name\":$(json_str "$name"),\"management_credential_id\":\"$cred\",\
\"configuration\":$cfg}")"
    [[ -n "$(printf '%s' "$resp" | jget id)" ]] \
      || fail "could not update integration '$name': $(printf '%s' "$resp" | jerr)"
    info "integration '$name' exists ($id) — updated"
  else
    resp="$(api POST /api/v1/integrations \
      "{\"name\":$(json_str "$name"),\"integration_type\":\"$itype\",\
\"management_credential_id\":\"$cred\",\"configuration\":$cfg}")"
    id="$(printf '%s' "$resp" | jget id)"
    [[ -n "$id" ]] || fail "could not create integration '$name': $(printf '%s' "$resp" | jerr)"
    info "integration '$name' created ($id)"
  fi

  # Validation actually connects to the target, so a failure here means the
  # object exists but the endpoint or credential is wrong.
  api POST "/api/v1/integrations/$id/validate" '{}' | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: print('    validate: unparseable response'); sys.exit(0)
if d.get('success'):
    print('    validate: OK (reached the endpoint at %s)' % (d.get('checked_at') or '')[:19])
else:
    print('    validate: FAILED — %s' % (d.get('error') or d.get('detail') or d))
"
}

ensure_integration 'aap' 'ansible_automation_platform' \
  "{\"integration_type\":\"ansible_automation_platform\",\"base_url\":$(json_str "$AAP_BASE")}" \
  "$AAP_CRED_ID"

ensure_integration 'maas' 'llm_provider' \
  "{\"integration_type\":\"llm_provider\",\"provider_hint\":\"$PROVIDER_HINT\",\
\"base_url\":$(json_str "$VLLM_URL")}" \
  "$LLM_CRED_ID"

# ------------------------------------------------------------------ report

step "Result"
api GET "$CRED_PATH" | python3 -c "
import json,sys
for r in json.load(sys.stdin).get('resources',[]):
    print('  credential   %-16s %s' % (r.get('name'), r.get('id')))
"
api GET /api/v1/integrations | python3 -c "
import json,sys
for r in json.load(sys.stdin).get('resources',[]):
    cfg = r.get('configuration') or {}
    print('  integration  %-16s %-38s %s' % (
        r.get('name'), r.get('id'), cfg.get('base_url','')))
"
