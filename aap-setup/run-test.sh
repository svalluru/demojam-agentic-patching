#!/usr/bin/env bash
# Launch 'CVE - Fetch and Commit' for one CVE and host, follow it, and report
# what it committed. This is the standalone test: it exercises the whole path
# — Insights SSO, remediation generation, GitHub commit — without Ansible
# Orchestrator or the console being involved at all.
#
# Usage:
#   ./run-test.sh CVE-2026-88812 rdu-z16-l13
#   ./run-test.sh CVE-2026-88812 rdu-z16-l13 --branch other-branch
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$(cd "$SCRIPT_DIR/.." && pwd)/.env}"
JT_NAME="${JT_NAME:-CVE - Fetch and Commit}"

CVE="${1:-}"
HOST="${2:-}"
BRANCH="generated-playbooks"
shift 2 2>/dev/null || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --branch) BRANCH="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '  %s\n' "$*"; }
step() { printf '\n=== %s ===\n' "$*"; }

[[ -n "$CVE" && -n "$HOST" ]] || fail "usage: ./run-test.sh <CVE-ID> <host> [--branch b]"
[[ -f "$ENV_FILE" ]] || fail "env file not found: $ENV_FILE"
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a
[[ -n "${AAP_TOKEN:-}" && -n "${AAP_BASE_URL:-}" ]] || fail "AAP_TOKEN / AAP_BASE_URL not set"

BASE="${AAP_BASE_URL%/}"
CURL_OPTS=(-s --max-time 90 -H "Authorization: Bearer $AAP_TOKEN"
           -H "Content-Type: application/json")
[[ "${AAP_VERIFY_TLS:-true}" =~ ^(0|false|no)$ ]] && CURL_OPTS+=(-k)
api() { curl "${CURL_OPTS[@]}" -X "$1" "$BASE$2" ${3:+-d "$3"}; }

JT_ID="$(curl "${CURL_OPTS[@]}" --get --data-urlencode "name=$JT_NAME" \
  "$BASE/job_templates/" | python3 -c "
import json,sys
for r in json.load(sys.stdin).get('results',[]):
    if r['name'] == '''$JT_NAME''': print(r['id']); break")"
[[ -n "$JT_ID" ]] || fail "job template '$JT_NAME' not found — run ./create-aap-objects.sh first"

step "Launching"
info "template : $JT_NAME ($JT_ID)"
info "cve      : $CVE"
info "host     : $HOST"
info "branch   : $BRANCH"

PAYLOAD="$(python3 -c "
import json
print(json.dumps({'extra_vars': {
  'cve_id': '''$CVE''', 'target_host': '''$HOST''', 'github_branch': '''$BRANCH''',
}}))")"
JOB_ID="$(api POST "/job_templates/$JT_ID/launch/" "$PAYLOAD" | python3 -c "
import json,sys
d=json.load(sys.stdin)
if 'id' not in d: print('LAUNCH_FAILED', json.dumps(d)[:400]); raise SystemExit
print(d['id'])")"
[[ "$JOB_ID" =~ ^[0-9]+$ ]] || fail "launch failed: $JOB_ID"
info "job      : $JOB_ID   ${BASE%/api/controller/v2}/#/jobs/playbook/$JOB_ID"

step "Waiting"
for _ in $(seq 1 150); do
  STATUS="$(api GET "/jobs/$JOB_ID/" | python3 -c "
import json,sys; print(json.load(sys.stdin).get('status',''))")"
  case "$STATUS" in
    successful|failed|error|canceled) break ;;
  esac
  sleep 2
done
info "status: ${STATUS:-unknown}"

step "Output"
api GET "/jobs/$JOB_ID/stdout/?format=txt" | sed 's/^/  /'

step "Artifacts"
api GET "/jobs/$JOB_ID/" | python3 -c "
import json,sys
d=json.load(sys.stdin)
a=d.get('artifacts') or {}
if not a: print('  none — the play did not reach set_stats')
for k,v in a.items(): print(f'  {k:20} {v}')"

[[ "$STATUS" == "successful" ]] || exit 1
