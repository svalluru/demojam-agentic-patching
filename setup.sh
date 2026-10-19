#!/usr/bin/env bash
# One command for everything between "I have a target host and a .env" and
# "live mode works".
#
#   ./setup.sh --check         preflight only — changes nothing
#   ./setup.sh --dry-run       show every stage without running it
#   ./setup.sh                 do it
#   ./setup.sh --skip-openshift --skip-ao       pick stages
#
# Stages, in dependency order:
#
#   preflight   credentials, reachability, and the one question that decides
#               whether any of this can work: is the target host visible to
#               BOTH Insights and AAP
#   openshift   Milvus + etcd + Llama Stack, the risk model, the RAG ingest
#   aap         projects, credential types, credentials, job templates
#   ao          credentials, integrations, the Agentic Patching workflow
#   console     writes the live-mode settings into .env
#   smoke       one live assessment, end to end
#
# Every stage is idempotent, because each underlying script is. Re-running
# after a failure resumes rather than duplicating.
#
# What it will not do: produce a target host, register it with Insights, or
# invent an AAP inventory and SSH credential. Those are judgement calls about
# real machines. ./discover-hosts.py reports whether hosts you already have
# qualify; docs/EC2_TARGET_HOST.md builds one when they do not.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"

DRY=false; CHECK_ONLY=false
SKIP_OPENSHIFT=false; SKIP_AAP=false; SKIP_AO=false; SKIP_SMOKE=false
for a in "$@"; do
  case "$a" in
    --dry-run)        DRY=true ;;
    --check)          CHECK_ONLY=true ;;
    --skip-openshift) SKIP_OPENSHIFT=true ;;
    --skip-aap)       SKIP_AAP=true ;;
    --skip-ao)        SKIP_AO=true ;;
    --skip-smoke)     SKIP_SMOKE=true ;;
    # Print the header comment and stop at the first line that is not one,
    # rather than a hardcoded range that drifts every time the header grows.
    -h|--help)        sed -n '2,/^[^#]/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 1 ;;
  esac
done

step()  { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
ok()    { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn()  { printf '  \033[33m!\033[0m %s\n' "$*"; }
bad()   { printf '  \033[31m✗\033[0m %s\n' "$*"; }
die()   { bad "$*"; echo; echo "  Stopped. Nothing after this point ran."; exit 1; }
run()   { if $DRY; then printf '  [dry-run] %s\n' "$*"; else eval "$@"; fi; }

FAILED=0
note_fail() { bad "$*"; FAILED=$((FAILED+1)); }

# ---------------------------------------------------------------- preflight

step "Preflight"

[[ -f "$ENV_FILE" ]] || die "no $ENV_FILE — copy .env.example and fill it in"

# Sourcing is the first real test: an unquoted value containing a space makes
# bash try to execute the second word, and every script that sources .env
# dies somewhere unhelpful. Catch it here, by name.
if ! ( set -a; . "$ENV_FILE"; set +a ) 2>/dev/null; then
  bad "$ENV_FILE does not source cleanly"
  python3 - "$ENV_FILE" <<'PY'
import sys, pathlib
for i, line in enumerate(pathlib.Path(sys.argv[1]).read_text().splitlines(), 1):
    if '=' not in line or line.strip().startswith('#'):
        continue
    k, v = line.split('=', 1)
    v = v.rstrip()
    if ' ' in v and not (v.startswith(('"', "'")) and v.endswith(('"', "'"))):
        print(f'      line {i}: {k} has a space and is not quoted — use {k}="{v}"')
PY
  die "fix the quoting above"
fi
set -a; . "$ENV_FILE"; set +a
ok ".env sources cleanly"

for v in LIGHTSPEED_CLIENT_ID LIGHTSPEED_CLIENT_SECRET \
         AO_URL AO_USERNAME AO_PASSWORD AAP_BASE_URL AAP_TOKEN; do
  [[ -n "${!v:-}" ]] || note_fail "$v is empty in .env"
done
# GIT_HUB_TOKEN is no longer required. It fed the REST fetch step, which the
# lab workflow replaces with a Gitea commit through AAP's own credential, so
# a run needs nothing from GitHub. Still checked below when it is set,
# because aap-setup/create-aap-objects.sh does use it.
# Stop here rather than carrying on: every check below dereferences these,
# and under `set -u` the first missing one aborts the script with "unbound
# variable" — losing the list of what was missing, which was the useful part.
if [[ $FAILED -gt 0 ]]; then
  echo
  die "$FAILED credential(s) missing — fill them in and run --check again"
fi
ok "required credentials present"

command -v python3 >/dev/null || die "python3 not found"
command -v curl    >/dev/null || die "curl not found"

# -- reachability -----------------------------------------------------------

if ! $SKIP_OPENSHIFT; then
  if command -v oc >/dev/null && oc whoami >/dev/null 2>&1; then
    ok "oc logged in as $(oc whoami) at $(oc whoami --show-server 2>/dev/null | sed 's#https://api\.##;s#:6443##')"
  else
    note_fail "oc not logged in — run 'oc login', or pass --skip-openshift"
  fi
fi

code="$(curl -sk -o /dev/null -m 20 -w '%{http_code}' \
        -H "Authorization: Bearer $AAP_TOKEN" "${AAP_BASE_URL%/}/me/" || echo 000)"
[[ "$code" == "200" ]] && ok "AAP reachable and the token works" \
                       || note_fail "AAP returned $code (503 = controller restarting, 401 = wrong token)"

AO_TOKEN="$(curl -sk -m 25 -X POST "${AO_URL%/}/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$AO_USERNAME\",\"password\":\"$AO_PASSWORD\"}" 2>/dev/null \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || true)"
[[ -n "$AO_TOKEN" ]] && ok "AO login works" || note_fail "AO login failed"

# -- the question that decides whether any of this can work -----------------
#
# The console reads Insights; AAP reaches machines. A host has to be in both
# or the flow has no target, and the two halves can each look perfectly
# healthy while never overlapping. This is the check that is worth the whole
# script: seconds here against hours of building on sand.

python3 - <<'PY' || FAILED=$((FAILED+1))
import json, os, ssl, sys, urllib.parse, urllib.request, urllib.error

ctx = ssl.create_default_context()
if os.environ.get('INSIGHTS_VERIFY_TLS', 'true').lower() in ('0', 'false', 'no'):
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

def fail(msg, hint=''):
    print(f'  \033[31m✗\033[0m {msg}')
    if hint: print(f'      {hint}')
    sys.exit(1)

data = urllib.parse.urlencode({
    'grant_type': 'client_credentials',
    'client_id': os.environ['LIGHTSPEED_CLIENT_ID'],
    'client_secret': os.environ['LIGHTSPEED_CLIENT_SECRET'],
    'scope': 'api.console'}).encode()
try:
    r = urllib.request.Request(
        'https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token',
        data=data, method='POST',
        headers={'Content-Type': 'application/x-www-form-urlencoded'})
    tok = json.load(urllib.request.urlopen(r, context=ctx, timeout=45))['access_token']
except Exception as e:
    fail(f'Insights SSO rejected the service account: {str(e)[:70]}')

import base64
claims = tok.split('.')[1]; claims += '=' * (-len(claims) % 4)
org = (json.loads(base64.urlsafe_b64decode(claims)).get('organization') or {}).get('id')
print(f'  \033[32m✓\033[0m Insights token works (org {org})')

def get(url):
    rq = urllib.request.Request(url, headers={'Authorization': f'Bearer {tok}'})
    try:
        return json.load(urllib.request.urlopen(rq, context=ctx, timeout=60)), 200
    except urllib.error.HTTPError as e:
        return None, e.code

d, c = get('https://console.redhat.com/api/vulnerability/v1/vulnerabilities/cves?limit=1')
if c != 200:
    fail(f'the service account cannot read vulnerability data (HTTP {c})',
         'add it to a User Access group with Vulnerability and Remediations roles — '
         'a service account inherits nothing from the user who created it')
print('  \033[32m✓\033[0m service account can read vulnerability data')

host = os.environ.get('HOSTS_FILTER', '').strip()
if not host:
    print('  \033[33m!\033[0m HOSTS_FILTER is not set — live mode will plan for every '
          'affected host of a CVE')
    sys.exit(0)

d, c = get('https://console.redhat.com/api/inventory/v1/hosts'
           f'?hostname_or_id={urllib.parse.quote(host)}')
rows = (d or {}).get('results') or []
if c != 200 or not rows:
    fail(f'{host} is not registered in Insights org {org}',
         'this is the trap: the console cannot assess a host it cannot see. '
         'Register it into THIS org — see docs/EC2_TARGET_HOST.md')
uuid = rows[0]['id']
print(f'  \033[32m✓\033[0m {host} is in Insights ({uuid[:8]}…)')

d, c = get(f'https://console.redhat.com/api/vulnerability/v1/systems/{uuid}/cves'
           '?limit=1&advisory_available=true')
n = ((d or {}).get('meta') or {}).get('total_items')
if c != 200:
    print(f'  \033[33m!\033[0m vulnerability evaluation has not run yet (HTTP {c}) — '
          'allow 10-30 min after registering')
else:
    print(f'  \033[32m✓\033[0m {n} CVE(s) with advisories available on it')
PY

# The other half of the same question.
if [[ -n "${HOSTS_FILTER:-}" && "$code" == "200" ]]; then
  n="$(curl -sk -m 25 -H "Authorization: Bearer $AAP_TOKEN" --get \
       --data-urlencode "name=$HOSTS_FILTER" "${AAP_BASE_URL%/}/hosts/" 2>/dev/null \
       | python3 -c "import json,sys; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo 0)"
  if [[ "$n" == "0" ]]; then
    note_fail "$HOSTS_FILTER is not in AAP inventory — the console could assess it but nothing could patch it"
  else
    ok "$HOSTS_FILTER is in AAP inventory"
  fi
fi

if [[ -n "${GIT_HUB_TOKEN:-}" ]]; then
  gh="$(curl -s -o /dev/null -m 20 -w '%{http_code}' \
        -H "Authorization: Bearer $GIT_HUB_TOKEN" https://api.github.com/user || echo 000)"
  [[ "$gh" == "200" ]] && ok "GitHub token works" \
                       || note_fail "GitHub token returned $gh (401 = expired or revoked)"
fi

if [[ $FAILED -gt 0 ]]; then
  echo
  die "$FAILED preflight check(s) failed"
fi
ok "preflight clean"
$CHECK_ONLY && { echo; echo "  --check only; nothing was changed."; exit 0; }

# --------------------------------------------------------------- openshift

if ! $SKIP_OPENSHIFT; then
  step "OpenShift — RAG and the risk model"
  run "'$ROOT/rag-setup/deploy.sh'"
  run "'$ROOT/risk_score/openshift/deploy-risk-score.sh' --skip-console"

  if ! $DRY; then
    NS="${NAMESPACE:-agentic-patching}"
    LS="https://$(oc get route llamastack -n "$NS" -o jsonpath='{.spec.host}' 2>/dev/null)"
    RS="https://$(oc get route risk-score -n "$NS" -o jsonpath='{.spec.host}' 2>/dev/null)"
    [[ "$LS" == "https://" ]] && die "no llamastack route in $NS"
    [[ "$RS" == "https://" ]] && die "no risk-score route in $NS"
    ok "Llama Stack $LS"
    ok "risk model  $RS"

    # Ingest last: it needs the route, and it is the step whose output has to
    # be written back. VECTOR_DB_ID changes on every rebuild, and pasting it
    # by hand is how it ends up stale and silently returning no hits.
    VEC="$("$ROOT/rag-setup/ingest.py" --route "$LS" --name patch_history \
             --dir "$ROOT/rag-setup/data" --ensure | tee /dev/stderr \
           | grep -oE 'VECTOR_DB_ID=[A-Za-z0-9_-]+' | tail -1 | cut -d= -f2)"
    [[ -n "$VEC" ]] || die "ingest did not report a VECTOR_DB_ID"
    ok "vector store $VEC"
    python3 - "$ENV_FILE" "$LS" "$RS" "$VEC" <<'PY'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
for k, v in (('LLAMA_STACK_URL', sys.argv[2]),
             ('RISK_URL', sys.argv[3].rstrip('/') + '/v1/models/risk-score:predict'),
             ('VECTOR_DB_ID', sys.argv[4])):
    pat = re.compile(rf'^{k}=.*$', re.M)
    s = pat.sub(f'{k}={v}', s) if pat.search(s) else s + f'\n{k}={v}\n'
p.write_text(s)
print('  \033[32m✓\033[0m wrote LLAMA_STACK_URL, RISK_URL and VECTOR_DB_ID back to .env')
PY
    set -a; . "$ENV_FILE"; set +a
  fi
fi

# --------------------------------------------------------------------- aap

if ! $SKIP_AAP; then
  step "AAP — projects, credentials, job templates"
  if [[ -z "${TARGET_INVENTORY:-}" || -z "${MACHINE_CREDENTIAL:-}" ]]; then
    warn "TARGET_INVENTORY / MACHINE_CREDENTIAL not set; using the script defaults."
    warn "Set them to the inventory and SSH credential that can reach your host."
  fi
  run "'$ROOT/aap-setup/create-aap-objects.sh'"
fi

# ---------------------------------------------------------------------- ao

if ! $SKIP_AO; then
  step "Ansible Orchestrator — credentials, integrations, workflow"
  run "'$ROOT/ao-setup/create-ao-objects.sh'"
  run "'$ROOT/aap-setup/create-ao-workflow.sh'"
fi

# ----------------------------------------------------------------- console

step "Console — live-mode settings"
# Defaults chosen from what this model and this API actually do, not from
# taste. Each one is a thing that was discovered the hard way; the comments
# below say which.
if $DRY; then
  echo "  [dry-run] would set MODE=live, AO_WORKFLOW_NAME, REVIEW_THRESHOLD=65,"
  echo "            HOSTS_LIMIT=1, INSIGHTS_TIMEOUT=60, AO_TIMEOUT=60, AO_DECIDE_WAIT=300"
else
python3 - "$ENV_FILE" <<'PY'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
want = {
    'MODE': 'live',
    # The workflow derived from the lab's own, which reaches node1 through
    # the lab job templates. Not 'Agentic Patching' — that one calls the DJ-
    # templates, which are bound to a retired inventory and cannot reach the lab
    # hosts. Writing the wrong name here is silent: .env looks configured,
    # the console resolves a real workflow, and the run fails several nodes
    # in on a host the templates cannot see.
    'AO_WORKFLOW_NAME': '"RHEL CVE Remediation - Intelligent Patching - Demo Jam"',
    # The risk model emits 36.6-100, so the stock threshold of 30 is below
    # everything it can produce and the auto-patch branch never fires.
    'REVIEW_THRESHOLD': '65',
    # A cap on the plan, independent of whether the filter behaves.
    'HOSTS_LIMIT': '1',
    # A large Insights org answers slowly, and a cold CVE takes ~30s.
    'INSIGHTS_TIMEOUT': '60',
    # AO's signal call exceeds the 10s default.
    'AO_TIMEOUT': '60',
    # An approved chain runs 2-3 minutes before it settles.
    'AO_DECIDE_WAIT': '300',
}
changed = []
for k, v in want.items():
    pat = re.compile(rf'^{k}=.*$', re.M)
    cur = pat.search(s)
    if cur and cur.group(0).split('=', 1)[1].strip() == v.strip():
        continue
    s = pat.sub(f'{k}={v}', s) if cur else s + f'\n{k}={v}\n'
    changed.append(k)
p.write_text(s)
print('  \033[32m✓\033[0m ' + (', '.join(changed) if changed else 'already set'))
PY
fi

# --------------------------------------------------------------------- smoke

if ! $SKIP_SMOKE && ! $DRY; then
  step "Smoke test — one live assessment"
  set -a; . "$ENV_FILE"; set +a
  if [[ -z "${HOSTS_FILTER:-}" ]]; then
    warn "HOSTS_FILTER not set — skipping, there is no single host to assess"
  else
    CVE="$(python3 - <<'PY'
import json, os, ssl, sys, urllib.parse, urllib.request, base64
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
d = urllib.parse.urlencode({'grant_type': 'client_credentials',
    'client_id': os.environ['LIGHTSPEED_CLIENT_ID'],
    'client_secret': os.environ['LIGHTSPEED_CLIENT_SECRET'],
    'scope': 'api.console'}).encode()
r = urllib.request.Request('https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token',
    data=d, method='POST', headers={'Content-Type': 'application/x-www-form-urlencoded'})
tok = json.load(urllib.request.urlopen(r, context=ctx, timeout=45))['access_token']
def get(u):
    rq = urllib.request.Request(u, headers={'Authorization': f'Bearer {tok}'})
    return json.load(urllib.request.urlopen(rq, context=ctx, timeout=60))
h = os.environ['HOSTS_FILTER']
inv = get(f'https://console.redhat.com/api/inventory/v1/hosts?hostname_or_id={urllib.parse.quote(h)}')
uuid = (inv.get('results') or [{}])[0].get('id')
cves = get(f'https://console.redhat.com/api/vulnerability/v1/systems/{uuid}/cves'
           '?limit=1&sort=cvss3_score&advisory_available=true')
print(((cves.get('data') or [{}])[0]).get('id', ''))
PY
)"
    [[ -n "$CVE" ]] || die "no CVE with an advisory on $HOSTS_FILTER to test with"
    ok "assessing $CVE on $HOSTS_FILTER"
    pkill -f "demo.sh" 2>/dev/null || true
    for prt in 8787 8788; do
      pid="$(lsof -t -nP -iTCP:$prt -sTCP:LISTEN 2>/dev/null || true)"
      [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    sleep 1
    nohup "$ROOT/demo.sh" --live >/tmp/setup-live.log 2>&1 &
    sleep 12
    curl -s -X POST localhost:8788/api/start -H 'Content-Type: application/json' \
         -d "{\"cve\":\"$CVE\"}" >/dev/null || true
    for _ in $(seq 1 60); do
      st="$(curl -s localhost:8788/api/state | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo '')"
      [[ "$st" == "running" ]] || break
      sleep 2
    done
    curl -s localhost:8788/api/state | python3 -c "
import json, sys
d = json.load(sys.stdin); p = d.get('plan') or {}
if d.get('status') == 'complete':
    print('  \033[32m✓\033[0m assess complete — %d host(s), risk source %s, history %s'
          % (len(d.get('hosts') or []), p.get('risk_source'), p.get('history_source')))
    for h in (d.get('hosts') or []):
        print('      %s  risk %s -> %s' % (h.get('host'), h.get('risk_score'), h.get('decision')))
else:
    e = d.get('error') or {}
    print('  \033[31m✗\033[0m assess %s: %s' % (d.get('status'), str(e.get('detail'))[:110]))
    sys.exit(1)
"
  fi
fi

step "Done"
echo "  Console: http://127.0.0.1:8788   (./demo.sh --live)"
echo
echo "  Not covered by this script, because they are decisions about real machines:"
echo "    - the target host itself          docs/EC2_TARGET_HOST.md"
echo "    - its AAP inventory + SSH credential"
echo "    - an Elastic IP, so the address stops moving on every stop"
