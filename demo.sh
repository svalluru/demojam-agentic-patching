#!/usr/bin/env bash
# Start the console in offline demo mode.
#
#   ./demo.sh            stored defaults only — no cluster, no .env, no network
#   ./demo.sh --live     use the real backends from .env, falling back per step
#
# Offline mode touches nothing: no Insights, no risk model, no RAG, no Ansible
# Orchestrator. Every step serves stored defaults from fallbacks.py and the
# console labels all of them. Nothing is patched — approving a host resolves a
# simulated run that exists in no AO instance.
set -euo pipefail

cd "$(dirname "$0")"

BACKEND_PORT=${BACKEND_PORT:-8787}
FRONTEND_PORT=${FRONTEND_PORT:-8788}

# Checked up front: an older interpreter fails deep inside an import with a
# SyntaxError that says nothing about the version.
for cmd in python3 curl lsof; do
  command -v "$cmd" >/dev/null || { echo "error: '$cmd' is required but not installed" >&2; exit 1; }
done
python3 - <<'PY' || exit 1
import sys
if sys.version_info < (3, 10):
    sys.exit(f"error: Python 3.10+ required, found {sys.version.split()[0]} "
             f"at {sys.executable}")
PY

if [[ "${1:-}" == "--live" ]]; then
  export OFFLINE=0
  MODE="live (per-step fallback if a backend is down)"
  [[ -f .env ]] || { echo "error: --live needs a .env (cp .env.example .env)" >&2; exit 1; }
else
  export OFFLINE=1
  MODE="offline — stored defaults, nothing is patched"
fi

# A previous run left on these ports would silently serve stale code.
for port in "$BACKEND_PORT" "$FRONTEND_PORT"; do
  pid=$(lsof -t -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)
  [[ -n "$pid" ]] && { echo "stopping old process on :$port ($pid)"; kill "$pid"; sleep 1; }
done

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

FRONTEND_PORT="$FRONTEND_PORT" ./agentic-patching.py serve >/tmp/demo-backend.log 2>&1 &
PIDS+=($!)

# --env is harmless when absent and is what supplies credentials in --live.
( cd frontend && python3 server.py ${CVE_LIST_LOCAL:+--env ../.env} \
    >/tmp/demo-frontend.log 2>&1 ) &
PIDS+=($!)

for _ in $(seq 1 20); do
  if curl -sf -o /dev/null "http://127.0.0.1:$FRONTEND_PORT/" 2>/dev/null; then
    cat <<EOF

  Agentic Patching Console
  mode : $MODE
  url  : http://127.0.0.1:$FRONTEND_PORT
  logs : /tmp/demo-backend.log  /tmp/demo-frontend.log

  Pick a CVE, Assess CVE Impact, dispatch the plan, then Approve.
  Ctrl-C to stop.

EOF
    wait
  fi
  sleep 1
done

echo "error: console did not come up — see /tmp/demo-backend.log" >&2
tail -20 /tmp/demo-backend.log /tmp/demo-frontend.log >&2
exit 1
