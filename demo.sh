#!/usr/bin/env bash
# Start the console. Two modes, and nothing in between.
#
#   ./demo.sh            demo — staged data for every step, no endpoint is
#                        contacted. No cluster, no .env, no network. Nothing
#                        is patched: approving a host resolves a simulated
#                        run that exists in no Automation Orchestrator.
#
#   ./demo.sh --live     live — real endpoints only, no fallback anywhere. An
#                        unreachable service fails the run and names it.
#                        Needs a filled-in .env and refuses to start without
#                        one, because every step would fail at the first
#                        call.
#
# There is deliberately no third mode mixing real endpoints with stored
# defaults: a patch plan that looks measured but is partly fabricated is the
# one thing an operator must not be handed to approve.
set -euo pipefail

cd "$(dirname "$0")"

# One port: the page, its API and the dependency scanner are all served by
# agentic-patching.py. Exported because that process reads it from the
# environment.
CONSOLE_PORT=${CONSOLE_PORT:-8788}
export CONSOLE_PORT
NOTE=""          # an extra line in the startup banner, when there is one

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
  export MODE=live
  MODE_LABEL="live — real endpoints only, no fallback"
  # Live mode has no fallback: an unreachable service fails the run. So an
  # empty .env is no longer a half-working state that merely looks odd on
  # screen — it is a run that cannot get past its first step. Refuse here,
  # where the reason is obvious, rather than at the first assessment.
  if [[ ! -f .env ]]; then
    if [[ -f .env.example ]]; then
      cp .env.example .env
      echo >&2 "created .env from .env.example — gitignored, never commit it."
    fi
    cat >&2 <<'EOF'
error: live mode needs real endpoints and .env is empty or missing.

  LIGHTSPEED_CLIENT_ID + _SECRET      the CVE list and the per-CVE detail
  RISK_URL                            per-host risk scores
  LLAMA_STACK_URL + VECTOR_DB_ID      per-host patch history
  AO_URL + AO_USERNAME + AO_PASSWORD  the only keys that make a patch real

Fill those in and run ./demo.sh --live again, or run ./demo.sh on its own for
the staged demo, which needs none of them.
EOF
    exit 1
  fi
else
  export MODE=demo
  MODE_LABEL="demo — staged data, no endpoint contacted, nothing is patched"
fi

# A previous run left on this port would silently serve stale code. 8787 is
# also cleared: it is where a console from before the single-port change ran
# its backend, and one left behind there is confusing to find later.
# Unquoted on purpose: lsof prints one PID per line and there can be more
# than one, which `kill "$pid"` would pass as a single bogus argument.
for port in "$CONSOLE_PORT" 8787; do
  pid=$(lsof -t -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)
  # shellcheck disable=SC2086
  [[ -n "$pid" ]] && { echo "stopping old process on :$port ($pid)"; kill $pid; sleep 1; }
done

PIDS=()
STOPPING=0
LOG=/tmp/demo-console.log

# Kills a child and anything it started.
kill_tree() {
  local p=$1 c
  for c in $(pgrep -P "$p" 2>/dev/null || true); do kill_tree "$c"; done
  kill "$p" 2>/dev/null || true
}

cleanup() {
  [[ "$STOPPING" == 1 ]] && return 0      # EXIT fires after INT; only once
  STOPPING=1
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill_tree "$p"; done
}

# Ctrl-C has to end the script, not just the server. It used to run cleanup
# and then let the wait loop below carry on, so the script sat there with
# nothing to serve, spun out its twenty retries, printed "console did not
# come up" — a misleading error for a perfectly normal stop — and exited 1.
# Worse, `wait` did not reliably yield to the trap at all: Ctrl-C could leave
# the script *and* the server running, with no way back to a prompt except
# closing the window. Hence the sleep loop further down instead of `wait`.
on_stop() {
  cleanup
  printf '\n  stopped. Run ./demo.sh again in this terminal when you want it back.\n\n'
  trap - EXIT
  exit 0
}
trap cleanup EXIT
trap on_stop INT TERM

./agentic-patching.py serve >"$LOG" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 20); do
  if curl -sf -o /dev/null "http://127.0.0.1:$CONSOLE_PORT/" 2>/dev/null; then
    cat <<EOF

  Agentic Patching Console
  mode : $MODE_LABEL
  url  : http://127.0.0.1:$CONSOLE_PORT
  scan : http://127.0.0.1:$CONSOLE_PORT/lightwell/  (dependency scanner)
  log  : $LOG

  Pick a CVE, Assess CVE Impact, dispatch the plan, then Approve.
  Ctrl-C to stop — the terminal stays, so you can start it again.

EOF
    # Deliberately not `wait`. Bash will not reliably run the INT trap while
    # blocked in it, which is what left Ctrl-C unable to stop this script.
    # A sleep loop is interruptible: the signal lands, on_stop runs, done.
    while :; do
      for p in "${PIDS[@]}"; do
        kill -0 "$p" 2>/dev/null || break 2   # the server died on its own
      done
      sleep 1
    done
    echo >&2
    echo "error: the console stopped on its own — last lines of $LOG:" >&2
    tail -n 20 "$LOG" >&2
    exit 1
  fi
  sleep 1
done

echo "error: console did not come up — see $LOG" >&2
tail -n 20 "$LOG" >&2
exit 1
