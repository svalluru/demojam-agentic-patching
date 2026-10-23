#!/usr/bin/env bash
# Start the Lightwell dependency scanner on http://127.0.0.1:8790
#   ./start.sh          demo mode: recorded data, no network
#   ./start.sh --live   real GitHub and OSV.dev calls
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
case "${1:-}" in
  --live) export LIGHTWELL_MODE=live ;;
  --demo|"") ;;
  -h|--help) sed -n '2,5p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "unknown option: $1" >&2; exit 1 ;;
esac
exec python3 server.py
