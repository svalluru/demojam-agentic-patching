# Sourced, not run. Confirms oc is logged in to the cluster .env names
# before anything creates objects.
#
#   . "$REPO/lib/ocp-check.sh"
#   ocp_check_cluster "$ENV_FILE" || exit 1
#
# OCP_API_URL is mandatory. Without it there is nothing to compare the
# login against, and "probably the right cluster" is the assumption this
# exists to remove.
#
# oc acts on whichever cluster you last logged in to, from any terminal, and
# this setup invites switching: more than one lab, more than one machine.
# Every deploy script here creates namespaces, volumes, builds and routes,
# so pointing one at the wrong cluster does real work in the wrong place —
# a second Milvus somebody else then pays for, or a console deployed beside
# the wrong backing services. Checking costs one oc call.

_ocp_norm() {  # https://API.Example:6443/ -> api.example:6443
  local u="${1%/}"
  u="${u#https://}"; u="${u#http://}"
  [[ "$u" == *:* ]] || u="$u:6443"
  printf '%s' "$u" | tr '[:upper:]' '[:lower:]'
}

ocp_check_cluster() {
  local env_file="${1:-}" want have
  want="${OCP_API_URL:-}"
  if [[ -z "$want" && -n "$env_file" && -f "$env_file" ]]; then
    want="$(sed -n 's/^OCP_API_URL=//p' "$env_file" | tr -d "\"'" | tail -1)"
  fi

  if ! command -v oc >/dev/null 2>&1; then
    printf '  \033[31m✗\033[0m oc not found on PATH\n' >&2; return 1
  fi
  if ! have="$(oc whoami --show-server 2>/dev/null)" || [[ -z "$have" ]]; then
    printf '  \033[31m✗\033[0m not logged in — run: oc login %s\n' "${want:-<api-url>}" >&2
    return 1
  fi
  # A token that has expired still leaves a server in the kubeconfig, so
  # --show-server alone would pass. whoami is what actually authenticates.
  if ! oc whoami >/dev/null 2>&1; then
    printf '  \033[31m✗\033[0m logged in to %s but the token is no longer valid — log in again\n' "$have" >&2
    return 1
  fi

  if [[ -z "$want" ]]; then
    printf '  \033[31m✗\033[0m OCP_API_URL is not set in .env — nothing to check the login against\n' >&2
    printf '      set it to the cluster this setup belongs to, e.g. OCP_API_URL=%s\n' "$have" >&2
    return 1
  fi

  if [[ "$(_ocp_norm "$have")" != "$(_ocp_norm "$want")" ]]; then
    printf '  \033[31m✗\033[0m oc is logged in to the wrong cluster\n' >&2
    printf '      logged in : %s\n' "$have" >&2
    printf '      .env says : %s\n' "$want" >&2
    printf '      run: oc login %s   — nothing has been created\n' "$want" >&2
    return 1
  fi
  printf '  \033[32m✓\033[0m oc is on the cluster .env names (%s as %s)\n' "$have" "$(oc whoami)" >&2
}
