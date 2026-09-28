#!/usr/bin/env bash
# Shared by test and benchmark tasks; arguments remain arrays, never shell code.

positive_integer() {
  if [[ ! "$2" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s must be a positive integer (got %s)\n' "$1" "$2" >&2
    return 1
  fi
}

package_worker_args() {
  package_args=()
  local workers="${usage_package_workers:-${NPC_TEST_PACKAGE_WORKERS:-}}"
  if [[ -n "$workers" ]]; then
    positive_integer 'package workers' "$workers" || return
    package_args=(-p "$workers")
  fi
}

validate_budget() {
  local duration='^(([0-9]+([.][0-9]*)?|[.][0-9]+)(ns|us|µs|μs|ms|s|m|h))+$'
  if [[ "$2" =~ ^[1-9][0-9]*x$ ]] || { [[ "$2" =~ $duration ]] && [[ "$2" =~ [1-9] ]]; }; then
    return
  fi
  printf '%s must be a positive Go duration or iteration count, such as 30s or 100x\n' "$1" >&2
  return 1
}

# Listing through Go respects build constraints and does not recurse into worktrees.
# Capture the command separately so a failed build cannot become an empty success.
list_go_targets() {
  local kind="$1" selection="$2" listing
  if ! listing="$(go test -buildvcs=false ${package_args[@]+"${package_args[@]}"} -json -list "^${kind}" "$selection")"; then
    printf '%s\n' "$listing" >&2
    return 1
  fi
  printf '%s\n' "$listing" | jq -r --arg kind "$kind" '
    select(.Action == "output") | .Output |= rtrimstr("\n") |
    select(.Output | test("^" + $kind + "[^[:space:]]+$")) |
    [.Package, .Output] | @tsv' | LC_ALL=C sort -u
}
