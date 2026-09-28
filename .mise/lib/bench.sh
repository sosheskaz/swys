#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/go-test.sh"
package_worker_args
mode="${1:-run}"
case "$mode" in
run | cpu | mem) ;;
*)
  printf 'unknown profile mode: %s (want cpu or mem)\n' "$mode" >&2
  exit 1
  ;;
esac
bench="${usage_bench-.}"
if [[ -z "$bench" ]]; then
  printf 'bench must not be empty\n' >&2
  exit 1
fi
budget="${usage_benchtime:-1s}"
count="${usage_count:-1}"
validate_budget benchtime "$budget"
positive_integer count "$count"
targets="$(list_go_targets Benchmark "${usage_package:-./...}")"
if [[ -z "$targets" ]]; then
  printf 'no runnable benchmarks match the package selection\n' >&2
  exit 1
fi
if [[ "${usage_list:-false}" == true ]]; then
  printf '%s\n' "$targets"
  exit
fi

output="$(mktemp "${TMPDIR:-/tmp}/npc-bench.XXXXXX")"
trap 'rm -f -- "$output"' EXIT
found=0
packages=()
while IFS= read -r package; do
  packages+=("$package")
done < <(cut -f1 <<<"$targets" | LC_ALL=C sort -u)

if [[ "$mode" == run ]]; then
  go test -buildvcs=false ${package_args[@]+"${package_args[@]}"} -run='^$' \
    -bench="$bench" -benchmem -benchtime="$budget" -count="$count" "${packages[@]}" | tee "$output"
  if grep -Eq '^Benchmark[^[:space:]]*[[:space:]]+[0-9]+[[:space:]]' "$output"; then
    exit
  fi
  printf 'no benchmarks ran for --bench=%s\n' "$bench" >&2
  exit 1
fi

for package in "${packages[@]}"; do
  # Retain the binary beside its profile; the full import path avoids collisions.
  directory="${usage_output_dir:-.artifacts/bench}/${package}/${mode}"
  mkdir -p "$directory"
  directory="$(cd "$directory" && pwd)"
  profile="${directory}/${mode}.prof"
  binary="${directory}/bench.test"
  printf '==> %s\n' "$package" >&2
  go test -buildvcs=false ${package_args[@]+"${package_args[@]}"} -run='^$' -bench="$bench" \
    -benchmem -benchtime="$budget" -count="$count" "-${mode}profile=$profile" -o "$binary" "$package" | tee "$output"
  if grep -Eq '^Benchmark[^[:space:]]*[[:space:]]+[0-9]+[[:space:]]' "$output"; then
    found=1
    printf 'Profile: %s\nBinary: %s\n' "$profile" "$binary"
    printf 'Inspect: go tool pprof %q %q\n' "$binary" "$profile"
  fi
done
if ((found == 0)); then
  printf 'no benchmarks ran for --bench=%s\n' "$bench" >&2
  exit 1
fi
