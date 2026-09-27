#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! -x $1 ]]; then
  printf 'usage: %s /absolute/path/to/npc\n' "$0" >&2
  exit 2
fi

npc_bin="$1"
interop_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scratch_dir="$(mktemp -d)"
trap 'rm -rf "$scratch_dir"' EXIT

for bits in 128 256; do
  case_dir="$scratch_dir/$bits"
  mkdir "$case_dir"
  head -c "$((bits / 8))" /dev/zero | tr '\000' 'B' >"$case_dir/key"
  printf '\000OpenPGP\n\377' >"$case_dir/plain"

  "$npc_bin" aes encrypt --wire-format openpgp --keyfile "$case_dir/key" \
    --input "$case_dir/plain" --output "$case_dir/npc-wire"
  NPC_INTEROP_SCRATCH="$scratch_dir" "$interop_dir/run.sh" \
    decrypt "/scratch/$bits/key" "/scratch/$bits/npc-wire" "/scratch/$bits/sequoia-opened"
  cmp "$case_dir/plain" "$case_dir/sequoia-opened"

  NPC_INTEROP_SCRATCH="$scratch_dir" "$interop_dir/run.sh" \
    encrypt "/scratch/$bits/key" "/scratch/$bits/plain" "/scratch/$bits/sequoia-wire"
  "$npc_bin" aes decrypt --wire-format openpgp --keyfile "$case_dir/key" \
    --input "$case_dir/sequoia-wire" --output "$case_dir/npc-opened"
  cmp "$case_dir/plain" "$case_dir/npc-opened"

  printf 'AES-%s Sequoia/NPC bidirectional interoperability passed\n' "$bits"
done
