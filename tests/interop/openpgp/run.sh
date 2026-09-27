#!/usr/bin/env bash
set -euo pipefail

interop_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scratch_dir="${NPC_INTEROP_SCRATCH:-$interop_dir}"
cache_dir="${NPC_INTEROP_CACHE_DIR:-${TMPDIR:-/tmp}/npc-openpgp-interop-cargo/$(uname -m)}"
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  printf 'Docker CLI and running daemon are required for Sequoia interoperability tests\n' >&2
  exit 2
fi
mkdir -p "$cache_dir/home" "$cache_dir/target"

docker run --rm \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$interop_dir,dst=/work" \
  --mount "type=bind,src=$scratch_dir,dst=/scratch" \
  --mount "type=bind,src=$cache_dir/home,dst=/cargo-home" \
  --mount "type=bind,src=$cache_dir/target,dst=/cargo-target" \
  --workdir /work \
  --env CARGO_HOME=/cargo-home \
  --env CARGO_TARGET_DIR=/cargo-target \
  'rust:1.90.0@sha256:e227f20ec42af3ea9a3c9c1dd1b2012aa15f12279b5e9d5fb890ca1c2bb5726c' \
  cargo run --locked -- "$@"
