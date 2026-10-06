#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! -x $1 ]]; then
  printf 'usage: %s /absolute/path/to/swys\n' "$0" >&2
  exit 2
fi

swys_bin="$1"
interop_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scratch_dir="$(mktemp -d)"
trap 'rm -rf "$scratch_dir"' EXIT

for bits in 128 256; do
  case_dir="$scratch_dir/$bits"
  mkdir "$case_dir"
  head -c "$((bits / 8))" /dev/zero | tr '\000' 'B' >"$case_dir/key"
  printf '\000OpenPGP\n\377' >"$case_dir/plain"

  "$swys_bin" aes encrypt --wire-format openpgp --key "$case_dir/key" \
    --input "$case_dir/plain" --output "$case_dir/swys-wire"
  SWYS_INTEROP_SCRATCH="$scratch_dir" "$interop_dir/run.sh" \
    decrypt "/scratch/$bits/key" "/scratch/$bits/swys-wire" "/scratch/$bits/sequoia-opened"
  cmp "$case_dir/plain" "$case_dir/sequoia-opened"

  SWYS_INTEROP_SCRATCH="$scratch_dir" "$interop_dir/run.sh" \
    encrypt "/scratch/$bits/key" "/scratch/$bits/plain" "/scratch/$bits/sequoia-wire"
  "$swys_bin" aes decrypt --wire-format openpgp --key "$case_dir/key" \
    --input "$case_dir/sequoia-wire" --output "$case_dir/swys-opened"
  cmp "$case_dir/plain" "$case_dir/swys-opened"

  printf 'AES-%s Sequoia/SwYS bidirectional interoperability passed\n' "$bits"
done

# Synthetic password: generated per run, kept in scratch, passed to SwYS by environment.
password_dir="$scratch_dir/password"
mkdir "$password_dir"
head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$password_dir/password"
printf '\000password\n\377' >"$password_dir/plain"
SWYS_INTEROP_PASSWORD="$(cat "$password_dir/password")" "$swys_bin" aes encrypt \
  --password-env SWYS_INTEROP_PASSWORD --input "$password_dir/plain" --output "$password_dir/swys-wire"
SWYS_INTEROP_SCRATCH="$scratch_dir" "$interop_dir/run.sh" \
  password-decrypt /scratch/password/password /scratch/password/swys-wire /scratch/password/sequoia-opened
cmp "$password_dir/plain" "$password_dir/sequoia-opened"
SWYS_INTEROP_SCRATCH="$scratch_dir" "$interop_dir/run.sh" \
  password-encrypt /scratch/password/password /scratch/password/plain /scratch/password/sequoia-wire
SWYS_INTEROP_PASSWORD="$(cat "$password_dir/password")" "$swys_bin" aes decrypt \
  --password-env SWYS_INTEROP_PASSWORD --input "$password_dir/sequoia-wire" --output "$password_dir/swys-opened"
cmp "$password_dir/plain" "$password_dir/swys-opened"
printf 'AES-256 Argon2 password Sequoia/SwYS bidirectional interoperability passed\n'
