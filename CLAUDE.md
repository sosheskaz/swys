# CLAUDE.md

## Project

`swys` is a Go CLI for operator-friendly cryptographic and X.509 tasks. It
uses Cobra and favors streaming I/O, small dependency and allocation footprints,
and explicit error handling.

## Commands

Tasks are managed by mise (`mise tasks` lists everything; scripts live in
`.config/mise/tasks/`). Tool versions are pinned in `.config/mise/config.toml` and shared with CI.

```fish
mise run build:dev       # development binary
mise run build:release   # stripped, reproducible-path binary
mise run test:unit       # unit tests (go test flags pass through after --)
mise run test:race       # race detector
mise run test:cover      # coverage run + HTML report
mise run lint:go         # configured golangci-lint suite
mise run lint:fix        # golangci-lint with auto-fixes
mise run check           # lint and unit tests
mise run bench           # all internal package benchmarks
mise run scan:vuln       # govulncheck vulnerability scan
mise run install:hooks   # install lefthook git hooks (once per clone)
```

## Architecture

- `cmd/` defines Cobra commands and owns CLI I/O setup, output encodings, and
  resource cleanup. Command handlers return errors through `RunE`.
- `internal/crypter/` implements authenticated AES-GCM as the default and
  streaming AES-CBC for compatibility. GCM buffers one bounded message so it
  can authenticate before releasing plaintext; CBC uses IV-prefixed ciphertext
  and PKCS#7 padding.
- `internal/asym/` parses, verifies, and formats X.509 certificates. TLS
  inspection deliberately completes the handshake without verification, then
  verifies the captured chain with the hostname and peer intermediates.
- `internal/sys/` provides process-wide logging.

## Engineering constraints

- Use `cmd.InOrStdin`, `cmd.OutOrStdout`, and `cmd.ErrOrStderr`; do not bypass
  Cobra's configured streams.
- Propagate and wrap I/O errors. Close output filters before their underlying
  files so buffered bytes are flushed.
- Keep CBC encryption and decryption streaming. Preserve GCM's 64 MiB bound and
  all-or-nothing authentication before plaintext output. Benchmark allocation
  changes before claiming a performance improvement.
- Add regression tests for boundary sizes, malformed ciphertext, output writer
  failures, and certificate-chain behavior. TESTING.md is the normative test
  policy: fixes ship with regression tests; coverage is maintained or
  increased by every change; crypto code gets adversarial-input tests first.
- Run `mise run check` after changes; use `mise run test:race` for
  concurrency-sensitive work.
