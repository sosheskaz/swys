# CLAUDE.md

## Project

`npc` is a Go CLI for operator-friendly cryptographic and X.509 tasks. It
uses Cobra and favors streaming I/O, small dependency and allocation footprints,
and explicit error handling.

## Commands

```fish
make build          # development binary
make build-release  # stripped, reproducible-path binary
make test           # unit tests
make test-race      # race detector
make lint           # configured golangci-lint suite
make check          # lint and unit tests
make bench          # all internal package benchmarks
```

## Architecture

- `cmd/` defines Cobra commands and owns CLI I/O setup, output encodings, and
  resource cleanup. Command handlers return errors through `RunE`.
- `internal/crypter/` implements streaming AES-CBC with IV-prefixed ciphertext
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
- Keep encryption and decryption streaming. Benchmark allocation changes before
  claiming a performance improvement.
- Add regression tests for boundary sizes, malformed ciphertext, output writer
  failures, and certificate-chain behavior.
- Run `make check` after changes; use `make test-race` for concurrency-sensitive
  work.
