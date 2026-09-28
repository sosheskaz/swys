# Repository guidance

## Project and layout

NPC is a Go CLI for networking, protocols, cryptography, and X.509 tasks.
It uses Cobra; `mise.toml` defines the toolchain and task configuration.

- `cmd/` assembles and executes the root command. Each command family lives in
  `cmd/internal/commands/<family>`, owns its flags, validation, execution,
  and guides, and exposes a `NewCommand` builder.
- `cmd/internal/cli/` contains shared CLI support for I/O, encoding,
  completion, help, and signal handling; helpers here may use Cobra. Production
  command families must not import `cmd` or other families; shared CLI support
  must not import families.
  Domain packages under the top-level `internal/` remain independent of the
  command tree.
- `cmd/internal/testcmd/` contains test-only command harnesses and is not a
  production dependency.
  External test packages may use `cmd.NewCommand` to exercise the full CLI.
- `internal/crypter/` implements standard OpenPGP and Tink AES streaming.
- `internal/asym/` handles asymmetric keys and X.509 parsing, creation,
  verification, and formatting.
- `internal/netconn/` provides connection setup and stream/datagram transport;
  `internal/dnsquery/` implements DNS resolution.
- `internal/contextio/` handles cancellable reads and opens;
  `internal/securefile/` implements platform-specific private-file protections.
- `cmd/guides/` contains root and generated-command guides; each
  `cmd/internal/commands/<family>/guides/` directory contains that family's guides. Follow
  [the help authoring standard](docs/help-authoring.md) when changing them.

## Commands and validation

Use the repository's mise tasks; `mise tasks` lists them.

```fish
mise run build:dev
mise run test:unit -- -run TestName
mise run check
mise run test:race -- -shuffle=on
mise run test:fuzz
mise run bench
mise run scan:vuln
```

`mise run check` runs Go lint, platform-specific vet checks, coverage-reporter
tests, task-runner tests, and unit tests. Race tests, fuzz mutation, benchmarks,
vulnerability scanning, and changed-file configuration checks are separate CI checks.
Lefthook configures formatting and configuration checks in `lefthook.yml`.

Follow [TESTING.md](TESTING.md), the existing testing policy, with the segmented
authentication contract below applying to streaming AES. Exercise user-visible
behavior through the real root command and its I/O hooks. Use local servers and
temporary fixtures for tests. Run `mise run check` before pushing code changes
and race tests for concurrency or subprocess work.

Every material defect needs a regression test demonstrated red without the fix
and green with it. Distinguish established-contract defects from design flaws or
preference changes. Pure refactors may rely on existing tests; configuration and
instructions use native validation. Choose tests for distinct contracts and
credible failures, not exhaustive matrices or coverage percentages. Keep
fixtures small, consolidate related tests, and review assertion failure paths
for panics, blocked workers, and missed cleanup. Prefer deterministic coordination
and applicable facilities in the pinned Go version over custom timing machinery.

## Command behavior

- Register command-specific preparation with the shared `commandio` lifecycle.
  Keep family-specific validation and state in the owning command package;
  preserve shared flag, completion, and I/O behavior.
- Use Cobra's configured input, output, and error streams. Preserve error
  identity when wrapping failures, and close output filters before their files.
- Preserve validation before output-file mutation and the existing same-file
  and sensitive-output protections.
- Add or update the corresponding embedded guide whenever a public command
  or its behavior changes. Aliases share the canonical command's guide.

## Cryptographic and I/O contracts

- Default AES encryption uses binary OpenPGP RFC 9580 AES-GCM. `--wire-format
tink` selects native Tink AES-GCM-HKDF. Decryption requires explicit format
  selection and verifies final authentication and EOF. Earlier authenticated
  plaintext may remain after a later failure.
- Historical NPC v1/v2, raw GCM, and CBC ciphertext require an older binary.
- Passwords use native OpenPGP AES-256 SKESK v6 with Argon2id and the SEIPDv2
  reader. Check stored KDF costs, per wrapper and cumulatively, before asking
  for a password, deriving, or opening output; there is no override. Password
  acquisition must not consume payload stdin or write secrets to output.
- Preserve the distinction between borrowed and owned inputs in
  `internal/contextio/`: cancellation must not close a borrowed input.
- Support performance claims with representative before-and-after benchmarks.
