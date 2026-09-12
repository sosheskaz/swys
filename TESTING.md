# Testing Policy

This document is normative. The test suite is a product feature of npc, not
overhead: for a tool whose job is cryptographic and wire-level correctness,
an untested path is an unshipped path. The suite that exists is maintained
and expanded — it is never weakened to make a change land.

## Ground rules

1. **Every fix ships with a regression test.** No exceptions. The test must
   fail on the pre-fix code (red) and pass on the fix (green) — verify this
   by actually reverting the fix once, not by reasoning about it. Name tests
   after the behavior they pin (`TestDecryptPreservesReadErrors`), not the
   bug number.
2. **Coverage is maintained or increased by every change.** The CI coverage
   report posts total and per-package deltas versus main on every PR; a
   negative total delta requires justification in the PR description (e.g.
   deleting a well-tested feature), and "I'll add tests later" is not a
   justification. New code lands with its tests in the same PR.
3. **Failing tests are fixed at the root or escalated.** Never deleted,
   skipped, or loosened to pass. If a test is wrong, the PR that changes it
   must explain why the pinned behavior was wrong.
4. **Tests run raced and shuffled.** CI runs `-race` and `-shuffle=on` on
   every PR; tests must not depend on execution order or unsynchronized
   shared state. Package-global mutation in a test requires cleanup
   (`t.Cleanup`) and a comment noting the parallelism constraint.

## What every change tests

The baseline expectations for any code path, established by the existing
suite and carried forward:

- **Boundary sizes**: 0 bytes, 1 byte, one block, block ± 1, internal buffer
  size ± 1, and multi-buffer inputs. Off-by-one bugs live at boundaries;
  tables make covering them cheap.
- **Malformed inputs**: truncated, empty, wrong-type, and garbage inputs
  produce wrapped, descriptive errors — never panics, never silent success,
  never partial output presented as complete.
- **I/O fault injection**: a reader failing mid-stream surfaces as an I/O
  error (not misreported as data corruption); a failing writer propagates
  its error. Output filters flush and close before their underlying files.
- **Command-level behavior**: user-visible behavior is tested through the
  real root command (`executeRoot` in `cmd/root_test.go`) so flag parsing,
  I/O hooks, and cleanup lifecycles are exercised, not mocked away.

## Cryptographic code: adversarial tests come first

Any cryptographic implementation (cipher modes, padding, key handling,
certificate verification, TLS capture) is accompanied by tests that assume
hostile input — written **ahead of** or alongside the implementation, not
retrofitted:

- **Tampering**: for authenticated or signed constructions such as GCM,
  flipping any single bit in every component (nonce, body, tag, associated
  data) must fail cleanly with **zero plaintext bytes reaching the output
  writer** — check the writer, not just the error. CBC is unauthenticated;
  test its structural and compatibility contracts without claiming universal
  tamper detection.
- **Truncation and structure attacks**: truncated IV/nonce/tag, non-block-
  multiple ciphertext, empty input, and inputs whose framing lies about
  their length are all explicit table cases.
- **Padding**: invalid, zero-length, over-length, and inconsistent padding
  variants are rejected without oracle-friendly behavioral differences.
- **Known-answer tests**: where an algorithm has published vectors (NIST
  CAVP, RFC test vectors), wire them in as table-driven tests. Vectors are
  the ground truth that separates "round-trips with itself" from "actually
  implements the algorithm" — a round-trip test alone proves nothing about
  correctness.
- **Wrong-key / wrong-mode**: authenticated GCM decryption with the wrong key,
  AAD, or mode fails with a clear error and emits nothing. CBC is
  unauthenticated and has no universal wrong-key or wrong-mode failure
  guarantee; test only its structural and compatibility contracts.
- **Certificate chains**: expired, name-mismatched, self-signed-in-chain,
  wrong-intermediate, and comma/escaping edge cases in distinguished names
  are regression-pinned behaviors.

## Benchmarks

### What gets benchmarked

A package must carry benchmarks when any of these hold:

- It processes **unbounded or caller-controlled input sizes** (streams,
  files, network payloads) — the crypter and future compression/transport
  layers.
- It sits on a **hot path** where npc's low-allocation goals apply
  (encoding pipelines, formatters invoked per-certificate, buffer
  management).
- It makes a **tunable performance decision** (buffer sizes, pooling) —
  the benchmark is what justifies the tuning, and it exercises the
  production code path, never a copy of it (copies drift).

### How

- Always `-benchmem`. Report `B/op` and `allocs/op`, not just ns/op.
- **Unbounded-input code must demonstrate bounded memory**: benchmark across
  a size sweep (e.g. 4KB → 64MB) and confirm `B/op` and `allocs/op` stay
  ~flat as input grows — that is the streaming guarantee made measurable.
  Allocation counts that scale with input size are a bug, both for memory
  and for the GC pressure they generate; per-chunk work must not allocate
  per iteration. Authenticated GCM is deliberately single-shot rather than
  streaming: benchmark its size-proportional allocation through the enforced
  64 MiB limit and retain its all-or-nothing plaintext-release guarantee.
- Performance claims require evidence: `mise run bench` before and after,
  compared with `benchstat`, numbers included in the PR description. No
  claim without a comparison.
- Profiling is per-package and discovery-driven: `mise run bench:cpu` /
  `bench:mem` find every package containing Benchmark functions
  automatically — adding benchmarks to a package requires no task or CI
  changes.
- CI runs the full benchmark suite with `-benchtime=1x` on every PR as a
  smoke test: benchmarks are code and rot like code; they must at least
  compile and run.

Published cryptographic vectors may contain public example keys and are safe to
commit as algorithm conformance data. Secret or deployment key material is
never fixture data; generate ephemeral private fixtures during test setup.

## Enforcement map

| Policy                                | Enforced by                                                                                                         |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Suite passes, raced + shuffled        | `ci.yml` test steps on every PR                                                                                     |
| Coverage maintained or increased      | CI sticky PR comment (delta vs main); reviewer blocks unjustified drops                                             |
| Benchmarks don't rot                  | CI benchmark smoke run (`-benchtime=1x`)                                                                            |
| Vulnerable dependencies               | `govulncheck` per PR + weekly scheduled run                                                                         |
| Config/workflow validity              | lefthook (local + changed-files CI)                                                                                 |
| No secret/deployment keys in fixtures | `.gitignore` patterns and review; provenance-backed published public vector and compatibility keys may be committed |

Run `mise run check` locally before pushing; `mise run test:race` for
anything concurrency-adjacent.

## Fuzzing

Fuzz seed corpora run with the ordinary unit and race suites. Run mutation
campaigns separately, selecting one target per invocation:

```sh
mise exec -- go test ./internal/asym -run='^$' -fuzz='^FuzzParseKey$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/asym -run='^$' -fuzz='^FuzzOpenSSHPrivateEnvelope$' -fuzztime=60s -parallel=2
mise exec -- go test ./internal/asym -run='^$' -fuzz='^FuzzOpenSSHAuthorizedKey$' -fuzztime=60s -parallel=2
mise exec -- go test ./internal/pemstrict -run='^$' -fuzz='^FuzzDecode$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzParsePEMCertificates$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzBase64URLDecoder$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/crypter -run='^$' -fuzz='^FuzzAESCBCDecrypt$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/crypter -run='^$' -fuzz='^FuzzAESGCMDecrypt$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/netconn -run='^$' -fuzz='^FuzzReadDatagram$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/netconn -run='^$' -fuzz='^FuzzReadDatagramInputFailure$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/netconn -run='^$' -fuzz='^FuzzRelayPreservesBidirectionalBytesWithoutHalfClose$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/netconn -run='^$' -fuzz='^FuzzRelayPreservesPrefixesBeforeInputFailure$' -fuzztime=30s -parallel=2
```

These targets bound generated input sizes and check key identity, certificate
order and DER preservation, base64url acceptance against the standard library
(including one-byte reads), and authenticated decryption against an independent
standard-library wire decoder. Authentication and structure failures in
authenticated modes must emit no plaintext. The unauthenticated CBC
compatibility mode may emit previously decrypted buffer prefixes before a later
structure or padding failure; its target checks that streamed prefix against
independent CBC decryption. Parser round trips cover successfully parsed
artifacts; they do not prove rejection of every invalid input.

The OpenSSH targets seed generated keys and exercise decoded private envelopes
and public-entry framing. Successful parses must preserve key identity through
canonical serialization; trailing envelope bytes, extra public entries, and
malformed lines must be rejected. Deterministic mutations additionally check
duplicated public/private fields, Ed25519 seed consistency, ECDSA type labels,
and private-block alignment. The strict PEM target checks successful first-block
decoding against `encoding/pem`, exact suffix preservation, unchanged input and
failure returns, and that a decoded block never originates at a later BEGIN
line. Because `encoding/pem` skips malformed blocks, it cannot witness
strictness on its own: malformed first blocks are framed in four shapes — a body
byte outside the base64 alphabet, a missing END line, an END line naming another
type, and truncation after the BEGIN line — each followed by a generated number
of valid blocks, and must be rejected instead of skipped.

Keep minimized failures in the package's `testdata/fuzz/<target>` directory after
reviewing their contents. Never add real private keys or deployment data.
