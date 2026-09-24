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

## Assertion style

Use Testify `assert` for independent checks and `require` for prerequisites
whose failure makes later checks invalid. Put expected values before actual
values, and retain useful case context in failure messages. Keep plain Go
checks when they express the condition more clearly.

Preserve the original comparison semantics: error identity, ordering,
nil versus empty values, and exact bytes matter. Prefer `ErrorIs` or `ErrorAs`
to matching error text when testing error identity or type.

Call `require` only from the goroutine running the test or subtest. Collect
worker results through the existing synchronization before asserting on them.
Do not replace deterministic coordination or `testing/synctest` with polling
assertions. Keep assertion work outside timed benchmark loops.

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

## Curated help guides

Every public command added to the initialized Cobra tree ships with its
embedded Markdown guide in the same change. The coverage test compares the
command tree and embedded mapping in both directions, so a missing guide and a
stale guide file both fail. Generated public commands, including `help`,
`completion`, and each completion shell, are covered. Aliases resolve through
the command tree and share the canonical guide. Hidden and deprecated commands
are the only standing exclusions; any broader exclusion must be narrow,
documented, and tested.

When command behavior changes, update every affected guide example and keep at
least one representative documented workflow executable through the real root
command. Use temporary artifacts and local servers where setup is required.
Select those workflows intentionally; tests never discover and execute
arbitrary Markdown fences.

Rendering tests exercise both plain and rich output. Golden fixtures cover a
root page, an intermediate branch, a leaf, and every supported Markdown
construct. Plain output must contain no NPC-generated ANSI controls or leaked
heading, emphasis, fence, or link presentation syntax; code punctuation and
visible link destinations remain intact in plain output. Rich links use clickable
labels without duplicate visible URLs, close before unrelated text and at line
boundaries, and do not consume layout columns. Phrase styling includes internal
spaces. Unsupported Markdown is an error and
must never fall back to dumping source.

Command-lifecycle tests cover canonical and alias navigation, invalid and
surplus path components, reference `--help`, writer failures, and isolation
from target command handlers, hooks, stdin, output files, and network work.
Rendering-policy tests cover every direct-terminal, pager, redirect, explicit
override, `NO_COLOR`, and `TERM=dumb` branch independently of the test runner's
terminal. Pager tests use local helper processes and include quoted arguments,
environment inheritance, startup fallback, successful early exit and broken
pipe handling, nonzero exit, and process reaping. Run `mise run test:race` for
changes to pager or subprocess behavior.

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
  per iteration. The default AES-GCM-HKDF stream uses bounded segments; report
  cumulative allocation separately from peak memory. Raw GCM remains
  single-message with a 64 MiB limit and whole-message authentication.
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
| Portable fuzz targets mutate          | CI discovery-driven smoke campaign (`-fuzztime=100x` per target)                                                    |
| Vulnerable dependencies               | `govulncheck` per PR + weekly scheduled run                                                                         |
| Config/workflow validity              | lefthook (local + changed-files CI)                                                                                 |
| No secret/deployment keys in fixtures | `.gitignore` patterns and review; provenance-backed published public vector and compatibility keys may be committed |

Run `mise run check` locally before pushing; `mise run test:race` for
anything concurrency-adjacent.

## Fuzzing

Fuzz seed corpora run with the ordinary unit and race suites. CI also discovers
every portable target declared in a `*_fuzz_test.go` artifact and runs each with
a fixed `-fuzztime=100x` budget through `mise run test:fuzz`.
Platform-constrained targets remain seed-corpus tests on matching runners. This
bounded smoke campaign catches harness rot and shallow regressions; use the
longer mutation campaigns below for meaningful exploration, selecting one target
per invocation:

```sh
mise exec -- go test ./internal/asym -run='^$' -fuzz='^FuzzParseKey$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/asym -run='^$' -fuzz='^FuzzFormatFingerprint$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/asym -run='^$' -fuzz='^FuzzEscapeDiagnosticValue$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/asym -run='^$' -fuzz='^FuzzCertificateJSON$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/asym -run='^$' -fuzz='^FuzzOpenSSHPrivateEnvelope$' -fuzztime=60s -parallel=2
mise exec -- go test ./internal/asym -run='^$' -fuzz='^FuzzOpenSSHAuthorizedKey$' -fuzztime=60s -parallel=2
mise exec -- go test ./internal/pemstrict -run='^$' -fuzz='^FuzzDecode$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzParsePEMCertificates$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzByteEncodingRoundTrip$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzByteDecoders$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzStripNewlinesInputFailure$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzParseALPN$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzEscapeNetworkDiagnosticValue$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzBase64URLDecoder$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzReadArtifact$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzHTTPField$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzParseHTTPHeaders$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzHTTPDecodedBody$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzSupportedHTTPContentCodings$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzWriteHTTPJSONResponse$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzWriteHTTPHead$' -fuzztime=30s -parallel=2
mise exec -- go test ./cmd -run='^$' -fuzz='^FuzzHTTPTraceText$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/crypter -run='^$' -fuzz='^FuzzAESCBCDecrypt$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/crypter -run='^$' -fuzz='^FuzzAESGCMDecrypt$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/crypter -run='^$' -fuzz='^FuzzUnpadPKCS7$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/netconn -run='^$' -fuzz='^FuzzReadDatagram$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/netconn -run='^$' -fuzz='^FuzzReadDatagramInputFailure$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/netconn -run='^$' -fuzz='^FuzzRelayPreservesBidirectionalBytes$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/netconn -run='^$' -fuzz='^FuzzRelayPreservesPrefixesBeforeInputFailure$' -fuzztime=30s -parallel=2
mise exec -- go test ./internal/securefile -run='^$' -fuzz='^FuzzDarwinReturnedCommonAttributes$' -fuzztime=30s -parallel=2
```

The artifact reader target exercises contiguous and one-byte reads at generated
size limits, verifies the single-byte overflow probe does not over-read, and
requires partial read failures to preserve their error identity without
returning buffered artifact bytes.

These targets bound generated input sizes and check key identity, certificate
order and DER preservation, base64url acceptance against the standard library
(including one-byte reads), and authenticated decryption against an independent
standard-library wire decoder. Authentication and structure failures in
authenticated modes must emit no plaintext. The unauthenticated CBC
compatibility mode may emit previously decrypted buffer prefixes before a later
structure or padding failure; its target checks that streamed prefix against
independent CBC decryption. Parser round trips cover successfully parsed
artifacts; they do not prove rejection of every invalid input. The ALPN target
uses an independently structured delimiter oracle to check ordered opaque
protocol bytes, empty elements, surrounding Unicode whitespace, and the TLS
one-byte length boundary. The network diagnostic target pins the escaping of
peer-controlled SNI against an independent rune-by-rune reference escaper:
printable runes pass through, the short forms and the `\xNN`, `\uNNNN`, and
`\UNNNNNNNN` escapes match Go's own spelling down to hex-digit case, and bytes
outside a valid encoding keep their own value. Output must also remain one
printable line and recover its exact original bytes through Go string
unquoting, but those invariants hold for any `strconv.Quote` body; exact
equality with the reference is what a later implementation cannot weaken.
Deterministic client and listener tests require negotiated ALPN diagnostics to
apply the same escaping.

Peer-supplied certificate DER is driven through parsing and the JSON formatter.
Successful renders must survive a decode: the serial parses back as hex to the
same integer, the signature and SPKI base64-decode to the same bytes, and both
fingerprints match an independently derived colon-hex encoding. Chain
verification is pinned to an explicit root pool and `CurrentTime` because the
fuzzing engine assumes targets are deterministic.

The HTTP response head and trace targets render peer-controlled header names,
header values, request targets, and negotiated TLS metadata. Neither may leave
its line: output stays valid UTF-8 with no raw control characters, the head
occupies exactly one line per emitted header value between its status line and
blank separator, and every trace line classifies as a numbered hop summary or
one of that hop's declared fields in order. Names and values already made of
printable runes must render verbatim, which pins content without restating the
escaper. Trace hops are built from generated timestamps rather than wall-clock
time. The trace target renders the textual summary; the certificate chain a hop
captures reaches JSON output only, and is covered by the certificate target.

The PKCS#7 padding target states the contract independently of how the pad
length is derived: a successful result is a prefix of its input whose removed
suffix consists entirely of bytes equal to that suffix's own length, and a
separate dimension supplies independently padded messages so an implementation
that rejected everything could not pass.

The asymmetric formatting targets preserve exact fingerprint byte ordering.
`FuzzEscapeDiagnosticValue` requires the escaper's output to remain valid UTF-8
and free of non-printing runes. Printable diagnostic values are preserved,
while escaping is idempotent.

The byte-encoding targets compare every distinct registered encoder and decoder
with the standard library, including arbitrary binary input, independently
varied incremental writes and wrapped lines, one-byte reads, invalid-input
prefixes, and source errors returned with data. Decoder failures may expose the
prefix produced by the corresponding streaming standard-library decoder.

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
of valid blocks, and must be rejected instead of skipped. When trailing blocks
are present the target first witnesses that `encoding/pem` does decode one of
them, so the rejection shows a skip was refused rather than that there was
nothing to skip to.

The relay targets check that both directions preserve their exact bytes across
generated chunk sizes and that the connection is closed once. Half close is a
generated dimension rather than a fixed argument: because `Relay` races the two
directions and only the input-first ordering reaches the half-close decision,
the fixture holds the peer direction open until `CloseWrite` runs. That forces
the ordering, so the target requires exactly one half close when it is asked
for and none when it is not. A failed input copy returns before that decision,
so its target requires no half close under either setting.

The Darwin attribute-response target, built only on darwin, re-derives
acceptance from the response bytes instead of merely checking for panics: the
header must be present, the reported size must be at least the header and no
larger than the buffer, and the returned-attributes bit must be set. Accepted
responses return exactly the common-attribute word the buffer carries; rejected
ones return zero and a malformed-response error.

Keep minimized failures in the package's `testdata/fuzz/<target>` directory after
reviewing their contents. Never add real private keys or deployment data.
