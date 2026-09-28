# Testing Policy

This document is normative. Tests protect NPC's observable cryptographic,
wire-level, and command behavior. Choose focused evidence for the change;
more assertions, fixtures, or coverage do not automatically mean better tests.

## Ground rules

1. **Every material defect has a regression test.** A defect violates an
   established behavior contract; a design flaw or preference change is not
   automatically a defect. Demonstrate that the test fails without the fix
   and passes with it. Name tests after the behavior they protect, not the bug
   number. Existing tests and native validation may be sufficient for pure
   refactors, configuration, and instruction changes.
2. **Coverage is a review signal, not a test quota.** Investigate unexpected
   total and per-package deltas, including nondeterministic execution. Explain
   meaningful losses in the PR; do not add redundant tests just to raise a
   percentage. New behavior and its relevant tests land together.
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

## Choose proportionate tests

Start with the observable contract and a credible failure mode. Each new case
should protect a distinct behavior. Prefer a representative consumer example
plus focused lower-level coverage over repeating the same cases at every layer.
For configuration and instructions, use native syntax, schema, and consumer
checks; do not write tests that merely restate checked-in values.

Use the following surfaces where relevant, not as a mandatory matrix for every
change:

- **Boundary sizes**: select meaningful block, buffer, and stream boundaries,
  including empty or multi-buffer input where those exercise distinct behavior.
- **Malformed inputs**: untrusted truncated, wrong-type, or garbage input must
  not panic or present partial output as complete. Preserve documented streaming
  contracts, including already-authenticated plaintext after later failure.
- **I/O failures**: verify error identity and output lifecycle when the changed
  path reads, writes, flushes, or closes resources. Inject failures at meaningful
  boundaries instead of every possible call count.
- **Command behavior**: exercise public flags, I/O hooks, and cleanup through
  the real command lifecycle. Use `cmd.NewCommand` for root integration and
  external family consumer tests with `cmd/internal/testcmd` for focused cases.

Keep fixtures local and small. Extract a helper when it clarifies repeated
setup, not to build a general test framework. Use tables for cases that share
setup and assertions; avoid cross-products of unrelated dimensions. Add related
tests to an existing file before creating another tiny artifact.

Review failure paths, not only green runs. A failed prerequisite must not lead
to a panic, a blocked channel receive, a leaked worker, or skipped cleanup.
Register cleanup before assertions can terminate the test, and preserve useful
independent checks when continuation is safe. Never place a parent assertion
before the parallel subtests whose results it checks.
For shell tests, verify that failed assertions exit on supported Bash versions;
`set -e` alone is not an assertion mechanism.

Prefer deterministic synchronization to sleeps and polling. Consult the pinned
Go version's documentation for applicable standard-library facilities such as
`testing/synctest` before writing custom timing machinery. Use it for suitable
in-process concurrency, not as a replacement for real OS or network integration.

## Curated help guides

Every public command added to the initialized Cobra tree ships with its
embedded Markdown guide in the same change. The coverage test compares the
command tree and embedded mapping in both directions, so a missing guide and a
stale guide file both fail. Generated public commands, including `help`,
`completion`, and each completion shell, are covered. Aliases resolve through
the command tree and share the canonical guide. Hidden and deprecated commands
are the only standing exclusions; any broader exclusion must be narrow,
documented, and tested.
Root and generated-command guides live in `cmd/guides/`; family guides live in
their owning `cmd/internal/commands/<family>/guides/` directory.

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

- **Tampering**: for authenticated or signed constructions, flipping bits in
  headers, ciphertext, tags, or associated data must fail cleanly. OpenPGP and
  Tink streams release only authenticated chunks: the failing chunk emits no
  plaintext, but earlier authenticated plaintext may remain. Check the output
  writer and error, including failure of the final authentication tag.
- **Truncation and structure attacks**: truncated headers, ciphertext, and
  final tags; empty input; invalid declared parameters; and trailing packets
  or bytes are explicit table cases.
- **Padding**: for constructions that use padding, invalid, zero-length,
  over-length, and inconsistent variants are rejected without oracle-friendly
  behavioral differences.
- **Known-answer tests**: where an algorithm has published vectors (NIST
  CAVP, RFC test vectors), wire them in as table-driven tests. Vectors are
  the ground truth that separates "round-trips with itself" from "actually
  implements the algorithm" — a round-trip test alone proves nothing about
  correctness.
- **Wrong-key / wrong-format**: OpenPGP and Tink decryption with the wrong key,
  selected wire format, or Tink AAD fails with a clear error. No plaintext from
  an unauthenticated chunk reaches output, and no format fallback occurs.
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
- **Unbounded-input code must demonstrate bounded peak memory**: benchmark
  across a size sweep (e.g. 4KB → 64MB), and measure peak memory separately
  from cumulative `B/op` and `allocs/op`. OpenPGP and Tink streams use bounded
  segments; explain any per-segment allocation that scales with input size.
- Performance claims require evidence: `mise run bench` before and after,
  compared with `benchstat`, numbers included in the PR description. No
  claim without a comparison.
- Profiling is per-package and discovery-driven: `mise run bench:cpu` /
  `bench:mem` find every package containing Benchmark functions
  using Go's build-aware listing — adding benchmarks requires no task or CI
  changes.
- CI runs the full benchmark suite with `-benchtime=1x` on every PR as a
  smoke test: benchmarks are code and rot like code; they must at least
  compile and run.

### Tasks and profiles

`bench`, `bench:cpu`, and `bench:mem` accept `--package` (default `./...`),
`--bench` (Go regexp, default all), `--benchtime` (default `1s`), `--count`
(default `1`), and `--package-workers`. Allocation reporting is always enabled.
`--list` lists top-level benchmarks in the selected packages without running
benchmarks; it does not enumerate or filter subbenchmarks using `--bench`.

```fish
mise run bench --help
mise run bench -- --list
mise run bench -- --package ./internal/contextio --bench BenchmarkReader --benchtime 1x
mise run bench:cpu -- --package ./internal/contextio --benchtime 3s
mise run bench:mem -- --package ./internal/contextio --output-dir /tmp/npc-profiles
```

Profiles run sequentially by package and retain the matching test binary under
`.artifacts/bench/<import-path>/<cpu|mem>/`. Tasks print both paths and a usable
`go tool pprof` command. Repeating a profile replaces that package/mode's files;
use separate `--output-dir` values to retain comparisons. `clean:artifacts`
removes the default profile directory. Ordinary benchmark runs retain Go's
package concurrency. Empty selections or a run producing no benchmark results
fail rather than report a successful measurement.

Use direct `mise exec -- go test` for options outside this small interface.
The former native benchmark flag syntax becomes `--benchtime 1x` in task calls;
unit/race/coverage tasks still pass native Go flags through unchanged.

Published cryptographic vectors may contain public example keys and are safe to
commit as algorithm conformance data. Secret or deployment key material is
never fixture data; generate ephemeral private fixtures during test setup.

## Enforcement map

| Policy                                | Enforced by                                                                                                         |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Suite passes, raced + shuffled        | `ci.yml` test steps on every PR                                                                                     |
| Coverage changes investigated         | CI sticky PR comment; investigate unexpected deltas and explain meaningful losses                                   |
| Benchmarks don't rot                  | CI benchmark smoke run (`-benchtime=1x`)                                                                            |
| Runnable fuzz targets mutate          | CI discovery-driven smoke campaign (`-fuzztime=100x` per target)                                                    |
| Vulnerable dependencies               | `govulncheck` per PR + weekly scheduled run                                                                         |
| Config/workflow validity              | lefthook (local + changed-files CI)                                                                                 |
| No secret/deployment keys in fixtures | `.gitignore` patterns and review; provenance-backed published public vector and compatibility keys may be committed |

Run `mise run check` locally before pushing; `mise run test:race` for
anything concurrency-adjacent.

## Fuzzing

Fuzz seed corpora run with ordinary unit and race suites. `test:fuzz` discovers
runnable targets using Go, including platform-specific targets on matching hosts.
It excludes nested worktrees and does not depend on source filenames. Targets run
sequentially; the budget applies separately to each target, not the whole campaign.

The default `smoke` preset uses `100x` per target. `explore` uses `30s` per target;
`--fuzztime` overrides either with a positive duration or iteration count. Smoke
catches harness rot and shallow regressions; it is not a thorough fuzz campaign.
Go may also spend time building, loading seeds, or minimizing a discovered failure.

```fish
mise run test:fuzz --help
mise run test:fuzz -- --list
mise run test:fuzz
mise run test:fuzz -- --package ./internal/pemstrict --target FuzzDecode --preset explore
mise run test:fuzz -- --package ./internal/pemstrict --fuzztime 500x --fuzz-workers 2
```

`--target` is an exact name; use `--package` to disambiguate targets with the same
name. Invalid options, empty selections, build failures, and failing targets
return nonzero. For advanced Go options, use `mise exec -- go test` directly.

### Worker controls

Package concurrency (`-p`) and fuzz subprocess concurrency (`-parallel`) are
separate. Leave both unset to use Go's defaults, based on `GOMAXPROCS`; these are
not a single total worker budget. CI explicitly sets two fuzz workers and leaves
package concurrency at Go's default.

- `NPC_TEST_PACKAGE_WORKERS` supplies the package/build concurrency default for
  unit, race, coverage, fuzz, and benchmark tasks.
- Fuzz/benchmark `--package-workers` overrides that environment default.
- Unit/race/coverage tasks retain native flags, such as
  `mise run test:unit -- -p 2 -run TestName`; explicit `-p` wins.
- `NPC_FUZZ_WORKERS` supplies fuzz concurrency; `--fuzz-workers` overrides it.
  Neither changes ordinary tests' within-package `-parallel` setting.

Worker counts must be positive integers. Limit them explicitly when running
expensive targets or several campaigns concurrently.

The artifact reader target exercises contiguous and one-byte reads at generated
size limits, verifies the single-byte overflow probe does not over-read, and
requires partial read failures to preserve their error identity without
returning buffered artifact bytes.

These targets bound generated input sizes and check key identity, certificate
order and DER preservation, base64url acceptance against the standard library
(including one-byte reads), and authenticated decryption against an independent
standard-library wire decoder. The bounded AES wire target exercises OpenPGP
and Tink framing, malformed inputs, and authenticated decryption. A failing
chunk emits no plaintext; earlier authenticated chunks may remain after a later
failure. Parser round trips cover successfully parsed
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
