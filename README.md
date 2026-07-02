# npc

**N**etworking, **P**rotocols, **C**rypto — an operator's tool that makes
wire behavior and cryptographic operations legible, ergonomic, and safe by
default. One static binary replacing manual `openssl`, `netcat`, and ad-hoc
`curl` invocations.

> **Status:** early development, pre-1.0. Command names and flags are still
> settling; expect breaking changes, batched and called out in commit messages.

## Product shape

npc is organized as **composable layers**, loosely following the OSI model.
Each layer's commands are useful alone, and each higher layer exposes rich
detail from the layers beneath it rather than reimplementing them:

| Layer | Domain                                | Nouns                          |
|-------|---------------------------------------|--------------------------------|
| L4    | Raw transport (netcat successor)      | `tcp`, `udp`                   |
| L5/6  | TLS, X.509, crypto primitives         | `cert`, `key`, `aes`, `hash`, `sign` |
| L7    | Application protocols                 | `http`, later `grpc`           |
| —     | Byte-level utilities                  | `encode`, `decode`, `rand`, `zip`, `unzip` |

The layering is the identity of the tool, not a grab-bag: `http` output
surfaces TLS handshake and certificate detail via the `cert` machinery; `cert
connect` rides the same dialer as `tcp connect`; everything emits through the
same encoding/format pipeline. **A feature that cannot reuse the layer beneath
it is a signal it may not belong.**

## Positioning: wire, not artifacts

The differentiator is breadth plus layered inspection of **live connections**,
bound together by a shared command language.

- [smallstep's `step`](https://smallstep.com/docs/step-cli/) owns the
  certificate-*artifact* lifecycle (create, inspect, verify, bundle, CA
  workflows) and does it well. npc does not compete there: artifact features
  are built to the minimum needed to make npc's wire-inspection loops
  self-contained, borrowing step's UX decisions where they are good.
- [`age`](https://age-encryption.org) owns no-knobs file encryption. If npc
  grows recipient-based file encryption, it speaks the age format rather than
  inventing a container (see Open decisions).
- npc's territory is what those tools structurally lack: probing **and
  serving** TLS with client identity (mTLS from both ends), STARTTLS, raw L4,
  HTTP timing/analysis, everyday symmetric encryption, and byte utilities —
  composing across layers in one binary.

In short: step manages identity artifacts; age encrypts files for humans;
**npc inspects live wire behavior and does everyday crypto plumbing.**

## Design principles

These are product features, not style preferences. Regressions against them
are bugs, and where possible they are enforced by tests rather than review.

1. **Noun-verb grammar, no exceptions.** `npc <noun> <verb> [flags]`. Nouns
   are resources (`cert`, `key`, `tcp`, `http`); verbs are actions
   (`inspect`, `generate`, `connect`, `listen`). Bare nouns print help — no
   implicit verbs. Knowledge must transfer: a user who has run `cert inspect`
   should correctly guess `key inspect`.

   *When is an algorithm a noun?* An algorithm appears in the command path
   when it is (a) established by out-of-band mutual agreement between the
   parties, and (b) not derivable from self-describing inputs. Negotiated
   parameters (TLS ciphersuite, ALPN, HTTP version) are rendered in output,
   never encoded in command structure; derivable parameters (the key type
   inside a PEM block) come from the artifact. Hence `aes encrypt`,
   `hash sha256`, and `tcp connect` name the mechanism — while `sign` does
   not (PEM keys are self-describing) and `http`/`cert connect` report what
   was negotiated.

2. **Two output axes, named consistently.**
   - `--encoding` / `-e`: byte serialization — `raw`, `hex`, `base64`,
     `base64url`, `base32`. Applies to binary output (keys, ciphertext,
     digests). Input gets the symmetric `--input-encoding`.
   - `--format` / `-f`: structured presentation — `text`, `long`, `json`,
     `pem`. Applies to structured output (certs, key metadata, analyses).

   The same words mean the same thing on every command.

3. **Universal I/O contract.** Every command reads stdin/`--input`, writes
   data to stdout/`--output`, and diagnostics to stderr. Commands compose:
   `npc key generate | npc key public | npc encode base64`.

4. **`--format json` everywhere** structured output exists, for `jq`.

5. **Secure by default.** Authenticated encryption (AES-GCM) by default,
   0600 output files, modern key types (ed25519) as defaults, randomness only
   from `crypto/rand`, legacy modes behind explicit flags — never silently.
   npc never modifies system trust stores.

6. **Mechanical consistency.** Uniformity is enforced by shared machinery —
   persistent I/O hooks, encoder/formatter registries that derive help text,
   validation errors, and shell completion from one table — and pinned by
   conformance tests that walk the command tree. Future commands cannot merge
   in violation without failing CI.

7. **Narrow, differentiated dependencies.** Not zero-dependency — a policy:
   - No runtime dependencies: single static binary, no cgo, nothing resolved
     at execution time.
   - stdlib and `golang.org/x/*` are free; treated as stdlib.
   - Curated third-party libraries are welcome when differentiated: a
     mainline, high-quality library used substantially earns its place
     (cobra today; colored output and gRPC reflection anticipated). What is
     banned is *undifferentiated sprawl* — trivial, poorly maintained, or
     transitively heavy dependencies.
   - Cryptographic primitives specifically stay stdlib/x-crypto. npc never
     takes third-party implementations of crypto, and never hand-rolls
     primitives.

8. **Streaming and low-allocation.** Encryption and I/O paths stream; buffer
   sizes are benchmarked, not guessed. Performance claims require benchmark
   evidence (`make bench`, compared with `benchstat`) before they are made.

## Commands today

```
npc aes encrypt|decrypt|genkey     # AES-CBC today; GCM-by-default in progress
npc x509 [connect]                 # certificate inspection and TLS probing
```

See `npc --help`; the surface is actively evolving toward the grammar above.

## Development

Work is organized in two tiers:

- **Issues** track convergent work on what exists — correctness debt,
  consistency machinery, and the core capability build-out (keys, GCM,
  cert creation).
- **Milestones** capture the expansion arcs (mTLS, L4 transport, HTTP
  analysis, byte utilities, gRPC), each of which will decompose into
  multiple sub-issues when its predecessor work settles.

```sh
make build          # development binary
make test           # unit tests
make test-race      # race detector
make lint           # golangci-lint suite
make check          # lint and unit tests
make bench          # benchmarks
```

Testing conventions: regression tests accompany every bug fix; boundary
sizes (0 bytes, one block, block±1), malformed inputs, and output-writer
failures are first-class test cases; failing tests are fixed at the root,
never deleted or skipped.

## Open decisions

Recorded here so they are decided deliberately, not by accident:

- **age-format interop.** If recipient-based file encryption enters scope,
  adopt `age-encryption.org/v1` via `filippo.io/age` instead of a bespoke
  container, and add stanza-level inspection age itself doesn't prioritize.
  Decide when the feature is scheduled. Passphrase-derived keys (KDF choice)
  ride with this decision.
- **HTTP verb surface.** Methods-as-verbs (`http get`) reads naturally but
  implies breadth; `http trace` may deliver most of the value first.
- **nectat disposition.** The L4 core absorbs the `nectat` prototype
  (preserving its flush → cancel → linger → close shutdown ordering); the
  standalone repo is then archived.
