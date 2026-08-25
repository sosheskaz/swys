# npc

[![CI](https://github.com/sosheskaz-systems/npc/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sosheskaz-systems/npc/actions/workflows/ci.yml)

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

| Layer | Domain                           | Nouns                                      |
| ----- | -------------------------------- | ------------------------------------------ |
| L4    | Raw transport (netcat successor) | `tcp`, `udp`                               |
| L5/6  | TLS, X.509, crypto primitives    | `cert`, `key`, `aes`, `hash`, `sign`       |
| L7    | Application protocols            | `http`, later `grpc`                       |
| —     | Byte-level utilities             | `encode`, `decode`, `rand`, `zip`, `unzip` |

The layering is the identity of the tool, not a grab-bag: `http` output
surfaces TLS handshake and certificate detail via the `cert` machinery; `cert
connect` rides the same dialer as `tcp connect`; everything emits through the
same encoding/format pipeline. **A feature that cannot reuse the layer beneath
it is a signal it may not belong.**

## Positioning: wire, not artifacts

The differentiator is breadth plus layered inspection of **live connections**,
bound together by a shared command language.

- [smallstep's `step`](https://smallstep.com/docs/step-cli/) owns the
  certificate-_artifact_ lifecycle (create, inspect, verify, bundle, CA
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

   _When is an algorithm a noun?_ An algorithm appears in the command path
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
   modern key types (ed25519) as defaults, randomness only from
   `crypto/rand`, legacy modes behind explicit flags — never silently. A
   newly created `--output` file is `0600`; overwriting an existing
   destination preserves its current permissions instead of resetting them.
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
     banned is _undifferentiated sprawl_ — trivial, poorly maintained, or
     transitively heavy dependencies.
   - Cryptographic primitives specifically stay stdlib/x-crypto. npc never
     takes third-party implementations of crypto, and never hand-rolls
     primitives.

8. **Bounded memory and low allocation.** Streaming algorithms stream;
   authenticated algorithms buffer only when their security contract requires
   it. Buffer sizes and limits are benchmarked, not guessed. Performance claims
   require benchmark evidence (`mise run bench`, compared with `benchstat`)
   before they are made.

## Commands today

```
npc aes encrypt|decrypt            # AES-GCM default; explicit AES-CBC compatibility
npc key generate                   # AES key generation; more key types are planned
npc cert inspect|connect           # certificate inspection and TLS probing
```

See `npc --help`; the surface is actively evolving toward the grammar above.

### AES quick start

Generate a new 256-bit key. `--output` writes the raw key bytes to `aes.key`, so
keep this file secret.

```fish
npc key generate --bits 256 --output aes.key
```

Encrypt a file with the default authenticated AES-GCM mode:

```fish
npc aes encrypt \
    --keyfile aes.key \
    --input document.txt \
    --output document.txt.gcm
```

Decrypt it using the same key:

```fish
npc aes decrypt \
    --keyfile aes.key \
    --input document.txt.gcm \
    --output recovered.txt
```

Prefer a new output path when decrypting. Runtime failures can leave an existing
`--output` file empty or partial.

For a small value or pipeline, encode the key and ciphertext as base64 so they
are safe to pass as text:

```fish
set key (npc key generate --bits 256 --encoding base64 | string trim)
set ciphertext (npc aes encrypt "secret message" --key "$key" --encoding base64)

npc aes decrypt "$ciphertext" --key "$key" --input-encoding base64
```

If the ciphertext needs to be bound to context, use the same `--aad` value when
encrypting and decrypting:

```fish
npc aes encrypt --keyfile aes.key --aad "customer=42;format=v1" \
    --input document.txt --output document.txt.gcm
npc aes decrypt --keyfile aes.key --aad "customer=42;format=v1" \
    --input document.txt.gcm --output recovered.txt
```

`aes encrypt` and `aes decrypt` default to authenticated AES-GCM. Its wire
format is `[12-byte random nonce][ciphertext][16-byte authentication tag]`.
GCM accepts `--aad`; the exact string bytes are authenticated but are not
stored in the ciphertext, so decryption requires the same value. Nonces are
generated internally and cannot be supplied by the caller. GCM reads one
message of at most 64 MiB before writing because authentication must complete
before any plaintext is released.

Use `--cipher-mode cbc` only for compatibility. CBC retains its existing wire
format, `[16-byte IV][PKCS#7-padded CBC ciphertext]`, and streams input and
output. `aes encrypt --cipher-mode cbc` generates a random IV when `--iv` is
omitted; `--iv` is not valid for GCM, and `--aad` is not valid for CBC. CBC is
unauthenticated: it cannot reliably detect tampering, a wrong key, or a wrong
mode, and successful decryption does not prove authenticity.

A single GCM key must encrypt no more than 2^32 messages in total across all
processes and machines that share it. Rotate well before that limit.

Binary input and output use `--input-encoding` and `--encoding/-e` with
`raw`, `hex`, `base64` (or the compatibility alias `b64`), `base64url`, or
`base32`. Structured certificate output uses `--format/-f`. This replaces the
old binary `--format/-f` axis and structured `--output-format/-F` axis; for
example, `cert connect -f hex` must be replaced with an applicable structured
format rather than a byte encoding.

The former `aes genkey` command remains available as a hidden compatibility
command for one release and prints a migration warning; use `key generate` in
new scripts. The legacy certificate aliases (`x509`, `certificate`, and
`x.509`) likewise forward to `cert inspect` with a warning so existing
inspection pipelines continue to produce certificate data. New invocations
should use the noun-verb form.

For `--output` paths, npc opens the destination and streams output to it as the
command runs, following symlinks like normal shell redirection. Before opening
the output, npc validates encodings, AES mode-specific flags, and `--mode`,
rejects directories and same-file input/output pairs, inspects existing target
types, and opens a named input first. Errors after the output is opened can
therefore leave an empty or partial destination; the command's non-zero exit
status indicates that the output is incomplete.

The GCM crypter itself makes zero writer calls until encryption or authenticated
decryption succeeds. That does not preserve a CLI output file on runtime
failure: npc opens and truncates regular `--output` destinations before the
crypter runs, and encoders and operating-system writes have their own buffering
and failure behavior. Flag and mode validation occurs before that open.

A newly created regular destination is `0600`; overwriting an existing file
keeps that file's current permissions. `--mode` (an octal permission string
such as `0640` or `640`) sets regular-file permissions explicitly on create or
overwrite and is applied before the command runs. It is rejected for
non-regular destinations, since npc has nothing there to chmod, and on Windows,
where POSIX permission bits cannot be applied exactly. Non-regular destinations
such as `/dev/stdout`, `/dev/fd/N`, and FIFOs stream directly as well.

## Development

Work is organized in two tiers:

- **Issues** track convergent work on what exists — correctness debt,
  consistency machinery, and the core capability build-out (keys, GCM,
  cert creation).
- **Milestones** capture the expansion arcs (mTLS, L4 transport, HTTP
  analysis, byte utilities, gRPC), each of which will decompose into
  multiple sub-issues when its predecessor work settles.

Tooling is managed by [mise](https://mise.jdx.dev): `mise install` provisions
the pinned toolchain, `mise tasks` lists every task, and `mise run
install:hooks` installs the pre-commit hooks. CI runs the same tasks against
the same pins. Task names follow verb:noun; a bare verb implies "all"
(`bench` runs every benchmark, `bench:cpu` narrows).

```sh
mise run build:dev      # development binary
mise run test:unit      # unit tests
mise run test:race      # race detector
mise run test:cover     # coverage + HTML report
mise run lint:go        # golangci-lint suite
mise run check          # lint and unit tests
mise run bench          # benchmarks
mise run scan:vuln      # govulncheck scan
```

Testing policy lives in [TESTING.md](TESTING.md) — the short version: every
fix ships with a regression test, coverage is maintained or increased by
every change, cryptographic code gets adversarial-input tests up front, and
unbounded-input code proves bounded memory in benchmarks.

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
