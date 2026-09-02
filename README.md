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
| L4    | Raw transport (netcat successor) | `net` (`tcp`; later `udp`)                 |
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

1. **Noun-verb grammar, no exceptions.** `npc <noun> <verb> [mechanism] [flags]`.
   Nouns are resources (`cert`, `key`, `net`, `http`); verbs are actions
   (`inspect`, `generate`, `connect`, `listen`). Bare nouns print help — no
   implicit verbs. Knowledge must transfer: a user who has run `cert inspect`
   should correctly guess `key inspect`.

   _When is an algorithm a noun?_ An algorithm appears in the command path
   when it is (a) established by out-of-band mutual agreement between the
   parties, and (b) not derivable from self-describing inputs. Negotiated
   parameters (TLS ciphersuite, ALPN, HTTP version) are rendered in output,
   never encoded in command structure; derivable parameters (the key type
   inside a PEM block) come from the artifact. Hence `aes encrypt`,
   `hash sha256`, and `net connect tcp` name the mechanism — while `sign` does
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
   `npc key generate ed25519 | npc key public | npc encode base64`.

4. **`--format json` everywhere** structured output exists, for `jq`.

5. **Secure by default.** Authenticated encryption (AES-GCM) by default,
   modern key types such as Ed25519, randomness only from
   `crypto/rand`, legacy modes behind explicit flags — never silently. A
   generated private-key file output is owner-only. Ordinary commands request
   `0600` for new Unix files and preserve permissions when overwriting; the
   primary output of key-generating commands rejects an existing regular
   destination that is not already owner-only. npc never modifies system trust
   stores.

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
npc key generate <algorithm>       # generate a key with an explicit algorithm
npc key public|inspect|convert     # consume a self-describing key
npc cert create|csr                # mint test identities and certificate requests
npc cert inspect|connect           # certificate inspection and TLS probing
npc net connect tcp|tls host:port  # exchange raw bytes over TCP or verified TLS
```

See `npc --help`; the surface is actively evolving toward the grammar above.

### Raw TCP and TLS walkthrough

`net connect` sends stdin or `--input` to an endpoint and copies the peer's
response to stdout or `--output`. At input EOF, it keeps the connection's write
side open while draining the response; `--close-write` opts into a TCP
half-close for protocols that require EOF before responding. The TCP form is a
compact netcat-style exchange:

```fish
printf 'hello\n' | npc net connect tcp localhost:9000
```

The TLS form verifies the server certificate and endpoint hostname by default.
Use a private test CA without changing the system trust store:

```fish
printf 'hello\n' | npc net connect tls localhost:9443 \
    --ca ca.crt
```

Add a client identity for mutual TLS. The certificate and private key are
required together and must match:

```fish
printf 'hello\n' | npc net connect tls localhost:9443 \
    --ca ca.crt \
    --cert client.crt \
    --key client.key
```

`--ca` replaces the system roots. Add `--system-ca` to combine the supplied CA
bundle with them. `--servername` overrides both SNI and the certificate name
used for verification. `--insecure` disables certificate and hostname
verification and cannot be combined with trust flags; its warning is shown
with `--verbose` connection diagnostics.

By default, npc advertises no ALPN protocols. Use `--alpn http/1.1`, `--alpn
h2`, or another comma-separated protocol list when the endpoint requires
explicit negotiation. ALPN negotiation never changes the bytes npc sends:
selecting `h2` requires the input itself to contain valid HTTP/2 frames.

`--timeout` bounds only TCP setup and the TLS handshake (10 seconds by
default); established streaming is not timed out. After input EOF, `--wait`
allows up to 5 seconds for the peer to finish its response before npc closes the
connection. Set `--wait 0` to drain until the peer closes, or choose a shorter
duration for a protocol that keeps connections open. With `--close-write`, npc
half-closes before starting that drain period. The aliases `npc nc` and `npc
netcat` select the same `net` command tree.

`cert connect` and `cert inspect` remain inspection commands: they always report
certificate verification status, but a failed verification is not enforced.
Text, long, and JSON views include it in their structured output; PEM views
report it on stderr so stdout remains a clean certificate artifact. `net
connect tls` is the data-bearing client and therefore fails the handshake before
sending input when verification fails.

### Key lifecycle walkthrough

Generate an Ed25519 private key in PKCS#8 PEM and its public half in canonical
PKIX PEM with one command, then inspect the private key's safe metadata without
printing private bytes:

```fish
npc key generate ed25519 \
    --output private.pem \
    --public-out public.pem
npc key inspect --input private.pem --format json
```

Inspect the public key separately. The private and public inspection results
have different `key_type` values but the same
`public_key_sha256_fingerprint`:

```fish
npc key inspect --input public.pem --format json
```

`--public-format` selects `pkix-pem` (the default), `pkix-der`, or `openssh`.
It applies only to `--public-out`; `--encoding` and `--mode` continue to apply
only to the private `--output`. The private key may go to stdout while the
public key goes to a file, but `--public-out -` is rejected because one stdout
stream cannot safely carry both artifacts. Use `key public` later when you need
to derive a public key from existing private material.

That fingerprint is calculated over canonical PKIX DER, so it is stable across
key containers. `cert inspect --format json` reports the same field, making it
possible to confirm that a certificate contains the expected public key:

```fish
npc cert inspect --input certificate.pem --format json
```

Convert the public key for an OpenSSH `authorized_keys` file, or convert it to
binary PKIX DER for a program that expects DER:

```fish
npc key convert --input private.pem --to openssh --output public.openssh
npc key convert --input public.pem --to pkix-der --output public.der
npc key inspect --input public.der
```

Binary key containers can be wrapped for text-only transport and decoded by any
key-consuming command. Encoding is not encryption; a base64-wrapped private key
must be protected exactly like the original:

```fish
npc key convert --input private.pem --to pkcs8-der \
    --encoding base64 --output private.der.b64
npc key inspect --input private.der.b64 \
    --input-encoding base64 --format json
```

Generation supports `ed25519`, `p256`, `p384`, `rsa2048`, `rsa4096`, and raw
`aes128|aes192|aes256` keys as a required argument. These compact names are
preferred; the descriptive aliases `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`,
`rsa-4096`, and `aes-128|aes-192|aes-256` are also accepted.
Asymmetric private keys use PKCS#8 PEM; AES keys are raw bytes. PKCS#1 output is
limited to RSA private keys, SEC1 to ECDSA private keys, and PKCS#8 to supported
private-key algorithms. PKIX and OpenSSH targets contain only public material.

`key generate` and the deprecated `aes genkey` treat regular output files as
sensitive. A new destination is created owner-only. Without an explicit Unix
`--mode`, an existing destination must be owned by the effective user and grant
no group or other permissions. macOS additionally suppresses inherited ACLs on
creation and rejects any extended ACL on an existing file. On Windows, the
current user must own the file and be the only principal granted access by a
protected DACL. An insecure destination is rejected before truncation,
preserving its contents and permissions. On Unix, an explicit `--mode` is a
deliberate override of that check; Windows continues to reject `--mode`.
Stdout, FIFOs, and device outputs remain explicit streaming sinks and are not
permission-checked by npc.

`--public-out` follows the ordinary output-file contract: an existing file is
overwritten while retaining its permissions. npc validates that the private
and public paths are not direct, symlink, or hardlink aliases before opening
either output. The private key is written first; if the public write fails, the
private key is retained and the error identifies its path (or notes that it was
already emitted to stdout).

`key public`, `key inspect`, and `key convert` accept one unencrypted PKCS#8,
PKCS#1, or SEC1 private key, or one PKIX public key, in PEM or DER form. All
three commands support `--input-encoding` for wrapped key bytes. Encrypted
private keys and OpenSSH input are not supported.

The key noun and lifecycle verbs also have composable Cobra aliases for
interactive use:

```fish
npc k g ed25519                 # npc key generate ed25519
npc k p --input private.pem     # npc key public
npc k i --input private.pem     # npc key inspect
npc k c --input private.pem --to openssh # npc key convert
```

The longer verb aliases are `gen`, `pub`, `ins`, and `conv`.

### Certificate creation walkthrough

Create a private key and a self-signed test CA. Certificate commands consume
private keys but never generate them, so key algorithm and output handling stay
under the `key generate` contract.

```fish
npc key generate ed25519 --output ca.key
npc cert create \
    --ca \
    --subject "CN=test-ca" \
    --key ca.key \
    --output ca.crt
```

Use that CA to mint separate server and client identities. Leaf certificates
default to 30 days and support both server and client authentication unless
`--server-only` or `--client-only` narrows them. CA certificates default to 365
days and cannot create subordinate CAs. An issued leaf starts no earlier than
its issuer and must use a short enough `--days` value to expire no later than its
issuer.

```fish
npc key generate ed25519 --output server.key
npc cert create \
    --dns localhost \
    --ip 127.0.0.1 \
    --server-only \
    --key server.key \
    --issuer-cert ca.crt \
    --issuer-key ca.key \
    --output server.crt

npc key generate ed25519 --output client.key
npc cert create \
    --subject "CN=client" \
    --client-only \
    --key client.key \
    --issuer-cert ca.crt \
    --issuer-key ca.key \
    --output client.crt
```

Inspect the resulting certificates using the normal certificate formatter:

```fish
npc cert inspect --input ca.crt --format long
npc cert inspect --input server.crt --format json
npc cert inspect --input client.crt
```

Use the same generation flags for certificate keys as for any other raw
keypair. Existing private keys may also be read from stdin by using `--key -`;
only one key or issuer flag can own stdin in a single invocation.

```fish
npc key generate p256 --output alternate-server.key
npc cert create \
    --dns localhost \
    --key alternate-server.key \
    --issuer-cert ca.crt \
    --issuer-key ca.key \
    --output alternate-server.crt
```

Create a minimal PKCS#10 request when a real CA owns certificate issuance:

```fish
npc cert csr \
    --subject "CN=service.internal" \
    --dns service.internal \
    --key alternate-server.key \
    --output service.csr
```

`--subject` currently accepts one `CN=<value>` component. DNS and IP values are
written as SAN extensions, not only into the common name. An issuer certificate
must be one PEM `CERTIFICATE`, its private key must match, and the requested
leaf validity must fit entirely within the issuer's validity window.
Server-capable leaves with no SAN flags classify their common name as a matching
DNS or IP SAN.
With no subject or SAN flags, server-capable leaves and CSRs default to both
`CN=localhost` and a `localhost` DNS SAN; client-only leaves default to the same
common name without a SAN.

These certificates and CAs are for test and development loops. npc never
installs trust roots; trust `ca.crt` only in an explicitly selected test store,
never system-wide. If certificate output fails after an automatic key is saved,
npc retains the usable key and reports its path.

### AES quick start

Generate a new 256-bit key. `--output` writes the raw key bytes to `aes.key`, so
keep this file secret.

```fish
npc key generate aes256 --output aes.key
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
set key (npc key generate aes256 --encoding base64 | string trim)
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
command for one release and prints a migration warning. The former canonical
`key generate --bits 256` form is replaced by
`key generate aes256`; bare `key generate` now reports the required algorithm
argument. The legacy certificate aliases (`x509`, `certificate`, and `x.509`)
likewise forward to `cert inspect` with a warning so existing inspection
pipelines continue to produce certificate data. New invocations should use the
noun-verb form.

For `--output` paths, npc opens the destination and streams output to it as the
command runs, following symlinks like normal shell redirection. Before opening
the output, npc validates encodings, AES mode-specific flags, key algorithm and
conversion-target values, and `--mode`, rejects directories and same-file
input/output pairs, inspects existing target types, and opens a named input
first. Errors after the output is opened can therefore leave an empty or partial
destination; the command's non-zero exit status indicates that the output is
incomplete.

The GCM crypter itself makes zero writer calls until encryption or authenticated
decryption succeeds. That does not preserve a CLI output file on runtime
failure: npc opens and truncates regular `--output` destinations before the
crypter runs, and encoders and operating-system writes have their own buffering
and failure behavior. Flag and mode validation occurs before that open.

A newly created regular destination requests mode `0600` on Unix; a restrictive
umask may remove additional owner permissions. Ordinary commands preserve an
existing file's permissions. Sensitive key-generating commands instead require
an existing regular destination to be owner-only, as described above, and
reject it before truncation otherwise. `--mode` (an octal permission string such
as `0640` or `640`) sets regular-file permissions explicitly on create or
overwrite, bypasses the sensitive-output check, and is applied before the
command runs. It is rejected for non-regular destinations, since npc has
nothing there to chmod, and on Windows, where POSIX permission bits cannot be
applied exactly. Non-regular destinations such as `/dev/stdout`, `/dev/fd/N`,
and FIFOs stream directly as well.

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
