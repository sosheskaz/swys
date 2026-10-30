# Changelog

## [0.5.0](https://github.com/sosheskaz/swys/compare/v0.4.1...v0.5.0) (2026-10-30)


### Features

* complete -d with request templates and add grpc --template ([#121](https://github.com/sosheskaz/swys/issues/121)) ([ac45e87](https://github.com/sosheskaz/swys/commit/ac45e87ea9d6743f840a55262ca93419f6aea038))


### Bug Fixes

* **crpc:** complete only lines that execution accepts ([#152](https://github.com/sosheskaz/swys/issues/152)) ([cf1d821](https://github.com/sosheskaz/swys/commit/cf1d821ac74227d98b30b8aa304a841f2a6517be))
* **grpc:** complete only lines that execution accepts ([#150](https://github.com/sosheskaz/swys/issues/150)) ([2451fcc](https://github.com/sosheskaz/swys/commit/2451fcce351dce9faa4c104ed1b099f4980bac1f))


### Dependencies

* **go:** update module golang.org/x/net to v0.62.0 [security] ([#162](https://github.com/sosheskaz/swys/issues/162)) ([3221de0](https://github.com/sosheskaz/swys/commit/3221de0806f83cf887fa491a7b3fd4a0f593ea77))

## [0.4.1](https://github.com/sosheskaz/swys/compare/v0.4.0...v0.4.1) (2026-10-24)


### Bug Fixes

* **asym:** show invalid bytes in diagnostic values as \xNN instead of U+FFFD ([#132](https://github.com/sosheskaz/swys/issues/132)) ([2524fae](https://github.com/sosheskaz/swys/commit/2524fae369d2f065172153b37e015189513e0dc5))
* escape C1 and bidi controls in crpc and http JSON output ([#133](https://github.com/sosheskaz/swys/issues/133)) ([b56eaeb](https://github.com/sosheskaz/swys/commit/b56eaeb16c7a0387e0815e17afbcd76ac207388f))
* escape C1 and bidi controls in remaining JSON and protobuf text output ([#142](https://github.com/sosheskaz/swys/issues/142)) ([41cf9f1](https://github.com/sosheskaz/swys/commit/41cf9f19207ae200ccd4d77cb08c55e9285c2e00))
* **grpc:** reject invalid service names in reflection listings ([#143](https://github.com/sosheskaz/swys/issues/143)) ([7207858](https://github.com/sosheskaz/swys/commit/7207858c020ef2d015bcc443f5673f32093b3efa))
* **help:** preserve non-UTF-8 PAGER bytes in pager argv ([#115](https://github.com/sosheskaz/swys/issues/115)) ([f5ccd50](https://github.com/sosheskaz/swys/commit/f5ccd500804cbb8edc650d8b8cbf2bd01acb2762))
* **password:** report cancellation that interrupts Windows password command setup ([#141](https://github.com/sosheskaz/swys/issues/141)) ([bebf7fd](https://github.com/sosheskaz/swys/commit/bebf7fd97f5a15a18a6e425f7ea5a01d8aff1b24))
* **password:** report SIGSTOP-stopped password commands on FreeBSD ([#112](https://github.com/sosheskaz/swys/issues/112)) ([22781c7](https://github.com/sosheskaz/swys/commit/22781c7c077ef69f0bf538da75a5a09bd5943449))
* **password:** report suspension when any supplier process stops ([#116](https://github.com/sosheskaz/swys/issues/116)) ([e7caf2c](https://github.com/sosheskaz/swys/commit/e7caf2c932bab6e3928dd2cff200e5d4893e6d59))


### Dependencies

* **go:** update module github.com/yuin/goldmark/v2 to v2.1.8 ([#126](https://github.com/sosheskaz/swys/issues/126)) ([bf0d820](https://github.com/sosheskaz/swys/commit/bf0d820f99f08c509a08c979310e70369679e4fb))

## [0.4.0](https://github.com/sosheskaz/swys/compare/v0.3.2...v0.4.0) (2026-10-22)


### Features

* add --auth-* credential flags to http, grpc, and crpc ([#93](https://github.com/sosheskaz/swys/issues/93)) ([6abf9e6](https://github.com/sosheskaz/swys/commit/6abf9e64a9ad97c999a58da7df405412cfd77167))
* **cert:** choose SNI for cert connect ([#84](https://github.com/sosheskaz/swys/issues/84)) ([e2fa63d](https://github.com/sosheskaz/swys/commit/e2fa63d25deabc89a76646b096f7a8193af13445))
* **cert:** choose trust roots for cert connect ([#83](https://github.com/sosheskaz/swys/issues/83)) ([35778df](https://github.com/sosheskaz/swys/commit/35778dfbb82acdc5f22898bc9de51f6bad403f28))
* **cert:** resolve connection addresses for cert connect ([#89](https://github.com/sosheskaz/swys/issues/89)) ([3bf63db](https://github.com/sosheskaz/swys/commit/3bf63db99c5511ea29d6a3f5cda09988d4a7cf40))
* **cert:** set handshake options for cert connect ([#86](https://github.com/sosheskaz/swys/issues/86)) ([20bf214](https://github.com/sosheskaz/swys/commit/20bf214f8220d3fa59b9534e2cf7887405ce32dc))
* **net:** resolve connection addresses for net connect ([#88](https://github.com/sosheskaz/swys/issues/88)) ([191a22f](https://github.com/sosheskaz/swys/commit/191a22f77ea512d519b30c59900aa86c776664ed))


### Bug Fixes

* **grpc:** report the deadline when an invocation outlives --timeout ([#104](https://github.com/sosheskaz/swys/issues/104)) ([838df77](https://github.com/sosheskaz/swys/commit/838df77b1c41e576777c1f724a9a924d3b08db85))
* treat --insecure flags as permissions ([#96](https://github.com/sosheskaz/swys/issues/96)) ([285dff0](https://github.com/sosheskaz/swys/commit/285dff0721bf556659bc78cac1e1292fa731a537))


### Dependencies

* **go:** update module connectrpc.com/connect/v2 to v2.0.1 ([#81](https://github.com/sosheskaz/swys/issues/81)) ([e7f760d](https://github.com/sosheskaz/swys/commit/e7f760d67e34e86ec7af5eab90f08f4d5001749c))
* **go:** update module connectrpc.com/connect/v2 to v2.0.2 ([#107](https://github.com/sosheskaz/swys/issues/107)) ([023faa4](https://github.com/sosheskaz/swys/commit/023faa4b7b22f55201a86a75f25e5baa2f545325))
* **go:** update module github.com/tink-crypto/tink-go/v2 to v2.9.0 ([#109](https://github.com/sosheskaz/swys/issues/109)) ([a3c4307](https://github.com/sosheskaz/swys/commit/a3c4307bb2d5094af665dd8f3a78f7ac89502e2a))

## [0.3.2](https://github.com/sosheskaz/swys/compare/v0.3.1...v0.3.2) (2026-10-21)


### Bug Fixes

* **crpc:** end each reflection request before awaiting its reply ([#71](https://github.com/sosheskaz/swys/issues/71)) ([402c7e9](https://github.com/sosheskaz/swys/commit/402c7e9ca499e1ac411bca594ad3c34dfe92fe72))
* **grpc:** accept mixed-case metadata keys ([#72](https://github.com/sosheskaz/swys/issues/72)) ([20d529e](https://github.com/sosheskaz/swys/commit/20d529e4d7bb3b2c39156cc9ad82185821f31fab))
* **grpc:** omit header value from malformed metadata errors ([#73](https://github.com/sosheskaz/swys/issues/73)) ([3ea1cca](https://github.com/sosheskaz/swys/commit/3ea1cca883560e5d16e16e79d1aa47fd21e71b24))

## [0.3.1](https://github.com/sosheskaz/swys/compare/v0.3.0...v0.3.1) (2026-10-20)


### Bug Fixes

* **crpc:** reflect over the Connect protocol ([#68](https://github.com/sosheskaz/swys/issues/68)) ([7128a87](https://github.com/sosheskaz/swys/commit/7128a878b0a73907d3e0659554f8074ba024a419))


### Dependencies

* **go:** update dependency go to v1.27.3 ([#65](https://github.com/sosheskaz/swys/issues/65)) ([a10e8ff](https://github.com/sosheskaz/swys/commit/a10e8ff939416d88d85b9473e2eab701d96b00ba))
* **go:** update module golang.org/x/crypto to v0.58.0 ([#62](https://github.com/sosheskaz/swys/issues/62)) ([d7333c4](https://github.com/sosheskaz/swys/commit/d7333c4480ba7864811bd2268bf47a473e685d78))
* **go:** update module golang.org/x/net to v0.61.0 ([#63](https://github.com/sosheskaz/swys/issues/63)) ([2fd7cbe](https://github.com/sosheskaz/swys/commit/2fd7cbe48c422136ae11d520273a3a1a0e978213))

## [0.3.0](https://github.com/sosheskaz/swys/compare/v0.2.1...v0.3.0) (2026-10-14)


### ⚠ BREAKING CHANGES

* **cert:** remove CA flags and JSON verification from cert inspect ([#48](https://github.com/sosheskaz/swys/issues/48))

### Features

* **crpc:** add Connect RPC calls, streaming, and discovery ([#43](https://github.com/sosheskaz/swys/issues/43)) ([dffc2ec](https://github.com/sosheskaz/swys/commit/dffc2ec00cc4403a461f73d9287b2a0781a49aac))


### Bug Fixes

* **cert:** remove CA flags and JSON verification from cert inspect ([#48](https://github.com/sosheskaz/swys/issues/48)) ([8dd9eba](https://github.com/sosheskaz/swys/commit/8dd9eba57907bb59a80c869fae68331365546931))


### Dependencies

* **go:** update module golang.org/x/sys to v0.49.0 ([#54](https://github.com/sosheskaz/swys/issues/54)) ([34a5783](https://github.com/sosheskaz/swys/commit/34a5783fd4918bf97596f3cc2519b785ceaa302c))

## [0.2.1](https://github.com/sosheskaz/swys/compare/v0.2.0...v0.2.1) (2026-10-12)


### Bug Fixes

* **net:** document encrypted exchange between two machines ([#41](https://github.com/sosheskaz/swys/issues/41)) ([028bf3d](https://github.com/sosheskaz/swys/commit/028bf3d0135a3b6e3b2aa230331922dc2243210f))


### Dependencies

* **go:** update module codeberg.org/miekg/dns to v0.6.118 ([#40](https://github.com/sosheskaz/swys/issues/40)) ([e04be9f](https://github.com/sosheskaz/swys/commit/e04be9f8bdf1b6c27b4ce3956dbe6e7747f490d1))

## [0.2.0](https://github.com/sosheskaz/swys/compare/v0.1.0...v0.2.0) (2026-10-09)


### Features

* **cert:** accept inline CA certificate data ([#24](https://github.com/sosheskaz/swys/issues/24)) ([f1933fc](https://github.com/sosheskaz/swys/commit/f1933fc3753e98845c00a74fc0fdce1feb19e596))
* **cli:** add rich text reports and plain output ([#25](https://github.com/sosheskaz/swys/issues/25)) ([1111a66](https://github.com/sosheskaz/swys/commit/1111a66cbfa710e50e05f694eb275f859f670816))
* **dns:** support multiple resolvers anywhere in arguments ([#28](https://github.com/sosheskaz/swys/issues/28)) ([b5173ee](https://github.com/sosheskaz/swys/commit/b5173ee20dba6cfbba29812aa13cf6bfcdbbb592))
* **skill:** add version-coupled agent instructions ([#29](https://github.com/sosheskaz/swys/issues/29)) ([b88a8b4](https://github.com/sosheskaz/swys/commit/b88a8b44941858519aa0155ed8cbe60f69bd2bff))


### Bug Fixes

* **help:** stop wrapping plain output and preserve Markdown validation ([#26](https://github.com/sosheskaz/swys/issues/26)) ([559672e](https://github.com/sosheskaz/swys/commit/559672ea2b44965ef5bdca1a2c51533d0489d141))


### Dependencies

* **go:** resolve security findings with Go 1.27.2 and golang.org/x/net v0.60.0 ([8a0790f](https://github.com/sosheskaz/swys/commit/8a0790f4931ac2786ba3c27fab2868189783bb8e))
* **go:** update module github.com/protonmail/gopenpgp/v3 to v3.5.2 ([#15](https://github.com/sosheskaz/swys/issues/15)) ([09bc6a1](https://github.com/sosheskaz/swys/commit/09bc6a138b9c471928a122e688d9541b9500dae3))

## 0.1.0 (2026-10-06)

SwYS is a sysadmin's Swiss Army knife: a single command-line tool for networking, protocols, cryptography, and X.509 operations. This first public release brings the project's existing capabilities together under the `swys` command.

### Networking and protocols

- Connect or listen over TCP, TLS, and UDP. TCP and TLS drain both directions by default, half-close sending on input EOF, and support receive-only pipelines.
- Resolve names with the system resolver or a selected DNS server, including DNS over TLS and HTTPS.
- Make HTTP requests with request bodies, headers, custom hostname resolution, TLS credentials, and optional tracing.
- Discover gRPC services through reflection or local schemas, invoke unary methods, and complete service and method names from the schema.

### Certificates and keys

- Inspect PEM and DER certificates, retrieve certificates from TLS endpoints, select a certificate or chain, and export text, JSON, or PEM with optional output encoding.
- Generate Ed25519, ECDSA, or RSA keys; inspect, convert, and derive public keys, including supported OpenSSH key inputs.
- Create certificates directly from keys or sign certificate requests with a CA. Verify certificate chains offline and check certificate, key, and CSR matches.

### Encryption and checksums

- Stream authenticated AES encryption and decryption using OpenPGP RFC 9580 AES-GCM by default, with native Tink AES-GCM-HKDF streams available explicitly.
- Encrypt with a raw AES key, a Tink keyset, or an OpenPGP password using Argon2id. Key readers detect supported raw and Tink key-container formats.
- Generate, inspect, and convert AES keys and keysets, and compute streaming checksums with `swys hash`.

### Command-line experience

- Embedded task guides, contextual shell completion, consistent common flags, and separate output selection, formatting, and encoding.
- Standard input/output streams, `-` stream operands, independently encoded supplemental credentials, private-file protections, and cancellation on interrupt or termination.
- Release archives for macOS, Linux, Windows, and FreeBSD on AMD64 and ARM64, with license notices and Bash, Zsh, and Fish completions. Linux container images target AMD64 and ARM64.

### Compatibility notes

- This is a pre-1.0 release; command interfaces may change in later releases.
- AES keys are 128 or 256 bits. Password decryption currently accepts Argon2-based OpenPGP password wrappers only, with unconditional resource limits.
- Streaming decryption releases authenticated chunks as they complete. A later authentication failure can leave earlier verified plaintext in the output; success requires final authentication and end of input.
- gRPC invocation currently supports unary methods. Older project-specific ciphertext formats, raw GCM, and CBC are not supported by this release.
