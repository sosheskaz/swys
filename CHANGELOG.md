# Changelog

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
