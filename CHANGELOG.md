# Changelog

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
