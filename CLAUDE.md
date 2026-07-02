# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`cryptool` is a CLI tool designed to provide many of the cryptographic functions of the OpenSSL CLI, but implemented in a simpler and more operator-friendly way. The tool prioritizes:
- User-friendly interface, intuitive ergonomics, and clear command structure
- Lightweight implementation with minimal memory footprint
- Performance optimization - avoiding heap allocations where possible
- Efficiency-focused design for production use

Built with Go using the Cobra CLI framework.

## Build and Run Commands

```bash
# Build the binary
go build -o cryptool .

# Run directly
go run . [command]

# Run tests (when tests are added)
go test ./...

# Run tests for specific package
go test ./internal/crypter
```

## Architecture

### Command Structure (Cobra-based)

The CLI is organized hierarchically using Cobra:

- **Root command** (`cmd/root.go`): Defines global flags and IO redirection handling
  - `--format/-f`: Output format (base64, hex, raw) - handled in `PersistentPreRun`
  - `--input/-i`: Redirect stdin from file
  - `--output/-o`: Redirect stdout to file

- **AES command** (`aes`): Parent for all AES operations
  - `encrypt/enc/e`: Encrypt plaintext with AES-CBC
  - `decrypt/dec/d`: Decrypt ciphertext with AES-CBC
  - `genkey`: Generate random AES key (128/192/256 bits)

- **X.509 command** (`x509/cert`): Certificate operations
  - `connect`: Fetch and display cert from TLS connection

### Key Architectural Patterns

1. **IO Redirection**: All commands use `cmd.InOrStdin()` and `cmd.OutOrStdout()` to support flexible IO. The root command's `PersistentPreRun` handles file-based redirection via flags.

2. **Format Filters**: The root command applies format transformations (currently base64) as filters wrapping the output writer in `PersistentPreRun`.

3. **Key Management**: AES commands accept keys via two mutually exclusive flags:
   - `--key/-k`: Base64-encoded key as argument
   - `--keyfile/-K`: Read raw key from file

   Helper function `getKey()` in `cmd/aes.go` handles this logic.

4. **Error Handling**: Uses `dieIf(err)` and `dieIfT(val, err)` helpers throughout for fail-fast error handling.

5. **IV Handling**: Encryption prepends IV to ciphertext. Decryption reads IV from the first block. Random IVs are generated when not explicitly provided.

### Package Organization

- **`cmd/`**: All Cobra command definitions
  - Each command in its own file (e.g., `encrypt.go`, `decrypt.go`)
  - `root.go`: Root command and shared utilities
  - `aes.go`: AES parent command and key flag helpers

- **`internal/crypter/`**: Actual cryptographic implementations
  - `aes.go`: `AESCrypter` struct with `Encrypt()` and `Decrypt()` methods
  - Uses CBC mode with PKCS#7 padding
  - Streams data in 64KB chunks for memory efficiency

- **`internal/asym/`**: Asymmetric crypto and certificate operations
  - `x509.go`: Certificate parsing, verification, and display
  - `conn.go`: TLS connection helpers for fetching remote certs

- **`internal/sym/`**: Symmetric encryption interfaces (currently minimal)

- **`internal/sys/`**: System utilities like logging

### Encryption Implementation Details

The AES implementation in `internal/crypter/aes.go`:
- Uses CBC mode (cipher block chaining)
- PKCS#7 padding for partial blocks
- IV is prepended to ciphertext during encryption
- Streams data in 64KB buffers to handle large files efficiently
- Key size determines AES variant (128/192/256 bits)
- Buffer reuse pattern to minimize allocations

### Certificate Handling

X.509 certificate operations (`internal/asym/x509.go`):
- Parses PEM-encoded certificates
- Verifies against system cert pool
- Displays cert chain, subject, DNS names, validity period, signature, and public key
- `x509 connect` command fetches certs via TLS dial (with InsecureSkipVerify for inspection)

## Performance Guidelines

When adding new features or modifying code:
- Reuse buffers and pre-allocate slices where size is known
- Use streaming/chunked processing for large data (follow the pattern in `AESCrypter`)
- Avoid unnecessary allocations in hot paths
- Prefer stack allocation over heap where possible
- Keep dependency footprint minimal
- Profile memory usage for new cryptographic operations

## Development Notes

- The project uses Go 1.25.3 (specified in `go.mod`)
- Main dependencies: Cobra (CLI), go-units (size formatting), go-logr (logging)
- No test files exist yet - tests should be added in `*_test.go` files alongside implementation
- The codebase uses a simple, direct style - avoid over-engineering when adding features
- When implementing new OpenSSL-equivalent commands, prioritize clarity and simplicity over feature parity
