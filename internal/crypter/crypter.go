// Package crypter provides versioned AES-GCM-HKDF streaming, legacy bounded
// single-message AES-GCM, and unauthenticated AES-CBC compatibility. The stream
// envelope is documented in docs/aes-stream-v1.md. Raw GCM retains its
// [12-byte nonce][ciphertext][16-byte tag] wire format and 64 MiB limit.
package crypter
