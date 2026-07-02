// Package sym defines shared symmetric-encryption types.
package sym

// SymmetricEncrypter transforms byte slices in both directions.
type SymmetricEncrypter interface {
	Encrypt(plaintext []byte) []byte
	Decrypt(ciphertext []byte) []byte
}
