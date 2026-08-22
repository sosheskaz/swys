// Package crypter provides AES-GCM with wire format [12-byte random
// nonce][ciphertext][16-byte authentication tag]. GCM buffers a bounded message
// of at most 64 MiB of plaintext because it cannot release authenticated
// plaintext before verifying the final tag.
//
// AES-CBC remains available only as streaming, unauthenticated compatibility,
// with wire format [16-byte IV][PKCS#7-padded CBC ciphertext].
package crypter
