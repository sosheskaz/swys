package crypter

import "errors"

// ErrInvalidAESKeySize identifies the CLI-supported AES key size contract.
var ErrInvalidAESKeySize = errors.New("AES key size must be 128 or 256 bits")

// AES chunk bounds also apply to raw Tink streaming keys.
const (
	MinAESChunkSize = 64
	MaxAESChunkSize = 64 << 20
)
