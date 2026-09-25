package crypter

import "errors"

// ErrInvalidAESKeySize identifies the CLI-supported AES key size contract.
var ErrInvalidAESKeySize = errors.New("AES key size must be 128 or 256 bits")
