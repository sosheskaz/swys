package aes

import "errors"

var (
	errInvalidAESChunkSize = errors.New("invalid AES chunk size")
	errAESWireFormat       = errors.New("unknown AES wire format")
	errAESWireFlag         = errors.New("invalid AES wire flag")
	errAESOperation        = errors.New("AES operation was not prepared")
	// ErrAESKeyOutputCollision identifies an output path that aliases the AES key file.
	ErrAESKeyOutputCollision = errors.New("AES keyfile and output collide")
)
