package aes

import "errors"

var (
	errKeySelection        = errors.New("exactly one of key or keyfile must be set")
	errRawCipherMode       = errors.New("--raw is only valid with --cipher-mode gcm")
	errChunkCipherMode     = errors.New("--chunk-size is only valid with --cipher-mode gcm")
	errRawChunkSize        = errors.New("--chunk-size cannot be used with --raw")
	errInvalidAESChunkSize = errors.New("invalid AES chunk size")
	// ErrUnknownAESCipherMode identifies an unsupported AES cipher mode.
	ErrUnknownAESCipherMode = errors.New("unknown AES cipher mode")
	// ErrAADCipherMode identifies additional authenticated data used outside GCM.
	ErrAADCipherMode = errors.New("--aad is only valid with --cipher-mode gcm")
	// ErrIVCipherMode identifies an initialization vector used outside CBC.
	ErrIVCipherMode = errors.New("--iv is only valid with --cipher-mode cbc")
	// ErrAESKeyOutputCollision identifies an output path that aliases the AES key file.
	ErrAESKeyOutputCollision = errors.New("AES keyfile and output collide")
)
