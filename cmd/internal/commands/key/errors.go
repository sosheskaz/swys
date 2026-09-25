// Package key constructs asymmetric-key generation and conversion commands.
package key

import "errors"

var (
	// ErrUnknownKeyAlgorithm identifies an unsupported key algorithm.
	ErrUnknownKeyAlgorithm = errors.New("unknown key algorithm")
	// ErrUnknownKeyConversionTarget identifies an unsupported key conversion target.
	ErrUnknownKeyConversionTarget = errors.New("unknown key conversion target")
	errUnknownKeyPublicFormat     = errors.New("unknown public key format")
	// ErrUnknownKeyFormat identifies an unsupported key output format.
	ErrUnknownKeyFormat = errors.New("unknown key output format")
	// ErrKeyOutputCollision identifies private and public key outputs that alias each other.
	ErrKeyOutputCollision      = errors.New("private and public key outputs collide")
	errInvalidKeyGenerateFlags = errors.New("invalid key generation flags")
)
