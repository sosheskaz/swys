// Package key constructs asymmetric-key generation and conversion commands.
package key

import "errors"

var (
	// ErrUnknownKeyConversionTarget identifies an unsupported key conversion target.
	ErrUnknownKeyConversionTarget = errors.New("unknown key conversion target")
	errUnknownKeyPublicFormat     = errors.New("unknown public key format")
	// ErrUnknownKeyFormat identifies an unsupported key output format.
	ErrUnknownKeyFormat = errors.New("unknown key output format")
)
