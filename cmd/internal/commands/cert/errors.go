package cert

import "errors"

var (
	// ErrUnknownKeyAlgorithm identifies an unsupported certificate-key algorithm.
	ErrUnknownKeyAlgorithm = errors.New("unknown key algorithm")
	// ErrKeyOutputCollision identifies private and public key outputs that alias each other.
	ErrKeyOutputCollision      = errors.New("private and public key outputs collide")
	errInvalidKeyGenerateFlags = errors.New("invalid key generation flags")
	errUnknownKeyPublicFormat  = errors.New("unknown public key format")
	errUnknownCertFormat       = errors.New("unknown output format")
	errInvalidCertificateFlags = errors.New("invalid certificate flags")
	// ErrCertificateInputSelection identifies invalid artifact input selection for stdin.
	ErrCertificateInputSelection = errors.New("invalid certificate stdin selection")
	errNoPeerCertificates        = errors.New("TLS peer returned no certificates")
)
