package cert

import "errors"

var (
	// ErrUnknownKeyConversionTarget identifies an unsupported key conversion target.
	ErrUnknownKeyConversionTarget = errors.New("unknown key conversion target")
	errUnknownKeyPublicFormat     = errors.New("unknown public key format")
	// ErrUnknownKeyFormat identifies an unsupported key output format.
	ErrUnknownKeyFormat = errors.New("unknown key output format")
	// ErrUnknownKeyAlgorithm identifies an unsupported certificate-key algorithm.
	ErrUnknownKeyAlgorithm = errors.New("unknown key algorithm")
	// ErrKeyOutputCollision identifies private and public key outputs that alias each other.
	ErrKeyOutputCollision      = errors.New("private and public key outputs collide")
	errInvalidKeyGenerateFlags = errors.New("invalid key generation flags")
	errUnknownCertFormat       = errors.New("unknown output format")
	errInvalidCertificateFlags = errors.New("invalid certificate flags")
	// ErrCertificateInputSelection identifies invalid artifact input selection for stdin.
	ErrCertificateInputSelection = errors.New("invalid certificate stdin selection")
	errNoPeerCertificates        = errors.New("TLS peer returned no certificates")
)
