package cert

import "errors"

var (
	errUnknownCertFormat       = errors.New("unknown output format")
	errInvalidCertificateFlags = errors.New("invalid certificate flags")
	// ErrCertificateInputSelection identifies invalid artifact input selection for stdin.
	ErrCertificateInputSelection = errors.New("invalid certificate stdin selection")
	errNoPeerCertificates        = errors.New("TLS peer returned no certificates")
)
