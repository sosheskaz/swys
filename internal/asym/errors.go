package asym

import "errors"

// Sentinel errors for the failure modes callers and tests match with errors.Is.
var (
	errNonTLSConnection   = errors.New("TLS dialer returned a non-TLS connection")
	errNoPeerCertificates = errors.New("TLS peer returned no certificates")
	errEmptyCertChain     = errors.New("certificate chain is empty")
)
