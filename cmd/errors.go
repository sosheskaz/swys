package cmd

import "errors"

// Sentinel errors for the failure modes callers and tests match with errors.Is.
// Dynamic detail is attached by wrapping these with fmt.Errorf and %w.
var (
	errKeySelection               = errors.New("exactly one of key or keyfile must be set")
	errUnknownCertFormat          = errors.New("unknown output format")
	errInvalidAESKeySize          = errors.New("AES key size must be 128, 192, or 256 bits")
	errSameInputOutput            = errors.New("input and output refer to the same file")
	errOutputIsDirectory          = errors.New("output is a directory")
	errUnexpectedPEMType          = errors.New("unexpected PEM block type")
	errNoPEMCertificates          = errors.New("no valid PEM certificates found")
	errUnknownKeyAlgorithm        = errors.New("unknown key algorithm")
	errUnknownKeyConversionTarget = errors.New("unknown key conversion target")
	errUnknownKeyFormat           = errors.New("unknown key output format")
)
