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
	errUnknownKeyPublicFormat     = errors.New("unknown public key format")
	errUnknownKeyFormat           = errors.New("unknown key output format")
	errKeyOutputCollision         = errors.New("private and public key outputs collide")
	errInvalidKeyGenerateFlags    = errors.New("invalid key generation flags")
	errInvalidCertificateFlags    = errors.New("invalid certificate flags")
	errCertificateInputSelection  = errors.New("invalid certificate stdin selection")
	errCertificatePathCollision   = errors.New("certificate input and output paths collide")
	errTrailingCertificateData    = errors.New("certificate input contains trailing data")
	errInvalidNetworkFlags        = errors.New("invalid network flags")
	errTLSClientKeyMismatch       = errors.New("TLS client certificate and private key do not match")
	errTLSServerKeyMismatch       = errors.New("TLS server certificate and private key do not match")
	errNoPeerCertificates         = errors.New("TLS peer returned no certificates")
)
