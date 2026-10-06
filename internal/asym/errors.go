package asym

import "errors"

// Sentinel errors for the failure modes callers and tests match with errors.Is.
var (
	errEmptyCertChain = errors.New("certificate chain is empty")

	// ErrEmptyKeyInput indicates that no key bytes were provided.
	ErrEmptyKeyInput = errors.New("key input is empty")
	// ErrUnexpectedKeyPEMType indicates that a PEM block is not a supported key container.
	ErrUnexpectedKeyPEMType = errors.New("unexpected key PEM block type")
	// ErrTrailingKeyData indicates that key input contains more than one artifact.
	ErrTrailingKeyData = errors.New("key input contains trailing data")
	// ErrEncryptedPrivateKey indicates that passphrase-protected input is unsupported.
	ErrEncryptedPrivateKey = errors.New("encrypted private keys are unsupported")
	// ErrMalformedKey indicates that key bytes or key fields are invalid.
	ErrMalformedKey = errors.New("malformed key")
	// ErrUnsupportedKeyType indicates a parsed key algorithm outside swys's supported set.
	ErrUnsupportedKeyType = errors.New("unsupported key type")
	// ErrUnsupportedKeyAlgorithm indicates a generation algorithm outside the supported registry.
	ErrUnsupportedKeyAlgorithm = errors.New("unsupported key generation algorithm")
	// ErrInvalidKeyConversion indicates an incompatible key type and output container.
	ErrInvalidKeyConversion = errors.New("invalid key conversion")
	// ErrPrivateKeyRequired indicates that an operation requires private signing material.
	ErrPrivateKeyRequired = errors.New("private key required")
	// ErrInvalidCertificateOptions indicates an invalid certificate or CSR profile.
	ErrInvalidCertificateOptions = errors.New("invalid certificate options")
	// ErrIssuerNotCA indicates that an issuer certificate is not permitted to sign certificates.
	ErrIssuerNotCA = errors.New("issuer certificate is not a certificate authority")
	// ErrIssuerKeyMismatch indicates that an issuer certificate and private key have different public keys.
	ErrIssuerKeyMismatch = errors.New("issuer certificate and private key do not match")
	// ErrIssuerValidity indicates that an issuer or requested leaf validity window is unusable.
	ErrIssuerValidity = errors.New("invalid issuer validity")
)
