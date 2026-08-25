package asym

import "errors"

// Sentinel errors for the failure modes callers and tests match with errors.Is.
var (
	errNonTLSConnection   = errors.New("TLS dialer returned a non-TLS connection")
	errNoPeerCertificates = errors.New("TLS peer returned no certificates")
	errEmptyCertChain     = errors.New("certificate chain is empty")

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
	// ErrUnsupportedKeyType indicates a parsed key algorithm outside npc's supported set.
	ErrUnsupportedKeyType = errors.New("unsupported key type")
	// ErrUnsupportedKeyAlgorithm indicates a generation algorithm outside the supported registry.
	ErrUnsupportedKeyAlgorithm = errors.New("unsupported key generation algorithm")
	// ErrInvalidKeyConversion indicates an incompatible key type and output container.
	ErrInvalidKeyConversion = errors.New("invalid key conversion")
)
