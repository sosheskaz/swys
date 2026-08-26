package asym

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KeyAlgorithm identifies a private-key generation profile.
type KeyAlgorithm string

const (
	// KeyAlgorithmEd25519 generates an Ed25519 key.
	KeyAlgorithmEd25519 KeyAlgorithm = "ed25519"
	// KeyAlgorithmECDSAP256 generates an ECDSA P-256 key.
	KeyAlgorithmECDSAP256 KeyAlgorithm = "ecdsa-p256"
	// KeyAlgorithmECDSAP384 generates an ECDSA P-384 key.
	KeyAlgorithmECDSAP384 KeyAlgorithm = "ecdsa-p384"
	// KeyAlgorithmRSA2048 generates an RSA-2048 key.
	KeyAlgorithmRSA2048 KeyAlgorithm = "rsa-2048"
	// KeyAlgorithmRSA4096 generates an RSA-4096 key.
	KeyAlgorithmRSA4096 KeyAlgorithm = "rsa-4096"
)

// KeyFormat identifies a key serialization container.
type KeyFormat string

const (
	// KeyFormatPKCS8PEM serializes a private key as PKCS#8 PEM.
	KeyFormatPKCS8PEM KeyFormat = "pkcs8-pem"
	// KeyFormatPKCS8DER serializes a private key as PKCS#8 DER.
	KeyFormatPKCS8DER KeyFormat = "pkcs8-der"
	// KeyFormatPKCS1PEM serializes an RSA private key as PKCS#1 PEM.
	KeyFormatPKCS1PEM KeyFormat = "pkcs1-pem"
	// KeyFormatPKCS1DER serializes an RSA private key as PKCS#1 DER.
	KeyFormatPKCS1DER KeyFormat = "pkcs1-der"
	// KeyFormatSEC1PEM serializes an ECDSA private key as SEC1 PEM.
	KeyFormatSEC1PEM KeyFormat = "sec1-pem"
	// KeyFormatSEC1DER serializes an ECDSA private key as SEC1 DER.
	KeyFormatSEC1DER KeyFormat = "sec1-der"
	// KeyFormatPKIXPEM serializes a public key as PKIX PEM.
	KeyFormatPKIXPEM KeyFormat = "pkix-pem"
	// KeyFormatPKIXDER serializes a public key as PKIX DER.
	KeyFormatPKIXDER KeyFormat = "pkix-der"
	// KeyFormatOpenSSH serializes a public key in OpenSSH authorized_keys form.
	KeyFormatOpenSSH KeyFormat = "openssh"
)

// KeyType distinguishes private and public input artifacts.
type KeyType string

const (
	// KeyTypePrivate identifies a private key.
	KeyTypePrivate KeyType = "private"
	// KeyTypePublic identifies a public key.
	KeyTypePublic KeyType = "public"
)

// Key is one validated supported public or private key.
type Key struct {
	material any
	private  bool
}

// KeyInfo contains safe metadata derived from a key's public part.
type KeyInfo struct {
	KeyType                    KeyType `json:"key_type"`
	Algorithm                  string  `json:"algorithm"`
	Curve                      string  `json:"curve,omitempty"`
	PublicKeySHA256Fingerprint string  `json:"public_key_sha256_fingerprint"`
	Bits                       int     `json:"bits"`
}

// GeneratePrivateKey creates a private key using a secure standard-library generator.
func GeneratePrivateKey(algorithm KeyAlgorithm) (crypto.PrivateKey, error) {
	switch algorithm {
	case KeyAlgorithmEd25519:
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate Ed25519 key: %w", err)
		}
		return privateKey, nil
	case KeyAlgorithmECDSAP256:
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ECDSA P-256 key: %w", err)
		}
		return privateKey, nil
	case KeyAlgorithmECDSAP384:
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ECDSA P-384 key: %w", err)
		}
		return privateKey, nil
	case KeyAlgorithmRSA2048:
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate RSA-2048 key: %w", err)
		}
		return privateKey, nil
	case KeyAlgorithmRSA4096:
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, fmt.Errorf("generate RSA-4096 key: %w", err)
		}
		return privateKey, nil
	default:
		return nil, fmt.Errorf("%w %q", ErrUnsupportedKeyAlgorithm, algorithm)
	}
}

// NewKey validates and wraps a supported public or private key.
func NewKey(material any) (*Key, error) {
	switch typed := material.(type) {
	case *rsa.PrivateKey:
		if err := typed.Validate(); err != nil {
			return nil, fmt.Errorf("%w: validate RSA private key: %w", ErrMalformedKey, err)
		}
		return &Key{material: typed, private: true}, nil
	case *ecdsa.PrivateKey:
		if err := validateECDSAPrivateKey(typed); err != nil {
			return nil, err
		}
		return &Key{material: typed, private: true}, nil
	case ed25519.PrivateKey:
		if len(typed) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: Ed25519 private key is %d bytes, want %d", ErrMalformedKey, len(typed), ed25519.PrivateKeySize)
		}
		return &Key{material: typed, private: true}, nil
	case *rsa.PublicKey:
		if err := validateRSAPublicKey(typed); err != nil {
			return nil, err
		}
		return &Key{material: typed}, nil
	case *ecdsa.PublicKey:
		if err := validateECDSAPublicKey(typed); err != nil {
			return nil, err
		}
		return &Key{material: typed}, nil
	case ed25519.PublicKey:
		if len(typed) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: Ed25519 public key is %d bytes, want %d", ErrMalformedKey, len(typed), ed25519.PublicKeySize)
		}
		return &Key{material: typed}, nil
	default:
		return nil, fmt.Errorf("%w %T", ErrUnsupportedKeyType, material)
	}
}

func validateRSAPublicKey(key *rsa.PublicKey) error {
	if key == nil || key.N == nil {
		return fmt.Errorf("%w: missing RSA public modulus", ErrMalformedKey)
	}
	if key.N.Sign() <= 0 || key.N.BitLen() < 2 {
		return fmt.Errorf("%w: RSA public modulus must be greater than one", ErrMalformedKey)
	}
	if key.N.Bit(0) == 0 {
		return fmt.Errorf("%w: RSA public modulus is even", ErrMalformedKey)
	}
	if key.E < 2 {
		return fmt.Errorf("%w: RSA public exponent is too small or negative", ErrMalformedKey)
	}
	if key.E&1 == 0 {
		return fmt.Errorf("%w: RSA public exponent is even", ErrMalformedKey)
	}
	if key.E > 1<<31-1 {
		return fmt.Errorf("%w: RSA public exponent is too large", ErrMalformedKey)
	}
	return nil
}

func validateECDSAPrivateKey(key *ecdsa.PrivateKey) error {
	if key == nil || key.D == nil || key.Curve == nil {
		return fmt.Errorf("%w: incomplete ECDSA private key", ErrMalformedKey)
	}
	parameters := key.Params()
	if parameters == nil || parameters.N == nil {
		return fmt.Errorf("%w: ECDSA curve parameters are incomplete", ErrMalformedKey)
	}
	order := parameters.N
	if key.D.Sign() <= 0 || key.D.Cmp(order) >= 0 {
		return fmt.Errorf("%w: ECDSA private scalar is out of range", ErrMalformedKey)
	}
	return validateECDSAPublicKey(&key.PublicKey)
}

func validateECDSAPublicKey(key *ecdsa.PublicKey) error {
	if key == nil || key.Curve == nil || key.X == nil || key.Y == nil {
		return fmt.Errorf("%w: invalid ECDSA public key fields", ErrMalformedKey)
	}
	switch key.Curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
	default:
		return fmt.Errorf("%w: ECDSA curve %T", ErrUnsupportedKeyType, key.Curve)
	}
	if _, err := key.ECDH(); err != nil {
		return fmt.Errorf("%w: validate ECDSA public key: %w", ErrMalformedKey, err)
	}
	return nil
}

// ParseKey parses one supported PEM or DER key artifact.
func ParseKey(data []byte) (*Key, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, ErrEmptyKeyInput
	}
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return parsePEMKey(trimmed)
	}
	return parseDERKey(data)
}

func parsePEMKey(data []byte) (*Key, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: decode PEM block", ErrMalformedKey)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrTrailingKeyData
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" || block.Headers["Proc-Type"] != "" || block.Headers["DEK-Info"] != "" {
		return nil, ErrEncryptedPrivateKey
	}

	var (
		material any
		err      error
	)
	switch block.Type {
	case "PRIVATE KEY":
		material, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		material, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		material, err = x509.ParseECPrivateKey(block.Bytes)
	case "PUBLIC KEY":
		material, err = x509.ParsePKIXPublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%w %q; expected PRIVATE KEY, RSA PRIVATE KEY, EC PRIVATE KEY, or PUBLIC KEY", ErrUnexpectedKeyPEMType, block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: parse %s: %w", ErrMalformedKey, block.Type, err)
	}
	return NewKey(material)
}

func parseDERKey(data []byte) (*Key, error) {
	parsers := []struct {
		parse func([]byte) (any, error)
		name  string
	}{
		{name: "PKCS#8 private key", parse: x509.ParsePKCS8PrivateKey},
		{name: "PKCS#1 RSA private key", parse: func(der []byte) (any, error) { return x509.ParsePKCS1PrivateKey(der) }},
		{name: "SEC1 EC private key", parse: func(der []byte) (any, error) { return x509.ParseECPrivateKey(der) }},
		{name: "PKIX public key", parse: x509.ParsePKIXPublicKey},
	}
	parseErrors := make([]error, 0, len(parsers))
	for _, parser := range parsers {
		material, err := parser.parse(data)
		if err == nil {
			return NewKey(material)
		}
		parseErrors = append(parseErrors, fmt.Errorf("parse as %s: %w", parser.name, err))
	}
	return nil, fmt.Errorf("%w: no supported DER key format matched: %w", ErrMalformedKey, errors.Join(parseErrors...))
}

// IsPrivate reports whether the parsed artifact contains private key material.
func (key *Key) IsPrivate() bool {
	return key.private
}

// Signer returns validated private signing material.
func (key *Key) Signer() (crypto.Signer, error) {
	if key == nil || !key.private {
		return nil, ErrPrivateKeyRequired
	}
	signer, ok := key.material.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: private key %T does not implement crypto.Signer", ErrUnsupportedKeyType, key.material)
	}
	return signer, nil
}

// Public returns the key's validated public part.
func (key *Key) Public() (crypto.PublicKey, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: nil key", ErrMalformedKey)
	}
	if !key.private {
		return key.material, nil
	}
	signer, err := key.Signer()
	if err != nil {
		return nil, fmt.Errorf("access private-key signer: %w", err)
	}
	publicKey := signer.Public()
	if _, err := NewKey(publicKey); err != nil {
		return nil, fmt.Errorf("validate derived public key: %w", err)
	}
	return publicKey, nil
}

// Info derives safe metadata from a key without retaining private bytes.
func (key *Key) Info() (*KeyInfo, error) {
	publicKey, err := key.Public()
	if err != nil {
		return nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key for fingerprint: %w", err)
	}
	fingerprint := sha256.Sum256(publicDER)
	info := &KeyInfo{PublicKeySHA256Fingerprint: formatFingerprint(fingerprint[:])}
	if key.private {
		info.KeyType = KeyTypePrivate
	} else {
		info.KeyType = KeyTypePublic
	}

	switch typed := publicKey.(type) {
	case *rsa.PublicKey:
		info.Algorithm = "rsa"
		info.Bits = typed.N.BitLen()
	case *ecdsa.PublicKey:
		info.Algorithm = "ecdsa"
		info.Bits = typed.Curve.Params().BitSize
		info.Curve = typed.Curve.Params().Name
	case ed25519.PublicKey:
		info.Algorithm = "ed25519"
		info.Bits = ed25519.PublicKeySize * 8
	default:
		return nil, fmt.Errorf("%w %T", ErrUnsupportedKeyType, publicKey)
	}
	return info, nil
}

// Marshal serializes a key into one supported target format.
func (key *Key) Marshal(format KeyFormat) ([]byte, error) {
	switch format {
	case KeyFormatPKCS8PEM, KeyFormatPKCS8DER,
		KeyFormatPKCS1PEM, KeyFormatPKCS1DER,
		KeyFormatSEC1PEM, KeyFormatSEC1DER:
		return key.marshalPrivate(format)
	case KeyFormatPKIXPEM, KeyFormatPKIXDER, KeyFormatOpenSSH:
		return key.marshalPublic(format)
	default:
		return nil, invalidConversion(key, format)
	}
}

func (key *Key) marshalPrivate(format KeyFormat) ([]byte, error) {
	if !key.private {
		return nil, invalidConversion(key, format)
	}
	switch format {
	case KeyFormatPKCS8PEM, KeyFormatPKCS8DER:
		der, err := x509.MarshalPKCS8PrivateKey(key.material)
		if err != nil {
			return nil, fmt.Errorf("marshal PKCS#8 private key: %w", err)
		}
		return encodeKeyContainer(format, "PRIVATE KEY", der), nil
	case KeyFormatPKCS1PEM, KeyFormatPKCS1DER:
		privateKey, ok := key.material.(*rsa.PrivateKey)
		if !ok {
			return nil, invalidConversion(key, format)
		}
		return encodeKeyContainer(format, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privateKey)), nil
	case KeyFormatSEC1PEM, KeyFormatSEC1DER:
		privateKey, ok := key.material.(*ecdsa.PrivateKey)
		if !ok {
			return nil, invalidConversion(key, format)
		}
		der, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("marshal SEC1 private key: %w", err)
		}
		return encodeKeyContainer(format, "EC PRIVATE KEY", der), nil
	case KeyFormatPKIXPEM, KeyFormatPKIXDER, KeyFormatOpenSSH:
		return nil, invalidConversion(key, format)
	default:
		return nil, invalidConversion(key, format)
	}
}

func (key *Key) marshalPublic(format KeyFormat) ([]byte, error) {
	publicKey, err := key.Public()
	if err != nil {
		return nil, err
	}
	if format == KeyFormatOpenSSH {
		sshKey, err := ssh.NewPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("create OpenSSH public key: %w", err)
		}
		return ssh.MarshalAuthorizedKey(sshKey), nil
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal PKIX public key: %w", err)
	}
	return encodeKeyContainer(format, "PUBLIC KEY", der), nil
}

func encodeKeyContainer(format KeyFormat, pemType string, der []byte) []byte {
	if strings.HasSuffix(string(format), "-pem") {
		return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der})
	}
	return der
}

func invalidConversion(key *Key, format KeyFormat) error {
	kind := KeyTypePublic
	if key.private {
		kind = KeyTypePrivate
	}
	return fmt.Errorf("%w: cannot serialize %s key %T as %q", ErrInvalidKeyConversion, kind, key.material, format)
}
