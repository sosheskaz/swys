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

	"github.com/sosheskaz-systems/npc/internal/pemstrict"
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
	if key == nil || key.D == nil || key.Curve == nil { //nolint:staticcheck // Bytes dereferences D; guard incomplete caller-supplied keys.
		return fmt.Errorf("%w: incomplete ECDSA private key", ErrMalformedKey)
	}
	if err := validateECDSAPublicKey(&key.PublicKey); err != nil {
		return err
	}
	if _, err := key.Bytes(); err != nil {
		return fmt.Errorf("%w: validate ECDSA private key: %w", ErrMalformedKey, err)
	}
	return nil
}

func validateECDSAPublicKey(key *ecdsa.PublicKey) error {
	if key == nil || key.Curve == nil || key.X == nil || key.Y == nil { //nolint:staticcheck // Bytes dereferences X and Y; guard incomplete keys.
		return fmt.Errorf("%w: invalid ECDSA public key fields", ErrMalformedKey)
	}
	switch key.Curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
	default:
		return fmt.Errorf("%w: ECDSA curve %T", ErrUnsupportedKeyType, key.Curve)
	}
	if _, err := key.Bytes(); err != nil {
		return fmt.Errorf("%w: validate ECDSA public key: %w", ErrMalformedKey, err)
	}
	return nil
}

// ParseKey parses one supported PEM, DER, or OpenSSH key artifact.
func ParseKey(data []byte) (*Key, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, ErrEmptyKeyInput
	}
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN OPENSSH PRIVATE KEY-----")) {
		return parseOpenSSHPrivateKey(trimmed)
	}
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return parsePEMKey(trimmed)
	}
	key, derErr := parseDERKey(data)
	if derErr == nil {
		return key, nil
	}
	if !errors.Is(derErr, ErrMalformedKey) {
		return nil, derErr
	}
	key, openSSHErr := parseOpenSSHPublicKey(trimmed)
	if openSSHErr == nil {
		return key, nil
	}
	if !errors.Is(openSSHErr, ErrMalformedKey) {
		return nil, openSSHErr
	}
	return nil, errors.Join(derErr, openSSHErr)
}

func parseOpenSSHPrivateKey(data []byte) (*Key, error) {
	block, rest := pemstrict.Decode(data)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		return nil, fmt.Errorf("%w: decode OpenSSH private key", ErrMalformedKey)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrTrailingKeyData
	}
	envelope, err := parseOpenSSHPrivateEnvelope(block.Bytes)
	if err != nil {
		return nil, err
	}

	material, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		var passphraseMissing *ssh.PassphraseMissingError
		if errors.As(err, &passphraseMissing) {
			return nil, ErrEncryptedPrivateKey
		}
		if openSSHPublicKeyTypeUnsupported(envelope.PublicKey) {
			return nil, fmt.Errorf("%w: OpenSSH private key", ErrUnsupportedKeyType)
		}
		return nil, fmt.Errorf("%w: parse OpenSSH private key: %w", ErrMalformedKey, err)
	}
	if pointer, ok := material.(*ed25519.PrivateKey); ok {
		if pointer == nil {
			return nil, fmt.Errorf("%w: nil Ed25519 private key", ErrMalformedKey)
		}
		material = *pointer
	}
	key, err := NewKey(material)
	if err != nil {
		return nil, err
	}
	if err := validateOpenSSHPrivateIdentity(envelope, key); err != nil {
		return nil, err
	}
	return key, nil
}

func parseOpenSSHPublicKey(data []byte) (*Key, error) {
	nonComment := make([][]byte, 0, 1)
	for line := range bytes.Lines(data) {
		line = bytes.TrimSuffix(line, []byte{'\n'})
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if bytes.ContainsRune(line, '\r') {
			return nil, fmt.Errorf("%w: bare carriage return in authorized_keys input", ErrMalformedKey)
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		nonComment = append(nonComment, line)
	}

	if len(nonComment) != 1 {
		validLines := 0
		for _, line := range nonComment {
			if _, _, _, rest, err := ssh.ParseAuthorizedKey(append(append([]byte(nil), line...), '\n')); err == nil && len(bytes.TrimSpace(rest)) == 0 {
				validLines++
			}
		}
		if validLines > 1 {
			return nil, ErrTrailingKeyData
		}
		return nil, fmt.Errorf("%w: authorized_keys input must contain exactly one valid non-comment line", ErrMalformedKey)
	}

	publicKey, _, _, rest, err := ssh.ParseAuthorizedKey(append(append([]byte(nil), nonComment[0]...), '\n'))
	if err != nil {
		return nil, fmt.Errorf("%w: parse authorized_keys input: %w", ErrMalformedKey, err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: trailing authorized_keys data", ErrMalformedKey)
	}
	cryptoPublicKey, ok := publicKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: OpenSSH public key type %q", ErrUnsupportedKeyType, publicKey.Type())
	}
	return NewKey(cryptoPublicKey.CryptoPublicKey())
}

type openSSHPrivateEnvelope struct { //nolint:govet // Field order is the OpenSSH wire format consumed by ssh.Unmarshal.
	CipherName   string
	KDFName      string
	KDFOptions   string
	NumKeys      uint32
	PublicKey    []byte
	PrivateBlock []byte
	Rest         []byte `ssh:"rest"`
}

func parseOpenSSHPrivateEnvelope(data []byte) (*openSSHPrivateEnvelope, error) {
	const authMagic = "openssh-key-v1\x00"
	if len(data) < len(authMagic) || string(data[:len(authMagic)]) != authMagic {
		return nil, fmt.Errorf("%w: invalid OpenSSH private-key envelope", ErrMalformedKey)
	}
	var envelope openSSHPrivateEnvelope
	if err := ssh.Unmarshal(data[len(authMagic):], &envelope); err != nil {
		return nil, fmt.Errorf("%w: parse OpenSSH private-key envelope: %w", ErrMalformedKey, err)
	}
	if len(envelope.Rest) != 0 {
		return nil, ErrTrailingKeyData
	}
	return &envelope, nil
}

func validateOpenSSHPrivateIdentity(envelope *openSSHPrivateEnvelope, key *Key) error {
	// The upstream parser decodes private material but does not check all
	// duplicated public fields or enforce the unencrypted cipher's block size.
	if len(envelope.PrivateBlock) < 8 || len(envelope.PrivateBlock)%8 != 0 {
		return fmt.Errorf("%w: unaligned OpenSSH private block", ErrMalformedKey)
	}
	public, err := key.Public()
	if err != nil {
		return err
	}
	canonical, err := ssh.NewPublicKey(public)
	if err != nil {
		return fmt.Errorf("%w: encode OpenSSH public key: %w", ErrMalformedKey, err)
	}
	outer, err := ssh.ParsePublicKey(envelope.PublicKey)
	if err != nil || !bytes.Equal(outer.Marshal(), canonical.Marshal()) {
		return fmt.Errorf("%w: OpenSSH envelope public key does not match private key", ErrMalformedKey)
	}
	header := struct { //nolint:govet // Field order is the SSH private-block wire format.
		Check1, Check2 uint32
		Type           string
		Rest           []byte `ssh:"rest"`
	}{}
	if err := ssh.Unmarshal(envelope.PrivateBlock, &header); err != nil {
		return fmt.Errorf("%w: decode OpenSSH private header: %w", ErrMalformedKey, err)
	}
	if header.Type != canonical.Type() {
		return fmt.Errorf("%w: OpenSSH private key type does not match public key", ErrMalformedKey)
	}
	if private, ok := key.material.(ed25519.PrivateKey); ok {
		fields := struct {
			Public, Private []byte
			Comment         string
			Padding         []byte `ssh:"rest"`
		}{}
		if err := ssh.Unmarshal(header.Rest, &fields); err != nil {
			return fmt.Errorf("%w: decode OpenSSH Ed25519 fields: %w", ErrMalformedKey, err)
		}
		derived := ed25519.NewKeyFromSeed(private.Seed())
		if !bytes.Equal(private, derived) || !bytes.Equal(fields.Public, derived[ed25519.SeedSize:]) {
			return fmt.Errorf("%w: inconsistent OpenSSH Ed25519 key fields", ErrMalformedKey)
		}
	}
	return nil
}

func openSSHPublicKeyTypeUnsupported(publicKeyBlob []byte) bool {
	publicKey, err := ssh.ParsePublicKey(publicKeyBlob)
	if err != nil {
		return false
	}
	cryptoPublicKey, ok := publicKey.(ssh.CryptoPublicKey)
	if !ok {
		return true
	}
	_, err = NewKey(cryptoPublicKey.CryptoPublicKey())
	return errors.Is(err, ErrUnsupportedKeyType)
}

func parsePEMKey(data []byte) (*Key, error) {
	block, rest := pemstrict.Decode(data)
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
