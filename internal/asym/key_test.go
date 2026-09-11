package asym

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA is intentionally used to verify unsupported-key rejection.
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

var errKeyTestWriteFailed = errors.New("write failed")

func TestKeyPrivateFormatRoundTrips(t *testing.T) {
	t.Parallel()

	tests := []struct {
		algorithm KeyAlgorithm
		formats   []KeyFormat
	}{
		{algorithm: KeyAlgorithmEd25519, formats: []KeyFormat{KeyFormatPKCS8PEM, KeyFormatPKCS8DER}},
		{algorithm: KeyAlgorithmECDSAP256, formats: []KeyFormat{KeyFormatPKCS8PEM, KeyFormatPKCS8DER, KeyFormatSEC1PEM, KeyFormatSEC1DER}},
		{algorithm: KeyAlgorithmRSA2048, formats: []KeyFormat{KeyFormatPKCS8PEM, KeyFormatPKCS8DER, KeyFormatPKCS1PEM, KeyFormatPKCS1DER}},
	}

	for _, test := range tests {
		t.Run(string(test.algorithm), func(t *testing.T) {
			t.Parallel()
			privateKey, err := GeneratePrivateKey(test.algorithm)
			if err != nil {
				t.Fatal(err)
			}
			key, err := NewKey(privateKey)
			if err != nil {
				t.Fatal(err)
			}
			wantPublic := mustPublicDER(t, key)
			wantPKCS8 := mustMarshalKey(t, key, KeyFormatPKCS8DER)

			for _, format := range test.formats {
				t.Run(string(format), func(t *testing.T) {
					encoded, err := key.Marshal(format)
					if err != nil {
						t.Fatal(err)
					}
					parsed, err := ParseKey(encoded)
					if err != nil {
						t.Fatal(err)
					}
					if !parsed.IsPrivate() {
						t.Fatal("parsed key is public, want private")
					}
					if got := mustPublicDER(t, parsed); !bytes.Equal(got, wantPublic) {
						t.Fatal("round-tripped public key differs")
					}
					if got := mustMarshalKey(t, parsed, KeyFormatPKCS8DER); !bytes.Equal(got, wantPKCS8) {
						t.Fatal("round-tripped canonical PKCS#8 DER differs")
					}
				})
			}
		})
	}
}

func TestParseKeyAcceptsOpenSSHPrivateKeys(t *testing.T) {
	t.Parallel()

	privateKeys := []crypto.PrivateKey{
		mustGenerateOpenSSHTestKey(t, KeyAlgorithmEd25519),
		mustGenerateOpenSSHTestKey(t, KeyAlgorithmRSA2048),
		mustGenerateOpenSSHTestKey(t, KeyAlgorithmECDSAP256),
		mustGenerateOpenSSHTestKey(t, KeyAlgorithmECDSAP384),
		mustGenerateECDSAKey(t, elliptic.P521()),
	}
	for _, privateKey := range privateKeys {
		t.Run(fmt.Sprintf("%T", privateKey), func(t *testing.T) {
			t.Parallel()
			block, err := ssh.MarshalPrivateKey(privateKey, "generated fixture")
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseKey(pem.EncodeToMemory(block))
			if err != nil {
				t.Fatal(err)
			}
			if !parsed.IsPrivate() {
				t.Fatal("parsed OpenSSH key is public, want private")
			}
			want, err := NewKey(privateKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(mustPublicDER(t, parsed), mustPublicDER(t, want)) {
				t.Fatal("parsed OpenSSH public key differs")
			}
		})
	}
}

func TestParseKeyAcceptsOneAuthorizedKeyEntry(t *testing.T) {
	t.Parallel()

	privateKeys := []crypto.PrivateKey{
		mustGenerateOpenSSHTestKey(t, KeyAlgorithmEd25519),
		mustGenerateOpenSSHTestKey(t, KeyAlgorithmRSA2048),
		mustGenerateOpenSSHTestKey(t, KeyAlgorithmECDSAP256),
		mustGenerateOpenSSHTestKey(t, KeyAlgorithmECDSAP384),
		mustGenerateECDSAKey(t, elliptic.P521()),
	}
	for _, privateKey := range privateKeys {
		signer, ok := privateKey.(crypto.Signer)
		if !ok {
			t.Fatalf("private key %T does not implement crypto.Signer", privateKey)
		}
		publicKey, err := ssh.NewPublicKey(signer.Public())
		if err != nil {
			t.Fatal(err)
		}
		line := bytes.TrimSpace(ssh.MarshalAuthorizedKey(publicKey))
		fixture := append([]byte("\n# generated fixture\nrestrict,command=\"npc test\" "), line...)
		fixture = append(fixture, []byte(" user@example\n\n")...)
		parsed, err := ParseKey(fixture)
		if err != nil {
			t.Fatalf("ParseKey(%s): %v", publicKey.Type(), err)
		}
		if parsed.IsPrivate() {
			t.Fatalf("ParseKey(%s) is private, want public", publicKey.Type())
		}
	}
}

func TestParseKeyRejectsInvalidOpenSSHInputs(t *testing.T) {
	t.Parallel()

	privateKey := mustGenerateOpenSSHTestKey(t, KeyAlgorithmEd25519)
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("private key %T does not implement crypto.Signer", privateKey)
	}
	publicKey, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	publicLine := ssh.MarshalAuthorizedKey(publicKey)
	privateBlock, err := ssh.MarshalPrivateKey(privateKey, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(privateBlock)
	privateEnvelopeTrailing := pem.EncodeToMemory(&pem.Block{
		Type:  privateBlock.Type,
		Bytes: append(append([]byte(nil), privateBlock.Bytes...), []byte("trailing")...),
	})
	encryptedBlock, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, "fixture", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		want error
		name string
		data []byte
	}{
		{name: "encrypted private", data: pem.EncodeToMemory(encryptedBlock), want: ErrEncryptedPrivateKey},
		{name: "private trailing junk", data: append(append([]byte(nil), privatePEM...), []byte("junk")...), want: ErrTrailingKeyData},
		{name: "private envelope trailing junk", data: privateEnvelopeTrailing, want: ErrTrailingKeyData},
		{name: "two public keys", data: append(append([]byte(nil), publicLine...), publicLine...), want: ErrTrailingKeyData},
		{name: "malformed line before public key", data: append([]byte("not-a-key\n"), publicLine...), want: ErrMalformedKey},
		{name: "malformed public key", data: []byte("ssh-ed25519 invalid"), want: ErrMalformedKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseKey(test.data)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if errors.Is(test.want, ErrTrailingKeyData) && errors.Is(err, ErrMalformedKey) {
				t.Fatalf("error = %v, trailing data must not be classified as malformed", err)
			}
		})
	}
}

func TestParseKeyRejectsUnsupportedOpenSSHTypes(t *testing.T) {
	t.Parallel()

	var parameters dsa.Parameters
	if err := dsa.GenerateParameters(&parameters, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	privateKey := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: parameters}}
	if err := dsa.GenerateKey(privateKey, rand.Reader); err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKey(ssh.MarshalAuthorizedKey(publicKey)); !errors.Is(err, ErrUnsupportedKeyType) || errors.Is(err, ErrMalformedKey) {
		t.Fatalf("DSA public error = %v, want only unsupported key type", err)
	}
	unsupportedDERKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(unsupportedDERKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKey(publicDER); !errors.Is(err, ErrUnsupportedKeyType) || errors.Is(err, ErrMalformedKey) {
		t.Fatalf("X25519 DER error = %v, want only unsupported key type", err)
	}

	const authMagic = "openssh-key-v1\x00"
	privateEnvelope := struct { //nolint:govet // Field order is the fixture's OpenSSH private-block wire format.
		Check1 uint32
		Check2 uint32
		Type   string
		Rest   []byte `ssh:"rest"`
	}{Check1: 1, Check2: 1, Type: ssh.InsecureKeyAlgoDSA} //nolint:staticcheck // DSA is intentionally unsupported fixture data.
	envelope := struct { //nolint:govet // Field order is the fixture's OpenSSH envelope wire format.
		CipherName   string
		KDFName      string
		KDFOptions   string
		NumKeys      uint32
		PublicKey    []byte
		PrivateBlock []byte
	}{
		CipherName: "none", KDFName: "none", NumKeys: 1,
		PublicKey: publicKey.Marshal(), PrivateBlock: ssh.Marshal(privateEnvelope),
	}
	block := &pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: append([]byte(authMagic), ssh.Marshal(envelope)...)}
	if _, err := ParseKey(pem.EncodeToMemory(block)); !errors.Is(err, ErrUnsupportedKeyType) || errors.Is(err, ErrMalformedKey) {
		t.Fatalf("DSA private error = %v, want only unsupported key type", err)
	}
}

func TestKeyPublicFormatsCanonicalizePrivateAndPublicInput(t *testing.T) {
	t.Parallel()

	privateKey, err := GeneratePrivateKey(KeyAlgorithmEd25519)
	if err != nil {
		t.Fatal(err)
	}
	private, err := NewKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	wantPublic := mustPublicDER(t, private)

	for _, source := range []*Key{private, mustParseKey(t, mustMarshalKey(t, private, KeyFormatPKIXPEM))} {
		for _, format := range []KeyFormat{KeyFormatPKIXPEM, KeyFormatPKIXDER} {
			encoded, err := source.Marshal(format)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseKey(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.IsPrivate() {
				t.Fatal("public serialization parsed as private")
			}
			if got := mustPublicDER(t, parsed); !bytes.Equal(got, wantPublic) {
				t.Fatal("canonical public key differs")
			}
		}
	}
}

func TestParseKeyPreservesWhitespaceValuedDERTrailer(t *testing.T) {
	t.Parallel()

	for _, trailer := range []byte{'\t', '\n', '\v', '\f', '\r', ' '} {
		publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
		publicKey[len(publicKey)-1] = trailer
		der, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		if der[len(der)-1] != trailer {
			t.Fatalf("DER trailer = %#x, want %#x", der[len(der)-1], trailer)
		}
		if _, err := ParseKey(der); err != nil {
			t.Fatalf("ParseKey with DER trailer %#x: %v", trailer, err)
		}
	}
}

func TestKeyOpenSSHRoundTrip(t *testing.T) {
	t.Parallel()

	privateKey, err := GeneratePrivateKey(KeyAlgorithmECDSAP384)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := key.Marshal(KeyFormatOpenSSH)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, _, _, rest, err := ssh.ParseAuthorizedKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("OpenSSH trailing data = %q", rest)
	}
	cryptoPublic, ok := sshPublic.(ssh.CryptoPublicKey)
	if !ok {
		t.Fatalf("OpenSSH key type = %T, want crypto public key", sshPublic)
	}
	parsed, err := NewKey(cryptoPublic.CryptoPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustPublicDER(t, parsed), mustPublicDER(t, key)) {
		t.Fatal("OpenSSH public key differs")
	}
}

func TestKeyInfoAndFormattersContainMetadataOnly(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	info, err := key.Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.KeyType != KeyTypePrivate || info.Algorithm != "ed25519" || info.Bits != 256 || info.Curve != "" {
		t.Fatalf("key info = %+v", info)
	}
	publicDER := mustPublicDER(t, key)
	fingerprint := sha256.Sum256(publicDER)
	if info.PublicKeySHA256Fingerprint != formatFingerprint(fingerprint[:]) {
		t.Fatalf("fingerprint = %q, want %q", info.PublicKeySHA256Fingerprint, formatFingerprint(fingerprint[:]))
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	for _, formatter := range []KeyFormatter{&KeyTextFormatter{}, &KeyJSONFormatter{Indent: true}} {
		var output bytes.Buffer
		if err := formatter.Format(info, &output); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(output.Bytes(), privateDER) || bytes.Contains(output.Bytes(), privatePEM) || strings.Contains(output.String(), "PRIVATE KEY") {
			t.Fatalf("formatter %T leaked private key material: %q", formatter, output.String())
		}
	}

	var decoded KeyInfo
	var output bytes.Buffer
	if err := (&KeyJSONFormatter{}).Format(info, &output); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != *info {
		t.Fatalf("decoded info = %+v, want %+v", decoded, *info)
	}
}

func TestKeyInfoCoversSupportedPublicAlgorithms(t *testing.T) {
	t.Parallel()

	for _, algorithm := range []KeyAlgorithm{KeyAlgorithmEd25519, KeyAlgorithmECDSAP256, KeyAlgorithmRSA2048} {
		t.Run(string(algorithm), func(t *testing.T) {
			t.Parallel()
			privateMaterial, err := GeneratePrivateKey(algorithm)
			if err != nil {
				t.Fatal(err)
			}
			privateKey, err := NewKey(privateMaterial)
			if err != nil {
				t.Fatal(err)
			}
			publicMaterial, err := privateKey.Public()
			if err != nil {
				t.Fatal(err)
			}
			publicKey, err := NewKey(publicMaterial)
			if err != nil {
				t.Fatal(err)
			}
			info, err := publicKey.Info()
			if err != nil {
				t.Fatal(err)
			}
			if info.KeyType != KeyTypePublic || info.Algorithm == "" || info.Bits == 0 {
				t.Fatalf("public key info = %+v", info)
			}
		})
	}
}

func TestKeyTextFormatterIncludesCurve(t *testing.T) {
	t.Parallel()

	info := &KeyInfo{
		KeyType:                    KeyTypePrivate,
		Algorithm:                  "ecdsa",
		Curve:                      "P-256",
		PublicKeySHA256Fingerprint: "AA:BB",
		Bits:                       256,
	}
	var output bytes.Buffer
	if err := (&KeyTextFormatter{}).Format(info, &output); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Key Type: private", "Algorithm: ecdsa", "Bits: 256", "Curve: P-256", "Public Key SHA256: AA:BB"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("text output = %q, want %q", output.String(), want)
		}
	}
}

func TestKeyRejectsUnknownGenerationAndMaterialTypes(t *testing.T) {
	t.Parallel()

	if _, err := GeneratePrivateKey(KeyAlgorithm("missing")); !errors.Is(err, ErrUnsupportedKeyAlgorithm) {
		t.Fatalf("generation error = %v, want unsupported algorithm", err)
	}
	if _, err := NewKey(struct{}{}); !errors.Is(err, ErrUnsupportedKeyType) {
		t.Fatalf("material error = %v, want unsupported key type", err)
	}
	if _, err := NewKey(ed25519.PublicKey{}); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("public-key error = %v, want malformed key", err)
	}
	if _, err := NewKey(ed25519.PrivateKey{}); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("private-key error = %v, want malformed key", err)
	}
}

func TestKeyRejectsUnsupportedECDSACurve(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewKey(privateKey); !errors.Is(err, ErrUnsupportedKeyType) || errors.Is(err, ErrMalformedKey) {
		t.Fatalf("P-224 error = %v, want only ErrUnsupportedKeyType", err)
	}
}

func TestParseKeyRejectsMalformedAndUnsupportedInputs(t *testing.T) {
	t.Parallel()

	certificate := generateTestCert(t)
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	validPrivate, err := GeneratePrivateKey(KeyAlgorithmEd25519)
	if err != nil {
		t.Fatal(err)
	}
	validKey, err := NewKey(validPrivate)
	if err != nil {
		t.Fatal(err)
	}
	validPEM := mustMarshalKey(t, validKey, KeyFormatPKCS8PEM)

	tests := []struct {
		want error
		name string
		data []byte
	}{
		{name: "empty", data: nil, want: ErrEmptyKeyInput},
		{name: "whitespace", data: []byte(" \n\t"), want: ErrEmptyKeyInput},
		{name: "garbage", data: []byte("not a key"), want: ErrMalformedKey},
		{name: "truncated PEM", data: []byte("-----BEGIN PRIVATE KEY-----\nAAAA"), want: ErrMalformedKey},
		{name: "certificate", data: certificatePEM, want: ErrUnexpectedKeyPEMType},
		{name: "encrypted", data: pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("ciphertext")}), want: ErrEncryptedPrivateKey},
		{
			name: "legacy encrypted",
			data: pem.EncodeToMemory(&pem.Block{
				Type:    "RSA PRIVATE KEY",
				Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"},
				Bytes:   []byte("ciphertext"),
			}),
			want: ErrEncryptedPrivateKey,
		},
		{name: "second block", data: append(append([]byte(nil), validPEM...), validPEM...), want: ErrTrailingKeyData},
		{name: "trailing junk", data: append(append([]byte(nil), validPEM...), []byte("junk")...), want: ErrTrailingKeyData},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseKey(test.data)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestKeyRejectsUnsupportedConversions(t *testing.T) {
	t.Parallel()

	privateKey, err := GeneratePrivateKey(KeyAlgorithmEd25519)
	if err != nil {
		t.Fatal(err)
	}
	private, err := NewKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	public := mustParseKey(t, mustMarshalKey(t, private, KeyFormatPKIXPEM))

	tests := []struct {
		key    *Key
		format KeyFormat
	}{
		{key: private, format: KeyFormatPKCS1PEM},
		{key: private, format: KeyFormatSEC1PEM},
		{key: public, format: KeyFormatPKCS8PEM},
		{key: private, format: KeyFormat("missing")},
	}
	for _, test := range tests {
		if _, err := test.key.Marshal(test.format); !errors.Is(err, ErrInvalidKeyConversion) {
			t.Fatalf("Marshal(%q) error = %v, want invalid conversion", test.format, err)
		}
	}
}

func TestParseKeyRejectsUnsupportedX25519Key(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := ParseKey(data); !errors.Is(err, ErrUnsupportedKeyType) {
		t.Fatalf("error = %v, want unsupported key type", err)
	}
}

func TestKeyFormattersPropagateWriterErrors(t *testing.T) {
	t.Parallel()

	info := &KeyInfo{KeyType: KeyTypePublic, Algorithm: "rsa", Bits: 2048, PublicKeySHA256Fingerprint: "AA:BB"}
	want := errKeyTestWriteFailed
	for _, formatter := range []KeyFormatter{&KeyTextFormatter{}, &KeyJSONFormatter{}} {
		if err := formatter.Format(info, keyFailingWriter{err: want}); !errors.Is(err, want) {
			t.Fatalf("formatter %T error = %v, want writer error", formatter, err)
		}
	}
}

//nolint:staticcheck // Raw fields are required to construct malformed keys that safe parsers reject.
func TestNewKeyRejectsMalformedECDSAKeys(t *testing.T) {
	t.Parallel()

	curve := elliptic.P256()
	x, y := curve.Params().Gx, curve.Params().Gy
	public := ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	tests := []struct {
		key  any
		name string
	}{
		{name: "nil public", key: (*ecdsa.PublicKey)(nil)},
		{name: "nil private", key: (*ecdsa.PrivateKey)(nil)},
		{name: "missing curve", key: &ecdsa.PublicKey{X: x, Y: y}},
		{name: "missing x", key: &ecdsa.PublicKey{Curve: curve, Y: y}},
		{name: "missing y", key: &ecdsa.PublicKey{Curve: curve, X: x}},
		{name: "off curve", key: &ecdsa.PublicKey{Curve: curve, X: big.NewInt(1), Y: big.NewInt(1)}},
		{name: "missing scalar", key: &ecdsa.PrivateKey{PublicKey: public}},
		{name: "missing private point", key: &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve}, D: big.NewInt(1)}},
		{name: "zero scalar", key: &ecdsa.PrivateKey{PublicKey: public, D: new(big.Int)}},
		{name: "negative scalar", key: &ecdsa.PrivateKey{PublicKey: public, D: big.NewInt(-1)}},
		{name: "scalar at order", key: &ecdsa.PrivateKey{PublicKey: public, D: curve.Params().N}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewKey(test.key); !errors.Is(err, ErrMalformedKey) {
				t.Fatalf("error = %v, want malformed key", err)
			}
		})
	}
}

func TestNewKeyValidatesRSA(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKey.Primes[0].SetInt64(3)
	if _, err := NewKey(privateKey); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("error = %v, want malformed key", err)
	}
}

func TestNewKeyRejectsInvalidRSAPublicParameters(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	evenModulus := new(big.Int).Sub(privateKey.N, big.NewInt(1))
	type testCase struct {
		key  *rsa.PublicKey
		name string
	}
	tests := []testCase{
		{name: "nil key", key: nil},
		{name: "missing modulus", key: &rsa.PublicKey{E: 65537}},
		{name: "zero modulus", key: &rsa.PublicKey{N: new(big.Int), E: 65537}},
		{name: "unit modulus", key: &rsa.PublicKey{N: big.NewInt(1), E: 65537}},
		{name: "even modulus", key: &rsa.PublicKey{N: evenModulus, E: 65537}},
		{name: "small exponent", key: &rsa.PublicKey{N: privateKey.N, E: 1}},
		{name: "even exponent", key: &rsa.PublicKey{N: privateKey.N, E: 2}},
	}
	if strconv.IntSize > 32 {
		largeExponent := int64(1 << 31)
		tests = append(tests, testCase{name: "large exponent", key: &rsa.PublicKey{N: privateKey.N, E: int(largeExponent)}})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewKey(test.key); !errors.Is(err, ErrMalformedKey) {
				t.Fatalf("error = %v, want malformed key", err)
			}
		})
	}
}

func TestParseKeyRejectsEvenRSAPublicExponent(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: privateKey.N, E: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		t.Fatalf("parse PKIX fixture: %v", err)
	}
	if _, err := ParseKey(der); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("error = %v, want malformed key", err)
	}
}

func mustParseKey(t *testing.T, data []byte) *Key {
	t.Helper()
	key, err := ParseKey(data)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustMarshalKey(t *testing.T, key *Key, format KeyFormat) []byte {
	t.Helper()
	data, err := key.Marshal(format)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustPublicDER(t *testing.T, key *Key) []byte {
	t.Helper()
	data, err := key.Marshal(KeyFormatPKIXDER)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustGenerateOpenSSHTestKey(t *testing.T, algorithm KeyAlgorithm) crypto.PrivateKey {
	t.Helper()
	key, err := GeneratePrivateKey(algorithm)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustGenerateECDSAKey(t *testing.T, curve elliptic.Curve) crypto.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type keyFailingWriter struct {
	err error
}

func (writer keyFailingWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

var _ io.Writer = keyFailingWriter{}
