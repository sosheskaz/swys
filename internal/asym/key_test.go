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

	"github.com/stretchr/testify/require"
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
			require.NoError(t, err)
			key, err := NewKey(privateKey)
			require.NoError(t, err)
			wantPublic := mustPublicDER(t, key)
			wantPKCS8 := mustMarshalKey(t, key, KeyFormatPKCS8DER)

			for _, format := range test.formats {
				t.Run(string(format), func(t *testing.T) {
					encoded, err := key.Marshal(format)
					require.NoError(t, err)
					parsed, err := ParseKey(encoded)
					require.NoError(t, err)
					require.True(t, parsed.IsPrivate(), "parsed key is public, want private")
					require.Equal(t, wantPublic, mustPublicDER(t, parsed), "round-tripped public key")
					require.Equal(t, wantPKCS8, mustMarshalKey(t, parsed, KeyFormatPKCS8DER), "round-tripped canonical PKCS#8 DER")
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
			require.NoError(t, err)
			parsed, err := ParseKey(pem.EncodeToMemory(block))
			require.NoError(t, err)
			require.True(t, parsed.IsPrivate(), "parsed OpenSSH key is public, want private")
			want, err := NewKey(privateKey)
			require.NoError(t, err)
			require.Equal(t, mustPublicDER(t, want), mustPublicDER(t, parsed), "parsed OpenSSH public key")
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
		require.NoError(t, err)
		line := bytes.TrimSpace(ssh.MarshalAuthorizedKey(publicKey))
		fixture := append([]byte("\n# generated fixture\nrestrict,command=\"swys test\" "), line...)
		fixture = append(fixture, []byte(" user@example\n\n")...)
		parsed, err := ParseKey(fixture)
		if err != nil {
			t.Fatalf("ParseKey(%s): %v", publicKey.Type(), err)
		}
		require.False(t, parsed.IsPrivate(), "ParseKey(%s) is private, want public", publicKey.Type())
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
	require.NoError(t, err)
	publicLine := ssh.MarshalAuthorizedKey(publicKey)
	privateBlock, err := ssh.MarshalPrivateKey(privateKey, "fixture")
	require.NoError(t, err)
	privatePEM := pem.EncodeToMemory(privateBlock)
	privateEnvelopeTrailing := pem.EncodeToMemory(&pem.Block{
		Type:  privateBlock.Type,
		Bytes: append(append([]byte(nil), privateBlock.Bytes...), []byte("trailing")...),
	})
	encryptedBlock, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, "fixture", []byte("secret"))
	require.NoError(t, err)

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
			require.ErrorIs(t, err, test.want)
			if errors.Is(test.want, ErrTrailingKeyData) && errors.Is(err, ErrMalformedKey) {
				t.Fatalf("error = %v, trailing data must not be classified as malformed", err)
			}
		})
	}
}

func TestParseKeyRejectsUnsupportedOpenSSHTypes(t *testing.T) {
	t.Parallel()

	var parameters dsa.Parameters
	require.NoError(t, dsa.GenerateParameters(&parameters, rand.Reader, dsa.L1024N160))
	privateKey := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: parameters}}
	require.NoError(t, dsa.GenerateKey(privateKey, rand.Reader))
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	if _, err := ParseKey(ssh.MarshalAuthorizedKey(publicKey)); !errors.Is(err, ErrUnsupportedKeyType) || errors.Is(err, ErrMalformedKey) {
		t.Fatalf("DSA public error = %v, want only unsupported key type", err)
	}
	unsupportedDERKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	publicDER, err := x509.MarshalPKIXPublicKey(unsupportedDERKey.PublicKey())
	require.NoError(t, err)
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
	require.NoError(t, err)
	private, err := NewKey(privateKey)
	require.NoError(t, err)
	wantPublic := mustPublicDER(t, private)

	for _, source := range []*Key{private, mustParseKey(t, mustMarshalKey(t, private, KeyFormatPKIXPEM))} {
		for _, format := range []KeyFormat{KeyFormatPKIXPEM, KeyFormatPKIXDER} {
			encoded, err := source.Marshal(format)
			require.NoError(t, err)
			parsed, err := ParseKey(encoded)
			require.NoError(t, err)
			require.False(t, parsed.IsPrivate(), "public serialization parsed as private")
			require.Equal(t, wantPublic, mustPublicDER(t, parsed), "canonical public key")
		}
	}
}

func TestParseKeyPreservesWhitespaceValuedDERTrailer(t *testing.T) {
	t.Parallel()

	for _, trailer := range []byte{'\t', '\n', '\v', '\f', '\r', ' '} {
		publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
		publicKey[len(publicKey)-1] = trailer
		der, err := x509.MarshalPKIXPublicKey(publicKey)
		require.NoError(t, err)
		require.Equal(t, trailer, der[len(der)-1], "DER trailer")
		_, err = ParseKey(der)
		require.NoError(t, err, "ParseKey with DER trailer %#x", trailer)
	}
}

func TestKeyOpenSSHRoundTrip(t *testing.T) {
	t.Parallel()

	privateKey, err := GeneratePrivateKey(KeyAlgorithmECDSAP384)
	require.NoError(t, err)
	key, err := NewKey(privateKey)
	require.NoError(t, err)
	encoded, err := key.Marshal(KeyFormatOpenSSH)
	require.NoError(t, err)
	sshPublic, _, _, rest, err := ssh.ParseAuthorizedKey(encoded)
	require.NoError(t, err)
	require.Empty(t, bytes.TrimSpace(rest), "OpenSSH trailing data")
	cryptoPublic, ok := sshPublic.(ssh.CryptoPublicKey)
	if !ok {
		t.Fatalf("OpenSSH key type = %T, want crypto public key", sshPublic)
	}
	parsed, err := NewKey(cryptoPublic.CryptoPublicKey())
	require.NoError(t, err)
	require.Equal(t, mustPublicDER(t, key), mustPublicDER(t, parsed), "OpenSSH public key")
}

func TestKeyInfoAndFormattersContainMetadataOnly(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := NewKey(privateKey)
	require.NoError(t, err)
	info, err := key.Info()
	require.NoError(t, err)
	if info.KeyType != KeyTypePrivate || info.Algorithm != "ed25519" || info.Bits != 256 || info.Curve != "" {
		t.Fatalf("key info = %+v", info)
	}
	publicDER := mustPublicDER(t, key)
	fingerprint := sha256.Sum256(publicDER)
	if info.PublicKeySHA256Fingerprint != formatFingerprint(fingerprint[:]) {
		t.Fatalf("fingerprint = %q, want %q", info.PublicKeySHA256Fingerprint, formatFingerprint(fingerprint[:]))
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	for _, formatter := range []KeyFormatter{&KeyTextFormatter{}, &KeyJSONFormatter{Indent: true}} {
		var output bytes.Buffer
		require.NoError(t, formatter.Format(info, &output))
		if bytes.Contains(output.Bytes(), privateDER) || bytes.Contains(output.Bytes(), privatePEM) || strings.Contains(output.String(), "PRIVATE KEY") {
			t.Fatalf("formatter %T leaked private key material: %q", formatter, output.String())
		}
	}

	var decoded KeyInfo
	var output bytes.Buffer
	require.NoError(t, (&KeyJSONFormatter{}).Format(info, &output))
	require.NoError(t, json.Unmarshal(output.Bytes(), &decoded))
	require.Equal(t, *info, decoded, "decoded info")
}

func TestKeyInfoCoversSupportedPublicAlgorithms(t *testing.T) {
	t.Parallel()

	for _, algorithm := range []KeyAlgorithm{KeyAlgorithmEd25519, KeyAlgorithmECDSAP256, KeyAlgorithmRSA2048} {
		t.Run(string(algorithm), func(t *testing.T) {
			t.Parallel()
			privateMaterial, err := GeneratePrivateKey(algorithm)
			require.NoError(t, err)
			privateKey, err := NewKey(privateMaterial)
			require.NoError(t, err)
			publicMaterial, err := privateKey.Public()
			require.NoError(t, err)
			publicKey, err := NewKey(publicMaterial)
			require.NoError(t, err)
			info, err := publicKey.Info()
			require.NoError(t, err)
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
	require.NoError(t, (&KeyTextFormatter{}).Format(info, &output))
	for _, want := range []string{"Key Type: private", "Algorithm: ecdsa", "Bits: 256", "Curve: P-256", "Public Key SHA256: AA:BB"} {
		require.Contains(t, output.String(), want, "text output")
	}
}

func TestKeyRejectsUnknownGenerationAndMaterialTypes(t *testing.T) {
	t.Parallel()

	_, err := GeneratePrivateKey(KeyAlgorithm("missing"))
	require.ErrorIs(t, err, ErrUnsupportedKeyAlgorithm)
	_, err = NewKey(struct{}{})
	require.ErrorIs(t, err, ErrUnsupportedKeyType)
	_, err = NewKey(ed25519.PublicKey{})
	require.ErrorIs(t, err, ErrMalformedKey)
	_, err = NewKey(ed25519.PrivateKey{})
	require.ErrorIs(t, err, ErrMalformedKey)
}

func TestKeyRejectsUnsupportedECDSACurve(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	if _, err := NewKey(privateKey); !errors.Is(err, ErrUnsupportedKeyType) || errors.Is(err, ErrMalformedKey) {
		t.Fatalf("P-224 error = %v, want only ErrUnsupportedKeyType", err)
	}
}

func TestParseKeyRejectsMalformedAndUnsupportedInputs(t *testing.T) {
	t.Parallel()

	certificate := generateTestCert(t)
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	validPrivate, err := GeneratePrivateKey(KeyAlgorithmEd25519)
	require.NoError(t, err)
	validKey, err := NewKey(validPrivate)
	require.NoError(t, err)
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
			require.ErrorIs(t, err, test.want)
		})
	}
}

func TestKeyRejectsUnsupportedConversions(t *testing.T) {
	t.Parallel()

	privateKey, err := GeneratePrivateKey(KeyAlgorithmEd25519)
	require.NoError(t, err)
	private, err := NewKey(privateKey)
	require.NoError(t, err)
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
		_, err := test.key.Marshal(test.format)
		require.ErrorIs(t, err, ErrInvalidKeyConversion)
	}
}

func TestParseKeyRejectsUnsupportedX25519Key(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	_, err = ParseKey(data)
	require.ErrorIs(t, err, ErrUnsupportedKeyType)
}

func TestKeyFormattersPropagateWriterErrors(t *testing.T) {
	t.Parallel()

	info := &KeyInfo{KeyType: KeyTypePublic, Algorithm: "rsa", Bits: 2048, PublicKeySHA256Fingerprint: "AA:BB"}
	want := errKeyTestWriteFailed
	for _, formatter := range []KeyFormatter{&KeyTextFormatter{}, &KeyJSONFormatter{}} {
		require.ErrorIs(t, formatter.Format(info, keyFailingWriter{err: want}), want)
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

			_, err := NewKey(test.key)
			require.ErrorIs(t, err, ErrMalformedKey)
		})
	}
}

func TestNewKeyValidatesRSA(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privateKey.Primes[0].SetInt64(3)
	_, err = NewKey(privateKey)
	require.ErrorIs(t, err, ErrMalformedKey)
}

func TestNewKeyRejectsInvalidRSAPublicParameters(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
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

			_, err := NewKey(test.key)
			require.ErrorIs(t, err, ErrMalformedKey)
		})
	}
}

func TestParseKeyRejectsEvenRSAPublicExponent(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: privateKey.N, E: 2})
	require.NoError(t, err)
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		t.Fatalf("parse PKIX fixture: %v", err)
	}
	_, err = ParseKey(der)
	require.ErrorIs(t, err, ErrMalformedKey)
}

func mustParseKey(t *testing.T, data []byte) *Key {
	t.Helper()
	key, err := ParseKey(data)
	require.NoError(t, err)
	return key
}

func mustMarshalKey(t *testing.T, key *Key, format KeyFormat) []byte {
	t.Helper()
	data, err := key.Marshal(format)
	require.NoError(t, err)
	return data
}

func mustPublicDER(t *testing.T, key *Key) []byte {
	t.Helper()
	data, err := key.Marshal(KeyFormatPKIXDER)
	require.NoError(t, err)
	return data
}

func mustGenerateOpenSSHTestKey(t *testing.T, algorithm KeyAlgorithm) crypto.PrivateKey {
	t.Helper()
	key, err := GeneratePrivateKey(algorithm)
	require.NoError(t, err)
	return key
}

func mustGenerateECDSAKey(t *testing.T, curve elliptic.Curve) crypto.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return key
}

type keyFailingWriter struct {
	err error
}

func (writer keyFailingWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

var _ io.Writer = keyFailingWriter{}
