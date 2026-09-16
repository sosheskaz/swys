package asym

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

const maxFuzzCertificateDERSize = 1 << 12

// fuzzCertificateVerifyTime pins chain verification to a fixed instant. Left to
// wall-clock time, NewCertInfoVerified would make this target nondeterministic,
// which Go's fuzzing engine assumes against when minimizing and reproducing.
var fuzzCertificateVerifyTime = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)

// FuzzCertificateJSON drives peer-supplied certificate DER through parsing and
// the JSON formatter and requires the envelope to survive a decode. Every
// certificate field a peer controls reaches the output verbatim, so the checks
// below invert the encoding rather than restate it: the serial parses back as
// hex to the same big.Int, the signature and SPKI base64-decode to the same
// bytes, and the fingerprints are recomputed with an independent colon-hex
// formatter.
func FuzzCertificateJSON(f *testing.F) {
	for _, der := range fuzzCertificateSeeds(f) {
		f.Add(der, false)
		f.Add(der, true)
	}
	f.Add([]byte{}, false)
	f.Add([]byte{0x30, 0x00}, false)

	f.Fuzz(func(t *testing.T, der []byte, indent bool) {
		if len(der) > maxFuzzCertificateDERSize {
			t.Skip()
		}
		cert, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			return
		}

		info, err := NewCertInfoVerified(cert, &x509.VerifyOptions{
			Roots:       x509.NewCertPool(),
			CurrentTime: fuzzCertificateVerifyTime,
		})
		if err != nil {
			t.Fatalf("inspect parsed certificate: %v", err)
		}
		var output bytes.Buffer
		formatErr := (&JSONFormatter{Indent: indent}).Format(info, &output)

		// The SPKI is the only part of the envelope whose rendering can fail, so
		// acceptance is differentiated against the standard library marshaller.
		wantPublicKey, publicKeyErr := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if (formatErr == nil) != (publicKeyErr == nil) {
			t.Fatalf("format error = %v, standard library public key error = %v", formatErr, publicKeyErr)
		}
		if formatErr != nil {
			return
		}
		if !utf8.Valid(output.Bytes()) {
			t.Fatalf("certificate JSON is not valid UTF-8: %x", output.Bytes())
		}
		if !indent && strings.Count(output.String(), "\n") != 1 {
			t.Fatalf("unindented certificate JSON spans multiple lines: %q", output.String())
		}
		checkFuzzCertificateEnvelope(t, output.Bytes(), cert, wantPublicKey)
	})
}

func checkFuzzCertificateEnvelope(t *testing.T, encoded []byte, cert *x509.Certificate, publicKey []byte) {
	t.Helper()
	var decoded struct {
		NotBefore         time.Time `json:"not_before"`
		NotAfter          time.Time `json:"not_after"`
		Subject           string    `json:"subject"`
		Issuer            string    `json:"issuer"`
		SerialNumber      string    `json:"serial_number"`
		SignatureBase64   string    `json:"signature_base64"`
		PublicKeyBase64   string    `json:"public_key_base64"`
		PublicKeySHA256   string    `json:"public_key_sha256_fingerprint"`
		SHA256Fingerprint string    `json:"sha256_fingerprint"`
		DNSNames          []string  `json:"dns_names"`
		IPAddresses       []string  `json:"ip_addresses"`
		IsCA              bool      `json:"is_ca"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("certificate JSON does not decode: %v; output %q", err, encoded)
	}

	if decoded.Subject != cert.Subject.String() {
		t.Fatalf("subject survived as %q, want %q", decoded.Subject, cert.Subject.String())
	}
	if decoded.Issuer != cert.Issuer.String() {
		t.Fatalf("issuer survived as %q, want %q", decoded.Issuer, cert.Issuer.String())
	}
	serial, ok := new(big.Int).SetString(decoded.SerialNumber, 16)
	if !ok || serial.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("serial %q does not parse back to %v", decoded.SerialNumber, cert.SerialNumber)
	}
	if !slices.Equal(decoded.DNSNames, cert.DNSNames) {
		t.Fatalf("DNS names survived as %q, want %q", decoded.DNSNames, cert.DNSNames)
	}
	if decoded.IsCA != cert.IsCA {
		t.Fatalf("CA flag survived as %t, want %t", decoded.IsCA, cert.IsCA)
	}
	if !decoded.NotBefore.Equal(cert.NotBefore) || !decoded.NotAfter.Equal(cert.NotAfter) {
		t.Fatalf("validity survived as %s..%s, want %s..%s",
			decoded.NotBefore, decoded.NotAfter, cert.NotBefore, cert.NotAfter)
	}
	if len(decoded.IPAddresses) != len(cert.IPAddresses) {
		t.Fatalf("IP addresses survived as %q, want %d entries", decoded.IPAddresses, len(cert.IPAddresses))
	}
	for index, address := range decoded.IPAddresses {
		if parsed := net.ParseIP(address); parsed == nil || !parsed.Equal(cert.IPAddresses[index]) {
			t.Fatalf("IP address %d survived as %q, want %s", index, address, cert.IPAddresses[index])
		}
	}

	checkFuzzCertificateBase64(t, "signature", decoded.SignatureBase64, cert.Signature)
	checkFuzzCertificateBase64(t, "public key", decoded.PublicKeyBase64, publicKey)
	certFingerprint := sha256.Sum256(cert.Raw)
	if want := fuzzColonHex(certFingerprint[:]); decoded.SHA256Fingerprint != want {
		t.Fatalf("certificate fingerprint = %q, want %q", decoded.SHA256Fingerprint, want)
	}
	publicKeyFingerprint := sha256.Sum256(publicKey)
	if want := fuzzColonHex(publicKeyFingerprint[:]); decoded.PublicKeySHA256 != want {
		t.Fatalf("public key fingerprint = %q, want %q", decoded.PublicKeySHA256, want)
	}
}

func checkFuzzCertificateBase64(t *testing.T, field, encoded string, want []byte) {
	t.Helper()
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("%s base64 does not decode: %v; value %q", field, err, encoded)
	}
	if !bytes.Equal(decoded, want) {
		t.Fatalf("%s survived as %x, want %x", field, decoded, want)
	}
}

// fuzzColonHex formats bytes as uppercase colon-separated hex without reusing
// formatFingerprint, so a regression there cannot move this expectation with it.
func fuzzColonHex(data []byte) string {
	parts := make([]string, len(data))
	for index, value := range data {
		parts[index] = strings.ToUpper(hex.EncodeToString([]byte{value}))
	}
	return strings.Join(parts, ":")
}

// fuzzCertificateSeeds builds certificates whose distinguished names, SANs, and
// serial exercise the escaping and encoding the JSON envelope has to survive.
func fuzzCertificateSeeds(f *testing.F) [][]byte {
	f.Helper()
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}

	templates := []*x509.Certificate{
		{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "plain.example.test"},
			NotBefore:    fuzzCertificateVerifyTime.Add(-time.Hour),
			NotAfter:     fuzzCertificateVerifyTime.Add(time.Hour),
			DNSNames:     []string{"plain.example.test"},
		},
		{
			// RFC 2253 metacharacters plus non-ASCII: pkix.Name.String escapes
			// these, and the JSON envelope has to carry the result unchanged.
			SerialNumber: new(big.Int).Lsh(big.NewInt(1), 127),
			Subject: pkix.Name{
				CommonName:   `comma, plus+ equals= quote" slash\ hash#`,
				Organization: []string{" leading and trailing ", "José 世界"},
			},
			Issuer:                pkix.Name{CommonName: "issuer, with comma"},
			NotBefore:             fuzzCertificateVerifyTime.Add(-24 * time.Hour),
			NotAfter:              fuzzCertificateVerifyTime.Add(24 * time.Hour),
			DNSNames:              []string{"a.example.test", "*.wildcard.example.test", ""},
			IPAddresses:           []net.IP{net.IPv4(198, 51, 100, 7), net.ParseIP("2001:db8::1")},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageAny},
			IsCA:                  true,
			BasicConstraintsValid: true,
		},
		{
			SerialNumber: big.NewInt(0),
			Subject:      pkix.Name{},
			NotBefore:    fuzzCertificateVerifyTime.Add(-2 * time.Hour),
			NotAfter:     fuzzCertificateVerifyTime.Add(-time.Hour),
		},
	}

	seeds := make([][]byte, 0, len(templates)+2)
	for _, template := range templates {
		der, createErr := x509.CreateCertificate(rand.Reader, template, template, ed25519Key.Public(), ed25519Key)
		if createErr != nil {
			f.Fatal(createErr)
		}
		seeds = append(seeds, der)
	}
	ecdsaDER, err := x509.CreateCertificate(rand.Reader, templates[0], templates[0], ecdsaKey.Public(), ecdsaKey)
	if err != nil {
		f.Fatal(err)
	}
	seeds = append(seeds, ecdsaDER)

	// A leaf signed by a different CA is the only seed whose subject and issuer
	// differ, so it is what separates the two names in the envelope.
	issuer, err := x509.ParseCertificate(seeds[1])
	if err != nil {
		f.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, templates[0], issuer, ecdsaKey.Public(), ed25519Key)
	if err != nil {
		f.Fatal(err)
	}
	return append(seeds, leafDER)
}
