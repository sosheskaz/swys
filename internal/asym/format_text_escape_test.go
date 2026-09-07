package asym

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
)

func TestCertificateTextEscapesControlCharacters(t *testing.T) {
	t.Parallel()
	const hostile = "demo\x1b[2J\r\n\t\u009b\u202e"
	const escaped = `demo\x1b[2J\r\n\t\u009b\u202e`
	cert := generateTestCert(t, func(cert *x509.Certificate) { cert.Subject.CommonName = hostile })
	for _, long := range []bool{false, true} {
		for _, names := range [][]string{{hostile}, {hostile, "two", "three", "four"}} {
			info := NewCertInfo(cert)
			info.DNSNames = names
			info.VerifyError = "failed: " + hostile
			info.Chains = [][]ChainCertInfo{{{CommonName: hostile}, {Subject: hostile}}}
			var output bytes.Buffer
			if err := (&TextFormatter{Long: long}).Format(info, &output); err != nil {
				t.Fatal(err)
			}
			text := output.String()
			if strings.ContainsAny(text, "\x1b\r\t\u009b\u202e") || strings.Contains(text, "\n\t") {
				t.Fatalf("unsafe output: %q", text)
			}
			if !strings.Contains(text, "x "+escaped+" | "+escaped+" |") || !strings.Contains(text, "Error: failed: "+escaped) {
				t.Fatalf("missing escaped summary: %q", text)
			}
			if !strings.Contains(text, escaped) || (long && !strings.Contains(text, escaped+" -> "+escaped)) {
				t.Fatalf("missing escaped fields: %q", text)
			}
			var structured bytes.Buffer
			if err := (&JSONFormatter{}).Format(info, &structured); err != nil {
				t.Fatal(err)
			}
			var decoded certInfoJSON
			if err := json.Unmarshal(structured.Bytes(), &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.DNSNames[0] != hostile || decoded.VerifyError != info.VerifyError {
				t.Fatalf("JSON values changed: %+v", decoded)
			}
		}
	}
}

func TestCertificateTextPreservesPrintableValues(t *testing.T) {
	t.Parallel()
	const value = `CN=José\, O="example"`
	var output bytes.Buffer
	if err := writeField(&output, "Subject", value); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), value) {
		t.Fatalf("printable value changed: %q", output.String())
	}
}
