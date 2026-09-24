package asym

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			require.NoError(t, (&TextFormatter{Long: long}).Format(info, &output))
			text := output.String()
			assert.False(t, strings.ContainsAny(text, "\x1b\r\t\u009b\u202e"), "unsafe output: %q", text)
			assert.NotContains(t, text, "\n\t")
			assert.Contains(t, text, "x "+escaped+" | "+escaped+" |")
			assert.Contains(t, text, "Error: failed: "+escaped)
			assert.Contains(t, text, escaped)
			if long {
				assert.Contains(t, text, escaped+" -> "+escaped)
			}
			var structured bytes.Buffer
			require.NoError(t, (&JSONFormatter{}).Format(info, &structured))
			var decoded certInfoJSON
			require.NoError(t, json.Unmarshal(structured.Bytes(), &decoded))
			require.NotEmpty(t, decoded.DNSNames)
			assert.Equal(t, hostile, decoded.DNSNames[0])
			assert.Equal(t, info.VerifyError, decoded.VerifyError)
		}
	}
}

func TestCertificateTextPreservesPrintableValues(t *testing.T) {
	t.Parallel()
	const value = `CN=José\, O="example"`
	var output bytes.Buffer
	require.NoError(t, writeField(&output, "Subject", value))
	assert.Contains(t, output.String(), value)
}
