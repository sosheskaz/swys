package cert_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExampleCertInspectUnrelatedCAs(t *testing.T) {
	t.Parallel()
	first := newCertVerifyMatchFixture(t, certFixtureOptions{})
	second := newCertVerifyMatchFixture(t, certFixtureOptions{})
	bundle := append(bytes.Clone(first.rootPEM), second.rootPEM...)

	stdout, stderr, err := executeCertTestWithInput(t, bundle, "cert", "inspect", "--format", "json")
	require.NoError(t, err)
	assert.Empty(t, stderr)
	var report struct {
		Certificates []struct {
			PEM    string `json:"pem"`
			Source string `json:"source"`
			IsCA   bool   `json:"is_ca"`
		} `json:"certificates"`
		Verification json.RawMessage `json:"verification"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &report))
	require.Len(t, report.Certificates, 2)
	for index, want := range [][]byte{first.rootPEM, second.rootPEM} {
		assert.Equal(t, string(want), report.Certificates[index].PEM)
		assert.Equal(t, "input", report.Certificates[index].Source)
		assert.True(t, report.Certificates[index].IsCA)
	}
	assert.Nil(t, report.Verification, "metadata inspection must omit verification entirely")
}
