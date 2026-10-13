package cert_test

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/cli/artifact"
	byteencoding "github.com/sosheskaz/swys/cmd/internal/cli/encoding"
)

func TestCertificateCustomCAData(t *testing.T) {
	t.Parallel()
	fixture := newCertificateCAFixture(t)
	wrong := newCertVerifyMatchFixture(t, certFixtureOptions{})
	chain := append(bytes.Clone(fixture.leafPEM), fixture.intermediatePEM...)
	for _, test := range []struct {
		name string
		data string
		args []string
	}{
		{name: "raw PEM", data: string(fixture.rootPEM)},
		{name: "base64 DER", data: base64.StdEncoding.EncodeToString(fixture.root.Raw), args: []string{"--ca-encoding", "base64"}},
		{name: "multiple trust anchors", data: string(wrong.rootPEM) + string(fixture.rootPEM)},
		{name: "combine system roots", data: string(fixture.rootPEM), args: []string{"--system-ca"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := append([]string{"cert", "verify", "--ca-data", test.data, "--format", "json"}, test.args...)
			stdout, stderr, err := executeCertTestWithInput(t, chain, args...)
			require.NoError(t, err, "stderr %q", stderr)
			assertCertBooleanReport(t, stdout, "verified", true)
		})
	}
	t.Run("unrelated CA", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := executeCertTestWithInput(t, append(bytes.Clone(chain), fixture.rootPEM...),
			"cert", "verify", "--ca-data", string(wrong.rootPEM), "--format", "json")
		require.ErrorIs(t, err, errCertificateReportNegative)
		assertCertBooleanReport(t, stdout, "verified", false)
	})
}

func TestCertificateCASelectionValidatesBeforeIO(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "conflicting sources", args: []string{"--ca", "missing.pem", "--ca-data", "literal"}},
		{name: "empty literal", args: []string{"--ca-data="}},
		{name: "codec without source", args: []string{"--ca-encoding", "raw"}},
		{name: "unknown codec", args: []string{"--ca-data", "literal", "--ca-encoding", "missing"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := assertCertArtifactPreIOFailure(t, append([]string{"cert", "verify"}, test.args...))
			if test.name == "unknown codec" {
				require.ErrorIs(t, err, byteencoding.ErrUnknownInputEncoding)
			}
		})
	}
}

func TestCertificateCADataFailuresPreserveOutput(t *testing.T) {
	t.Parallel()
	fixture := newCertificateCAFixture(t)
	chain := append(bytes.Clone(fixture.leafPEM), fixture.intermediatePEM...)
	for _, test := range []struct {
		name string
		data string
		args []string
	}{
		{name: "malformed encoding", data: "%%%%", args: []string{"--ca-encoding", "base64"}},
		{name: "malformed certificate", data: "not a certificate"},
		{name: "trailing data", data: string(fixture.rootPEM) + "trailing"},
		{name: "wrong PEM type", data: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: fixture.root.Raw}))},
		{name: "literal dash", data: "-"},
		{name: "literal filename", data: "missing.pem"},
		{
			name: "decoded size limit", data: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, int(artifact.MaxCertificateBytes)+1)),
			args: []string{"--ca-encoding", "base64"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output := writeCertTestFile(t, t.TempDir(), "output", []byte("preserve"))
			args := append([]string{"cert", "verify", "--ca-data", test.data, "--output", output}, test.args...)
			stdout, _, err := executeCertTestWithInput(t, chain, args...)
			require.Error(t, err)
			require.NotErrorIs(t, err, os.ErrNotExist, "literal input must never be opened as a file")
			require.Empty(t, stdout)
			if test.name == "malformed encoding" {
				var decodeErr base64.CorruptInputError
				require.ErrorAs(t, err, &decodeErr)
			}
			if test.name == "decoded size limit" {
				require.ErrorIs(t, err, artifact.ErrTooLarge)
			}
			data, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			require.Equal(t, "preserve", string(data))
		})
	}
}

func TestCertificateVerifyCAFileAndStdin(t *testing.T) {
	t.Parallel()
	fixture := newCertificateCAFixture(t)
	dir := t.TempDir()
	chain := append(bytes.Clone(fixture.leafPEM), fixture.intermediatePEM...)
	chainPath := writeCertTestFile(t, dir, "chain.b64", []byte(base64.StdEncoding.EncodeToString(chain)))
	caPath := writeCertTestFile(t, dir, "root.pem", fixture.rootPEM)
	for _, test := range []struct {
		name  string
		input []byte
		args  []string
	}{
		{name: "CA file with chain stdin", input: chain, args: []string{"--ca", caPath}},
		{name: "raw CA stdin with encoded chain file", input: fixture.rootPEM, args: []string{"--input", chainPath, "--input-encoding", "base64", "--ca", "-"}},
		{
			name: "encoded CA stdin with encoded chain file", input: []byte(base64.StdEncoding.EncodeToString(fixture.rootPEM)),
			args: []string{"--input", chainPath, "--input-encoding", "base64", "--ca", "-", "--ca-encoding", "base64"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stdout, stderr, err := executeCertTestWithInput(t, test.input, append([]string{"cert", "verify", "--format", "json"}, test.args...)...)
			require.NoError(t, err, "stderr %q", stderr)
			assertCertBooleanReport(t, stdout, "verified", true)
		})
	}
	t.Run("output collides with CA", func(t *testing.T) {
		t.Parallel()
		output := writeCertTestFile(t, t.TempDir(), "root.pem", fixture.rootPEM)
		alias := filepath.Join(t.TempDir(), "alias.pem")
		require.NoError(t, os.Link(output, alias))
		root := newRootCmd()
		input := &certVerifyReadCounter{}
		root.SetIn(input)
		stdout, _, err := executeRootCommandStreams(t, root, "cert", "verify", "--ca", alias, "--output", output)
		require.ErrorIs(t, err, errCertificatePathCollision)
		require.Zero(t, input.count.Load())
		require.Empty(t, stdout)
		contents, readErr := os.ReadFile(output)
		require.NoError(t, readErr)
		require.Equal(t, fixture.rootPEM, contents)
	})
}

func newCertificateCAFixture(t *testing.T) *certVerifyMatchFixture {
	t.Helper()
	// CA workflows verify at the real clock rather than passing --at.
	return newCertVerifyMatchFixture(t, certFixtureOptions{
		leafNotBefore: certTestCurrentTime.AddDate(-9, 0, 0),
		leafNotAfter:  certTestCurrentTime.AddDate(9, 0, 0),
	})
}
