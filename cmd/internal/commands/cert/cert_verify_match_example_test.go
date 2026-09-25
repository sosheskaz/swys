package cert_test

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
)

func TestExampleCertVerifyCustomRoot(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	dir := t.TempDir()
	chainPath := writeCertTestFile(t, dir, "chain.pem", fixture.leafPEM, fixture.intermediatePEM)
	rootPath := writeCertTestFile(t, dir, "root.pem", fixture.rootPEM)

	stdout, stderr, err := executeRootStreams(t,
		"cert", "verify",
		"--input", chainPath,
		"--ca", rootPath,
		"--hostname", certTestDNSName,
		"--at", certTestCurrentTime.Format(certTestRFC3339),
		"--format", "json",
	)
	require.NoError(t, err, "npc cert verify: %v (stderr %q)", err, stderr)
	assertCertBooleanReport(t, stdout, "verified", true)
	assertCertReportPublicDetails(t, stdout)
}

func TestExampleCertMatchCertificateAndPrivateKey(t *testing.T) {
	t.Parallel()
	fixture := newCertVerifyMatchFixture(t, certFixtureOptions{})
	dir := t.TempDir()
	certPath := writeCertTestFile(t, dir, "leaf.pem", fixture.leafPEM)
	keyPath := writeCertTestFile(t, dir, "leaf-key.pem", fixture.leafKeyPKCS8PEM)

	stdout, stderr, err := executeRootStreams(t,
		"cert", "match", "--cert", certPath, "--key", keyPath, "--format", "json",
	)
	require.NoError(t, err, "npc cert match: %v (stderr %q)", err, stderr)
	assertCertBooleanReport(t, stdout, "match", true)
	assertCertReportPublicDetails(t, stdout)
}

func TestCertVerifyAndMatchCommandSurface(t *testing.T) {
	t.Parallel()
	certCommand := certCommand(t)
	wantFlags := map[string][]string{
		"verify": {"ca", "system-ca", "intermediates", "purpose", "hostname", "at", "format"},
		"match":  {"cert", "key", "csr", "format"},
	}
	for verb, flags := range wantFlags {
		command, _, err := certCommand.Find([]string{verb})
		if err != nil || command == certCommand || command.Name() != verb {
			t.Errorf("cert %s command missing", verb)
			continue
		}
		if !commandio.HasShape(command, "structured-output") {
			t.Errorf("cert %s is not a structured-output command", verb)
		}
		for _, flag := range flags {
			if command.Flags().Lookup(flag) == nil && command.InheritedFlags().Lookup(flag) == nil {
				t.Errorf("cert %s missing --%s", verb, flag)
			}
		}
	}
}

func assertCertBooleanReport(t *testing.T, output, field string, want bool) {
	t.Helper()
	var report map[string]any
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("decode report %q: %v", output, err)
	}
	got, ok := report[field].(bool)
	if !ok || got != want {
		t.Fatalf("%s = %#v, want %t", field, report[field], want)
	}
}

func assertCertReportPublicDetails(t *testing.T, output string) {
	t.Helper()
	var report map[string]any
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("decode report %q: %v", output, err)
	}
	if details, ok := report["details"]; !ok || details == nil || details == "" {
		t.Fatalf("details = %#v, want a completed-report explanation", details)
	}
	if !jsonContainsNonEmptyFingerprint(report) {
		t.Fatalf("report = %s, want at least one public fingerprint", output)
	}
	assertNoPrivateKeyMaterial(t, output)
}

func jsonContainsNonEmptyFingerprint(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if strings.Contains(strings.ToLower(key), "fingerprint") {
				switch fingerprint := child.(type) {
				case string:
					if fingerprint != "" {
						return true
					}
				case []any:
					if len(fingerprint) > 0 {
						return true
					}
				}
			}
			if jsonContainsNonEmptyFingerprint(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if jsonContainsNonEmptyFingerprint(child) {
				return true
			}
		}
	}
	return false
}

func assertNoPrivateKeyMaterial(t *testing.T, output string, privateArtifacts ...[]byte) {
	t.Helper()
	if block, _ := pem.Decode([]byte(output)); block != nil && strings.Contains(block.Type, "PRIVATE KEY") {
		t.Fatalf("report contains serialized private-key PEM block %q", block.Type)
	}
	for _, artifact := range privateArtifacts {
		block, _ := pem.Decode(artifact)
		if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") || len(block.Bytes) == 0 {
			continue
		}
		encoded := base64.StdEncoding.EncodeToString(block.Bytes)
		fragments := []string{string(artifact)}
		if len(block.Bytes) >= 32 {
			fragments = append(fragments, string(block.Bytes))
		}
		if len(encoded) >= 32 {
			fragments = append(fragments, encoded)
		}
		if len(encoded) > 32 {
			fragments = append(fragments, encoded[:32])
		}
		for _, fragment := range fragments {
			if fragment != "" && strings.Contains(output, fragment) {
				t.Fatal("report contains bytes from the supplied private key")
			}
		}
	}
}

func writeCertTestFile(t *testing.T, dir, name string, parts ...[]byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(certTestByteStrings(parts), "")), 0o600))
	return path
}

func certTestByteStrings(parts [][]byte) []string {
	stringsOut := make([]string, len(parts))
	for i, part := range parts {
		stringsOut[i] = string(part)
	}
	return stringsOut
}
