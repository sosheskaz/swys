package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCertificateInspectEscapesCommonName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	certPath := filepath.Join(dir, "cert.pem")
	if _, err := executeRoot(t, "key", "generate", "ed25519", "--output", keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := executeRoot(t, "cert", "create", "--key", keyPath, "--subject", "CN=demo\x1b[2J", "--output", certPath); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"text", "long"} {
		output, err := executeRoot(t, "cert", "inspect", "--input", certPath, "--format", format)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output, "\x1b") || !strings.Contains(output, `demo\x1b[2J`) {
			t.Fatalf("unsafe certificate output: %q", output)
		}
	}
}
