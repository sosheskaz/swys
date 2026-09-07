package cmd

import (
	"bytes"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

func TestCertificatePEMEscapesVerificationDiagnostics(t *testing.T) {
	t.Parallel()
	info := &asym.CertInfo{RawDER: newTLSCertificateChain(t).Certificate[0], VerifyError: "bad\x1b[2J\r\nname"}
	var output, diagnostics bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&output)
	command.SetErr(&diagnostics)
	if err := formatCertificates(command, &asym.PEMFormatter{}, []*asym.CertInfo{info}); err != nil {
		t.Fatal(err)
	}
	if got, want := diagnostics.String(), "certificate verification: not verified: bad\\x1b[2J\\r\\nname\n"; got != want {
		t.Fatalf("diagnostics = %q, want %q", got, want)
	}
	block, rest := pem.Decode(output.Bytes())
	if block == nil || !bytes.Equal(block.Bytes, info.RawDER) || strings.TrimSpace(string(rest)) != "" {
		t.Fatal("PEM certificate changed")
	}
}

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
