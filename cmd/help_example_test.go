package cmd

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestExampleHelpSelectsCanonicalGuideThroughAlias(t *testing.T) {
	t.Parallel()

	root := newRootCmdWithGuideDependencies(defaultDNSDependencies(), guideDependencies{
		getenv: func(string) (string, bool) { return "", false },
		terminal: func(io.Writer) (bool, int) {
			return false, 0
		},
	})
	stdout, stderr, err := executeRootCommandStreams(t, root, "help", "x509", "connect", "--plain")
	if err != nil {
		t.Fatalf("npc help x509 connect --plain: %v", err)
	}
	if !strings.HasPrefix(stdout, "Inspect a TLS server's certificates\n") {
		t.Fatalf("stdout = %q, want the canonical cert connect guide", stdout)
	}
	if !strings.Contains(stdout, "npc cert connect --help") {
		t.Fatalf("stdout does not point to canonical reference help: %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want no diagnostics", stderr)
	}
}

func TestExampleReferenceHelpRemainsGenerated(t *testing.T) {
	t.Parallel()

	stdout, stderr, err := executeRootStreams(t, "cert", "connect", "--help")
	if err != nil {
		t.Fatalf("npc cert connect --help: %v", err)
	}
	for _, want := range []string{
		"Usage:\n  npc cert connect host:port [flags]",
		"--chain",
		"For a usage guide, run 'npc help cert connect'.",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout does not contain %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "Inspect a TLS server's certificates\n") {
		t.Fatalf("reference output unexpectedly contains the curated guide:\n%s", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want no diagnostics", stderr)
	}
}

func TestExampleCertificateGuideUsesClickableLabelsInRichOutput(t *testing.T) {
	t.Parallel()

	const destination = "https://www.rfc-editor.org/rfc/rfc5280"
	rich, _, err := executeRootCommandStreams(t, newGuideTestRoot(false, 0, nil), "help", "cert", "--rich")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rich, "\x1b]8;;"+destination+"\x1b\\") || strings.Count(rich, destination) != 1 {
		t.Fatalf("rich guide must link the label without a second URL: %q", rich)
	}
	plain, _, err := executeRootCommandStreams(t, newGuideTestRoot(false, 0, nil), "help", "cert", "--plain")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain, destination) || strings.Contains(plain, "\x1b") {
		t.Fatalf("plain guide must retain a visible URL without controls: %q", plain)
	}
}

func TestExampleHelpKeyCertificateWorkflow(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	privateKey := filepath.Join(directory, "private.pem")
	publicKey := filepath.Join(directory, "id_ed25519.pub")
	convertedKey := filepath.Join(directory, "private.der")
	certificate := filepath.Join(directory, "localhost.pem")
	caKey := filepath.Join(directory, "ca-key.pem")
	caCertificate := filepath.Join(directory, "ca.pem")
	signedCertificate := filepath.Join(directory, "signed-leaf.pem")
	commands := [][]string{
		{"key", "generate", "ed25519", "--output", privateKey, "--public-out", publicKey, "--public-format", "openssh"},
		{"key", "inspect", "--input", privateKey},
		{"key", "convert", "--input", publicKey, "--to", "pkix-pem", "--output", filepath.Join(directory, "public.pem")},
		{"key", "convert", "--input", privateKey, "--to", "pkcs8-der", "--output", convertedKey},
		{"cert", "create", "--key", convertedKey, "--dns", "localhost", "--output", certificate},
		{"key", "generate", "ed25519", "--output", caKey},
		{"cert", "create", "--ca", "--key", caKey, "--subject", "CN=Local Test CA", "--output", caCertificate},
		{
			"cert", "create", "--key", privateKey, "--dns", "localhost",
			"--issuer-cert", caCertificate, "--issuer-key", caKey, "--output", signedCertificate,
		},
	}
	for _, args := range commands {
		if _, err := executeRoot(t, args...); err != nil {
			t.Fatalf("documented command %q: %v", args, err)
		}
	}
	leaf := readSingleCertificate(t, signedCertificate)
	if err := leaf.CheckSignatureFrom(readSingleCertificate(t, caCertificate)); err != nil {
		t.Fatalf("test CA did not sign the leaf: %v", err)
	}
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Fatalf("certificate does not identify localhost: %v", err)
	}
	output, err := executeRoot(t, "cert", "inspect", "--input", certificate, "--format", "long")
	if err != nil || !strings.Contains(output, "localhost") {
		t.Fatalf("inspect documented certificate: output=%q error=%v", output, err)
	}
}

func TestExampleHelpKeyAESWorkflow(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	key := filepath.Join(directory, "key.bin")
	ciphertext := filepath.Join(directory, "message.gcm")
	if _, err := executeRoot(t, "key", "generate", "aes256", "--output", key); err != nil {
		t.Fatal(err)
	}
	root := newRootCmd()
	root.SetIn(strings.NewReader("deploy at 09:00"))
	if _, _, err := executeRootCommandStreams(t, root, "aes", "encrypt", "--keyfile", key, "--output", ciphertext); err != nil {
		t.Fatal(err)
	}
	plaintext, err := executeRoot(t, "aes", "decrypt", "--keyfile", key, "--input", ciphertext)
	if err != nil || plaintext != "deploy at 09:00" {
		t.Fatalf("recover documented message: plaintext=%q error=%v", plaintext, err)
	}
}
