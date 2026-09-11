package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

func TestExampleKeyPublicDerivesOpenSSH(t *testing.T) {
	t.Parallel()
	privateKey := generateExampleEd25519Key(t)
	output, _, err := executeRootStreamsWithInput(
		t,
		bytes.NewReader(privateKey),
		"key", "public", "--to", "openssh",
	)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(output))
	if err != nil {
		t.Fatal(err)
	}
	if comment != "" || len(options) != 0 || len(rest) != 0 {
		t.Fatalf("OpenSSH output comment/options/rest = %q/%q/%q", comment, options, rest)
	}
	if publicKey.Type() != ssh.KeyAlgoED25519 || output[len(output)-1] != '\n' {
		t.Fatalf("OpenSSH output type/newline = %q/%t", publicKey.Type(), output[len(output)-1] == '\n')
	}
}

func TestExampleKeyPublicDefaultsToPKIXPEM(t *testing.T) {
	t.Parallel()
	output, _, err := executeRootStreamsWithInput(
		t,
		bytes.NewReader(generateExampleEd25519Key(t)),
		"key", "public",
	)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode([]byte(output))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("PKIX PEM output = %q", output)
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		t.Fatal(err)
	}
}

func TestExampleKeyConvertReserializesPublicKey(t *testing.T) {
	t.Parallel()
	privateKey, err := asym.ParseKey(generateExampleEd25519Key(t))
	if err != nil {
		t.Fatal(err)
	}
	openSSH, err := privateKey.Marshal(asym.KeyFormatOpenSSH)
	if err != nil {
		t.Fatal(err)
	}
	output, _, err := executeRootStreamsWithInput(
		t,
		bytes.NewReader(openSSH),
		"key", "convert", "--to", "pkix-pem",
	)
	if err != nil {
		t.Fatal(err)
	}
	converted, err := asym.ParseKey([]byte(output))
	if err != nil {
		t.Fatal(err)
	}
	if converted.IsPrivate() {
		t.Fatal("converted output contains private material")
	}
}

func generateExampleEd25519Key(t *testing.T) []byte {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}
