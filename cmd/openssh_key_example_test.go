package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

func TestExampleKeyCommandsConsumeOpenSSHKeys(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateBlock, err := ssh.MarshalPrivateKey(privateKey, "developer@example")
	if err != nil {
		t.Fatal(err)
	}
	privateData := pem.EncodeToMemory(privateBlock)

	inspection, stderr, err := executeRootStreamsWithInput(t, bytes.NewReader(privateData), "key", "inspect")
	if err != nil {
		t.Fatal(err)
	}
	if stderr != "" || !strings.Contains(inspection, "ed25519") || !strings.Contains(inspection, "private") {
		t.Fatalf("inspection stdout/stderr = %q/%q", inspection, stderr)
	}

	publicPEM, _, err := executeRootStreamsWithInput(t, bytes.NewReader(privateData), "key", "public")
	if err != nil {
		t.Fatal(err)
	}
	public, err := asym.ParseKey([]byte(publicPEM))
	if err != nil || public.IsPrivate() {
		t.Fatalf("public output parse = %v, private = %t", err, err == nil && public.IsPrivate())
	}

	sshPublic, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	authorizedKey := append([]byte("\n# workstation key\nrestrict,no-agent-forwarding "), bytes.TrimSpace(ssh.MarshalAuthorizedKey(sshPublic))...)
	authorizedKey = append(authorizedKey, []byte(" developer@example\n")...)
	convertedPEM, _, err := executeRootStreamsWithInput(
		t, bytes.NewReader(authorizedKey), "key", "convert", "--to", "pkix-pem",
	)
	if err != nil {
		t.Fatal(err)
	}
	converted, err := asym.ParseKey([]byte(convertedPEM))
	if err != nil || converted.IsPrivate() {
		t.Fatalf("converted public key parse = %v, private = %t", err, err == nil && converted.IsPrivate())
	}
}

func TestExampleCertificateAndTLSConsumersAcceptOpenSSHPrivateKey(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateBlock, err := ssh.MarshalPrivateKey(privateKey, "tls identity")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "identity.key")
	certPath := filepath.Join(dir, "identity.crt")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(privateBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executeRootStreams(
		t, "cert", "create", "--key", keyPath, "--output", certPath,
	); err != nil {
		t.Fatal(err)
	}

	tlsCommand := newNetConnectTestCommand(t, "tls")
	if err := tlsCommand.Flags().Set(tlsCertFlagName, certPath); err != nil {
		t.Fatal(err)
	}
	if err := tlsCommand.Flags().Set(tlsKeyFlagName, keyPath); err != nil {
		t.Fatal(err)
	}
	identity, configured, err := tlsClientIdentityFromCommand(tlsCommand)
	if err != nil {
		t.Fatal(err)
	}
	if !configured || len(identity.Certificate) != 1 || identity.PrivateKey == nil {
		t.Fatalf("TLS identity = configured:%t chain:%d key:%T", configured, len(identity.Certificate), identity.PrivateKey)
	}
}
