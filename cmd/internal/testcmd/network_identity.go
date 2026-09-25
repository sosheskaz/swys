package testcmd

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

const (
	identityOutputFlag = "--output"
	identityKeyFlag    = "--key"
	identityKeyNoun    = "key"
	identityCertNoun   = "cert"
	identityGenerate   = "generate"
	identityCreate     = "create"
	identityAlgorithm  = "ed25519"
)

// NetworkIdentity names certificate and key fixtures created through the CLI.
type NetworkIdentity struct {
	CACert     string
	ServerCert string
	ServerKey  string
	ClientCert string
	ClientKey  string
}

// CreateNetworkIdentity uses the CLI to create short-lived test certificates.
func CreateNetworkIdentity(tb testing.TB, newRoot func() *cobra.Command) NetworkIdentity {
	tb.Helper()
	directory := tb.TempDir()
	identity := NetworkIdentity{
		CACert:     filepath.Join(directory, "ca.crt"),
		ServerCert: filepath.Join(directory, "server.crt"),
		ServerKey:  filepath.Join(directory, "server.key"),
		ClientCert: filepath.Join(directory, "client.crt"),
		ClientKey:  filepath.Join(directory, "client.key"),
	}
	caKey := filepath.Join(directory, "ca.key")
	commands := [][]string{
		{identityKeyNoun, identityGenerate, identityAlgorithm, identityOutputFlag, caKey},
		{identityKeyNoun, identityGenerate, identityAlgorithm, identityOutputFlag, identity.ServerKey},
		{identityKeyNoun, identityGenerate, identityAlgorithm, identityOutputFlag, identity.ClientKey},
		{identityCertNoun, identityCreate, "--ca", "--subject", "CN=test-ca", identityKeyFlag, caKey, identityOutputFlag, identity.CACert},
		{
			identityCertNoun, identityCreate, "--dns", "localhost", "--server-only", identityKeyFlag, identity.ServerKey,
			"--issuer-cert", identity.CACert, "--issuer-key", caKey, identityOutputFlag, identity.ServerCert,
		},
		{
			identityCertNoun, identityCreate, "--subject", "CN=client", "--client-only", identityKeyFlag, identity.ClientKey,
			"--issuer-cert", identity.CACert, "--issuer-key", caKey, identityOutputFlag, identity.ClientCert,
		},
	}
	for _, args := range commands {
		_, stderr, err := RunStreams(tb, newRoot(), bytes.NewReader(nil), args...)
		if err != nil {
			tb.Fatalf("execute %v: %v (stderr %q)", args, err, stderr)
		}
	}
	return identity
}
