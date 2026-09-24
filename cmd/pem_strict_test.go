package cmd

import (
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sosheskaz-systems/npc/internal/asym"
)

func TestPEMCommandsRejectSkippedBlocks(t *testing.T) {
	t.Parallel()
	chain := newTLSCertificateChain(t)
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: chain.Certificate[0]}))
	key, err := asym.NewKey(chain.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := key.Marshal(asym.KeyFormatPKCS8PEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range []struct {
		wantErr                error
		name, blockType, valid string
	}{
		{name: "cert", blockType: "CERTIFICATE", valid: certificate, wantErr: errTrailingCertificateData},
		{name: "key", blockType: "PRIVATE KEY", valid: string(keyPEM), wantErr: asym.ErrMalformedKey},
	} {
		for _, malformed := range []struct{ name, data string }{
			{name: "invalid base64", data: "-----BEGIN TYPE-----\n!invalid!\n-----END TYPE-----\n"},
			{name: "missing end", data: "-----BEGIN TYPE-----\nYQ==\n"},
			{name: "wrong end type", data: "-----BEGIN TYPE-----\nYQ==\n-----END OTHER-----\n"},
			{name: "malformed begin", data: "-----BEGIN TYPE----\nYQ==\n-----END TYPE-----\n"},
			{name: "malformed end", data: "-----BEGIN TYPE-----\nYQ==\n-----END TYPE----\n"},
		} {
			t.Run(artifact.name+"/"+malformed.name, func(t *testing.T) {
				t.Parallel()
				data := strings.ReplaceAll(malformed.data, "TYPE", artifact.blockType) + artifact.valid
				path := filepath.Join(t.TempDir(), "artifact.pem")
				if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
				output, err := executeRoot(t, artifact.name, "inspect", "--input", path)
				if !errors.Is(err, artifact.wantErr) {
					t.Fatalf("error = %v, want %v", err, artifact.wantErr)
				}
				if output != "" {
					t.Fatalf("output = %q, want empty", output)
				}
				if artifact.name == "cert" {
					if err := os.WriteFile(path, []byte(artifact.valid+data), 0o600); err != nil {
						t.Fatal(err)
					}
					output, err = executeRoot(t, "cert", "inspect", "--input", path)
					if !errors.Is(err, errTrailingCertificateData) || output != "" {
						t.Fatalf("intermediate corruption: output = %q, error = %v", output, err)
					}
					output, err = executeRoot(t, "net", "connect", "--tls", "localhost:1", "--ca", path)
					if !errors.Is(err, errTrailingCertificateData) || output != "" {
						t.Fatalf("TLS CA corruption: output = %q, error = %v", output, err)
					}
				}
			})
		}
	}
}
