package cmd

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/certinput"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
	"github.com/sosheskaz-systems/npc/internal/asym"
)

func TestPEMCommandsRejectSkippedBlocks(t *testing.T) {
	t.Parallel()
	chain := testcmd.NewTLSCertificateChain(t)
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: certinput.PEMType, Bytes: chain.Certificate[0]}))
	key, err := asym.NewKey(chain.PrivateKey)
	require.NoError(t, err)
	keyPEM, err := key.Marshal(asym.KeyFormatPKCS8PEM)
	require.NoError(t, err)
	for _, artifact := range []struct {
		wantErr                error
		name, blockType, valid string
	}{
		{name: "cert", blockType: "CERTIFICATE", valid: certificate, wantErr: certinput.ErrTrailingData},
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
				require.NoError(t, os.WriteFile(path, []byte(data), 0o600))
				command := "inspect"
				if artifact.name == "key" {
					command = "key-inspect"
				}
				output, err := executeRoot(t, "cert", command, "--input", path)
				require.ErrorIs(t, err, artifact.wantErr)
				assert.Empty(t, output)
				if artifact.name == "cert" {
					require.NoError(t, os.WriteFile(path, []byte(artifact.valid+data), 0o600))
					output, err = executeRoot(t, "cert", "inspect", "--input", path)
					require.ErrorIs(t, err, certinput.ErrTrailingData, "intermediate corruption")
					assert.Empty(t, output, "intermediate corruption")
					output, err = executeRoot(t, "net", "connect", "--tls", "localhost:1", "--ca", path)
					require.ErrorIs(t, err, certinput.ErrTrailingData, "TLS CA corruption")
					assert.Empty(t, output, "TLS CA corruption")
				}
			})
		}
	}
}
