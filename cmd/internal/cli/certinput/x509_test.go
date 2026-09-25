package certinput_test

import (
	"bytes"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/certinput"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
)

func TestParsePEMCertificates(t *testing.T) {
	t.Parallel()
	chain := testcmd.NewTLSCertificateChain(t).Certificate
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: certinput.PEMType, Bytes: chain[0]})
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: certinput.PEMType, Bytes: chain[1]})
	wrongType := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})
	malformedDER := pem.EncodeToMemory(&pem.Block{Type: certinput.PEMType, Bytes: []byte("not a certificate")})

	tests := []struct {
		wantErr   error
		name      string
		input     []byte
		wantCount int
	}{
		{name: "empty", wantErr: certinput.ErrNoCertificates},
		{name: "whitespace", input: []byte(" \n\t"), wantErr: certinput.ErrNoCertificates},
		{name: "one certificate", input: leafPEM, wantCount: 1},
		{name: "certificate chain", input: append(bytes.Clone(leafPEM), rootPEM...), wantCount: 2},
		{name: "surrounding whitespace", input: append(append([]byte(" \n"), leafPEM...), []byte("\t \n")...), wantCount: 1},
		{name: "malformed DER", input: malformedDER},
		{name: "wrong block type", input: wrongType, wantErr: certinput.ErrUnexpectedPEMType},
		{name: "garbage before", input: append([]byte("garbage\n"), leafPEM...), wantErr: certinput.ErrTrailingData},
		{name: "garbage between", input: append(append(bytes.Clone(leafPEM), []byte("garbage\n")...), rootPEM...), wantErr: certinput.ErrTrailingData},
		{name: "garbage after", input: append(bytes.Clone(leafPEM), []byte("garbage\n")...), wantErr: certinput.ErrTrailingData},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			certificates, err := certinput.ParsePEMCertificates(test.input)
			if test.name == "malformed DER" {
				if err == nil || !strings.Contains(err.Error(), "parse PEM certificate") {
					t.Fatalf("error = %v, want malformed certificate error", err)
				}
				return
			}
			require.ErrorIs(t, err, test.wantErr, "error = %v, want %v", err, test.wantErr)
			if len(certificates) != test.wantCount {
				t.Fatalf("certificate count = %d, want %d", len(certificates), test.wantCount)
			}
		})
	}
}
