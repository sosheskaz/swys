package cmd

import (
	"encoding/pem"
	"strings"
	"testing"
)

func TestParsePEMCertificatesRejectsNonCertificateBlock(t *testing.T) {
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})
	_, err := parsePEMCertificates(data)
	if err == nil || !strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatalf("error = %v, want unexpected PEM block type", err)
	}
}

func TestCertificateFormattersDeclareChainRequirements(t *testing.T) {
	tests := []struct {
		format        string
		requiresChain bool
	}{
		{format: "text", requiresChain: false},
		{format: "pem", requiresChain: false},
		{format: "chain", requiresChain: true},
		{format: "fullchain", requiresChain: true},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			formatter, err := getCertFormatter(tt.format)
			if err != nil {
				t.Fatal(err)
			}
			if got := formatter.RequiresChain(); got != tt.requiresChain {
				t.Fatalf("RequiresChain() = %t, want %t", got, tt.requiresChain)
			}
		})
	}
}
