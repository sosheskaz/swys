package pemstrict

import (
	"bytes"
	"encoding/pem"
	"testing"
)

func TestDecodePreservesPEMConventions(t *testing.T) {
	t.Parallel()
	encoded := pem.EncodeToMemory(&pem.Block{Type: "TEST", Bytes: []byte("data"), Headers: map[string]string{"Comment": "retained"}})
	for _, newline := range []string{"\n", "\r\n"} {
		t.Run(newline, func(t *testing.T) {
			t.Parallel()
			first := bytes.ReplaceAll(encoded, []byte("\n"), []byte(newline))
			for _, suffix := range [][]byte{nil, []byte(" \t\ntrailing"), encoded, append([]byte("garbage\n"), encoded...)} {
				input := append(bytes.Clone(first), suffix...)
				block, rest := Decode(input)
				if block == nil || block.Type != "TEST" || string(block.Bytes) != "data" || block.Headers["Comment"] != "retained" || !bytes.Equal(rest, suffix) {
					t.Fatalf("Decode = %#v, %q; want original block and %q", block, rest, suffix)
				}
			}
		})
	}
}

func TestDecodeRejectsMalformedFirstBlock(t *testing.T) {
	t.Parallel()
	valid := pem.EncodeToMemory(&pem.Block{Type: "TEST", Bytes: []byte("data")})
	for _, prefix := range []string{"", "garbage\n", "-----BEGIN TEST-----\n!\n-----END TEST-----\n", "-----BEGIN TEST-----\n"} {
		t.Run(prefix, func(t *testing.T) {
			t.Parallel()
			input := []byte(prefix)
			if prefix != "" {
				input = append(input, valid...)
			}
			block, rest := Decode(input)
			if block != nil || !bytes.Equal(rest, input) {
				t.Fatalf("Decode = %#v, %q, want nil and unchanged input", block, rest)
			}
		})
	}
}
