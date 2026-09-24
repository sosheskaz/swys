package pemstrict

import (
	"bytes"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				require.NotNil(t, block, "suffix %q", suffix)
				assert.Equal(t, "TEST", block.Type, "suffix %q", suffix)
				assert.Equal(t, []byte("data"), block.Bytes, "suffix %q", suffix)
				assert.Equal(t, "retained", block.Headers["Comment"], "suffix %q", suffix)
				assert.True(t, bytes.Equal(rest, suffix), "rest = %q, want suffix %q", rest, suffix)
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
			assert.Nil(t, block, "prefix %q", prefix)
			assert.True(t, bytes.Equal(rest, input), "rest = %q, want unchanged input %q", rest, input)
		})
	}
}
