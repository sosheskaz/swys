package cmd

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// TestBase64Format_DoesNotTruncateOutput reproduces the bug where `-f base64`
// drops the final base64 group whenever the underlying output isn't a
// multiple of 3 bytes. The wrapping base64.Encoder buffers partial groups
// internally and must be Close()d to flush them; nothing currently closes it.
func TestBase64Format_DoesNotTruncateOutput(t *testing.T) {
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"aes", "genkey", "-b", "128", "-f", "base64"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(buf.String()))
	if err != nil {
		t.Fatalf("output %q is not valid base64: %v", buf.String(), err)
	}
	if len(decoded) != 16 {
		t.Errorf("expected 16 decoded bytes (128-bit key), got %d (output: %q)", len(decoded), buf.String())
	}
}
