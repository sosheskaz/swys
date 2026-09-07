package cmd

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func FuzzBase64URLDecoder(f *testing.F) {
	for _, seed := range []string{"", "Zg", "Zg==", "Zm8=", "Zm9v", "Zg=", "Z===", "Zm\r\n8=", "Zm8=A", "_w=="} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 4096 {
			t.Skip()
		}
		clean := strings.NewReplacer("\r", "", "\n", "").Replace(input)
		encoding := base64.RawURLEncoding
		if strings.Contains(clean, "=") {
			encoding = base64.URLEncoding
		}
		want, wantErr := encoding.DecodeString(clean)
		for _, reader := range []io.Reader{strings.NewReader(input), iotest.OneByteReader(strings.NewReader(input))} {
			got, err := io.ReadAll(base64URLDecoder(reader))
			if (err == nil) != (wantErr == nil) {
				t.Fatalf("acceptance differs from stdlib: got %v, want %v", err, wantErr)
			}
			if err == nil && !bytes.Equal(got, want) {
				t.Fatalf("decoded bytes differ: got %x, want %x", got, want)
			}
		}
	})
}
