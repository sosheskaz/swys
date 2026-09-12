package asym

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

const maxFuzzFormatInputSize = 1 << 12

func FuzzFormatFingerprint(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xff, 0x10, 0x80, 0x01})
	f.Add(bytes.Repeat([]byte{0x00, 0xff, 0x7f, 0x80}, 8))

	f.Fuzz(func(t *testing.T, fingerprint []byte) {
		if len(fingerprint) > maxFuzzFormatInputSize {
			t.Skip()
		}

		original := bytes.Clone(fingerprint)
		formatted := formatFingerprint(fingerprint)
		if !bytes.Equal(fingerprint, original) {
			t.Fatal("formatFingerprint modified its input")
		}
		if len(fingerprint) == 0 {
			if formatted != "" {
				t.Fatalf("empty fingerprint formatted as %q", formatted)
			}
			return
		}
		if len(formatted) != len(fingerprint)*3-1 {
			t.Fatalf("formatted length = %d, want %d", len(formatted), len(fingerprint)*3-1)
		}
		for index, char := range []byte(formatted) {
			if index%3 == 2 {
				if char != ':' {
					t.Fatalf("separator at byte %d = %q, want colon", index, char)
				}
				continue
			}
			if !strings.ContainsRune("0123456789ABCDEF", rune(char)) {
				t.Fatalf("fingerprint contains non-uppercase-hex byte %q", char)
			}
		}
		decoded, err := hex.DecodeString(strings.ReplaceAll(formatted, ":", ""))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded, fingerprint) {
			t.Fatal("formatted fingerprint changed byte values or ordering")
		}
	})
}

func FuzzEscapeDiagnosticValue(f *testing.F) {
	for _, seed := range []string{
		"",
		"printable ASCII",
		"José 世界",
		"line\r\nfeed\tand\x00nul",
		"\x1b[2J\u009b\u202e",
		string([]byte{0xff, 0xfe, 'x'}),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > maxFuzzFormatInputSize {
			t.Skip()
		}

		escaped := EscapeDiagnosticValue(value)
		if !utf8.ValidString(escaped) {
			t.Fatalf("escaped diagnostic is not valid UTF-8: %x", escaped)
		}
		for _, char := range escaped {
			if !strconv.IsPrint(char) {
				t.Fatalf("escaped diagnostic contains non-printing rune %U: %q", char, escaped)
			}
		}
		if again := EscapeDiagnosticValue(escaped); again != escaped {
			t.Fatalf("escaping is not idempotent: first %q, second %q", escaped, again)
		}
		if utf8.ValidString(value) && allFuzzDiagnosticRunesPrintable(value) && escaped != value {
			t.Fatalf("printable value changed: got %q, want %q", escaped, value)
		}
	})
}

func allFuzzDiagnosticRunesPrintable(value string) bool {
	for _, char := range value {
		if !strconv.IsPrint(char) {
			return false
		}
	}
	return true
}
