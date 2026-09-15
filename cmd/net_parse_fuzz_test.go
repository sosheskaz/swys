package cmd

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

const maxFuzzNetworkMetadataInputSize = 1 << 12

func FuzzParseALPN(f *testing.F) {
	for _, seed := range []string{
		"",
		"h2",
		"h2,http/1.1",
		",h2",
		"h2,",
		" h2",
		strings.Repeat("x", 255),
		strings.Repeat("x", 256),
		strings.Repeat("é", 127),
		strings.Repeat("é", 128),
		"\x00\xff",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > maxFuzzNetworkMetadataInputSize {
			t.Skip()
		}

		protocols, err := parseALPN(text)
		wantProtocols, valid := referenceALPN(text)
		if (err == nil) != valid {
			t.Fatalf("ALPN %q acceptance = %v, want valid %t", text, err, valid)
		}
		if !valid {
			if protocols != nil {
				t.Fatalf("invalid ALPN returned protocols %q", protocols)
			}
			return
		}
		// ALPN identifiers are opaque bytes. Display sites escape them instead of
		// normalizing the values passed to crypto/tls.
		if !slices.Equal(protocols, wantProtocols) {
			t.Fatalf("ALPN protocols = %q, want ordered opaque bytes %q", protocols, wantProtocols)
		}
		for _, protocol := range protocols {
			if protocol == "" || len(protocol) > 255 {
				t.Fatalf("successful ALPN protocol has invalid byte length %d", len(protocol))
			}
		}
	})
}

// FuzzEscapeNetworkDiagnosticValue characterizes the helper's reversible
// strconv.Quote body contract so later implementations cannot weaken it.
func FuzzEscapeNetworkDiagnosticValue(f *testing.F) {
	for _, seed := range []string{
		"",
		"example.test",
		"quote\"slash\\",
		"line\r\nfeed\tand\x00nul",
		"\x1b[2J\u009b\u202e",
		string([]byte{0xff, 0xfe, 'x'}),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > maxFuzzNetworkMetadataInputSize {
			t.Skip()
		}

		escaped := escapeNetworkDiagnosticValue(value)
		if !utf8.ValidString(escaped) {
			t.Fatalf("escaped network diagnostic is not valid UTF-8: %x", escaped)
		}
		for _, char := range escaped {
			if !strconv.IsPrint(char) {
				t.Fatalf("escaped network diagnostic contains non-printing rune %U: %q", char, escaped)
			}
		}
		decoded, err := strconv.Unquote(`"` + escaped + `"`)
		if err != nil {
			t.Fatalf("escaped network diagnostic is not a valid quoted body: %v", err)
		}
		if decoded != value {
			t.Fatalf("network diagnostic round trip = %q, want %q", decoded, value)
		}
	})
}

func referenceALPN(text string) ([]string, bool) {
	if text == "" {
		return nil, true
	}
	var protocols []string
	for remaining := text; ; {
		protocol, rest, found := strings.Cut(remaining, ",")
		if protocol == "" || len(protocol) > 255 || hasFuzzALPNEdgeWhitespace(protocol) {
			return nil, false
		}
		protocols = append(protocols, protocol)
		if !found {
			return protocols, true
		}
		remaining = rest
	}
}

func hasFuzzALPNEdgeWhitespace(protocol string) bool {
	first, _ := utf8.DecodeRuneInString(protocol)
	last, _ := utf8.DecodeLastRuneInString(protocol)
	return unicode.IsSpace(first) || unicode.IsSpace(last)
}
