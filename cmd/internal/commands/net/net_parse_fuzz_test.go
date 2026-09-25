package net

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

// FuzzEscapeNetworkDiagnosticValue pins the escaper against an independent
// rune-by-rune reference. The reversibility and printability invariants follow
// from strconv.Quote by construction, so exact equality with the reference is
// what keeps a later implementation from silently changing the escaping.
func FuzzEscapeNetworkDiagnosticValue(f *testing.F) {
	for _, seed := range []string{
		"",
		"example.test",
		"quote\"slash\\",
		"line\r\nfeed\tand\x00nul",
		"\x1b[2J\u009b\u202e",
		"caf\u00e9 \u4e16\u754c",
		"\U0001d173\U0001f600",
		string([]byte{0xff, 0xfe, 'x'}),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > maxFuzzNetworkMetadataInputSize {
			t.Skip()
		}

		escaped := escapeNetworkDiagnosticValue(value)
		if want := referenceNetworkDiagnosticEscape(value); escaped != want {
			t.Fatalf("escaped network diagnostic = %q, want %q", escaped, want)
		}
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

// referenceNetworkDiagnosticEscape rebuilds the body of a Go double-quoted
// string one rune at a time. It is an independent oracle for the escaper: it
// shares no code with strconv's quoting, so a change to which runes are
// escaped, to their escape form, or to hex-digit case is visible as a
// difference instead of being absorbed by a round trip.
func referenceNetworkDiagnosticEscape(value string) string {
	var escaped strings.Builder
	for index := 0; index < len(value); {
		char, width := utf8.DecodeRuneInString(value[index:])
		if char == utf8.RuneError && width == 1 {
			// A byte that is not part of a valid encoding keeps its own value.
			escaped.WriteString(referenceHexEscape(`\x`, rune(value[index]), 2))
			index += width
			continue
		}
		escaped.WriteString(referenceEscapedRune(char))
		index += width
	}
	return escaped.String()
}

func referenceEscapedRune(char rune) string {
	if char == '"' || char == '\\' {
		return `\` + string(char)
	}
	if unicode.IsPrint(char) {
		return string(char)
	}
	switch char {
	case '\a':
		return `\a`
	case '\b':
		return `\b`
	case '\f':
		return `\f`
	case '\n':
		return `\n`
	case '\r':
		return `\r`
	case '\t':
		return `\t`
	case '\v':
		return `\v`
	}
	switch {
	case char < ' ' || char == 0x7f:
		return referenceHexEscape(`\x`, char, 2)
	case char < 0x10000:
		return referenceHexEscape(`\u`, char, 4)
	default:
		return referenceHexEscape(`\U`, char, 8)
	}
}

func referenceHexEscape(prefix string, char rune, digits int) string {
	const lowerHexDigits = "0123456789abcdef"
	escaped := make([]byte, 0, len(prefix)+digits)
	escaped = append(escaped, prefix...)
	for shift := (digits - 1) * 4; shift >= 0; shift -= 4 {
		escaped = append(escaped, lowerHexDigits[char>>shift&0xf])
	}
	return string(escaped)
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
