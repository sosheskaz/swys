package tlsconfig

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

const maxFuzzALPNInputSize = 1 << 12

var errFuzzInvalidALPN = errors.New("invalid fuzz flags")

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
		if len(text) > maxFuzzALPNInputSize {
			t.Skip()
		}

		protocols, err := ParseALPN(text, errFuzzInvalidALPN)
		wantProtocols, valid := referenceALPN(text)
		if (err == nil) != valid {
			t.Fatalf("ALPN %q acceptance = %v, want valid %t", text, err, valid)
		}
		if err != nil && !errors.Is(err, errFuzzInvalidALPN) {
			t.Fatalf("ALPN %q error = %v, want the caller's error identity", text, err)
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
