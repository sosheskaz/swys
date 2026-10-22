package help

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

const maxFuzzPagerConfigurationSize = 1 << 10

// fuzzPagerAccepted and the three rejection fragments match parsePager's
// outcome classes; the reference tokenizer reports the same class so the
// oracle stays about structure, not message wording.
const (
	fuzzPagerAccepted       = "accepted"
	fuzzPagerTrailingEscape = "trailing escape"
	fuzzPagerUnterminated   = "unterminated quote"
	fuzzPagerNoExecutable   = "expected an executable"

	// fuzzPagerQuoteEscapeRunes are the runes that change tokenization.
	fuzzPagerQuoteEscapeRunes = `'"\`
	fuzzPagerDoubleStopRunes  = `"\`
)

// FuzzParsePagerShellWords tokenizes generated PAGER values — environment
// input that becomes a pager process's argv — against an independently
// structured span-scanning reference. Configurations without any quoting or
// escaping must match strings.Fields exactly, and every outcome (including
// the three rejection classes) must agree with the reference. Because the
// tokenizer splits directly into argv, shell metacharacters in the value can
// never gain a second interpretation.
func FuzzParsePagerShellWords(f *testing.F) {
	f.Add("less -R")
	f.Add("")
	f.Add("   \t  ")
	f.Add("'/path with spaces/pager' \"two words\" plain\\ value ''")
	f.Add("''")
	f.Add("pager ''")
	f.Add("a\\")
	f.Add("'unterminated")
	f.Add("\"unterminated")
	f.Add("\"trailing\\")
	f.Add("back\\\\slash \"quote\\\"inner\" 'lit\\eral'")
	f.Add("em\\ joe \U0001F469\u200d\U0001F4BB")
	f.Add("one''two\"\"three")

	f.Fuzz(func(t *testing.T, configuration string) {
		if len(configuration) > maxFuzzPagerConfigurationSize {
			t.Skip()
		}

		arguments, err := parsePager(configuration)
		want, wantClass := fuzzReferencePagerWords(configuration)
		if wantClass != fuzzPagerAccepted {
			if err == nil {
				t.Fatalf("configuration %q accepted, want %s", configuration, wantClass)
			}
			if !errors.Is(err, ErrInvalidPager) {
				t.Fatalf("configuration %q rejected with %v, want %s", configuration, err, wantClass)
			}
			if !strings.Contains(err.Error(), wantClass) {
				t.Fatalf("configuration %q rejected with %q, want %s", configuration, err.Error(), wantClass)
			}
			return
		}
		if err != nil {
			t.Fatalf("configuration %q rejected with %v, want arguments %q", configuration, err, want)
		}
		if !reflect.DeepEqual(arguments, want) {
			t.Fatalf("configuration %q split into %q, want %q", configuration, arguments, want)
		}

		if !strings.ContainsAny(configuration, fuzzPagerQuoteEscapeRunes) {
			if fields := strings.Fields(configuration); len(fields) == 0 {
				t.Fatalf("configuration %q without quoting produced %q, want rejection", configuration, arguments)
			} else if !reflect.DeepEqual(arguments, fields) {
				t.Fatalf("configuration %q without quoting split into %q, want strings.Fields %q", configuration, arguments, fields)
			}
		}
	})
}

// fuzzReferencePagerWords re-derives the pager command line by slicing spans
// between interesting runes, instead of parsePager's per-rune state machine:
// unquoted text runs to the next quote, escape, or whitespace; single quotes
// span to their closing quote with everything literal; double quotes stop
// only for their closing quote or a backslash that escapes just quotes and
// backslashes. It returns the expected words, or the rejection fragment.
func fuzzReferencePagerWords(configuration string) ([]string, string) {
	var words []string
	var current strings.Builder
	started := false
	flush := func() {
		words = append(words, current.String())
		current.Reset()
		started = false
	}
	rest := configuration
	for rest != "" {
		end := strings.IndexFunc(rest, func(r rune) bool {
			return r == '\'' || r == '"' || r == '\\' || unicode.IsSpace(r)
		})
		if end < 0 {
			current.WriteString(rest)
			started = true
			break
		}
		if end > 0 {
			current.WriteString(rest[:end])
			started = true
			rest = rest[end:]
		}
		character, size := utf8.DecodeRuneInString(rest)
		rest = rest[size:]
		switch character {
		case '\\':
			escaped, escapedSize := utf8.DecodeRuneInString(rest)
			if escapedSize == 0 {
				return nil, fuzzPagerTrailingEscape
			}
			rest = rest[escapedSize:]
			current.WriteRune(escaped)
			started = true
		case '\'':
			started = true
			closing := strings.IndexRune(rest, '\'')
			if closing < 0 {
				return nil, fuzzPagerUnterminated
			}
			current.WriteString(rest[:closing])
			rest = rest[closing+1:]
		case '"':
			started = true
			for {
				stop := strings.IndexFunc(rest, func(r rune) bool {
					return strings.ContainsRune(fuzzPagerDoubleStopRunes, r)
				})
				if stop < 0 {
					return nil, fuzzPagerUnterminated
				}
				current.WriteString(rest[:stop])
				rest = rest[stop:]
				if rest[0] == '"' {
					rest = rest[1:]
					break
				}
				// A backslash inside double quotes escapes only quotes and
				// backslashes; any other escape keeps its backslash.
				escaped, escapedSize := utf8.DecodeRuneInString(rest[1:])
				if escapedSize == 0 {
					return nil, fuzzPagerTrailingEscape
				}
				if escaped != '"' && escaped != '\\' {
					current.WriteByte('\\')
				}
				current.WriteRune(escaped)
				rest = rest[1+escapedSize:]
			}
		default:
			if started {
				flush()
			}
		}
	}
	if started {
		flush()
	}
	if len(words) == 0 || words[0] == "" {
		return nil, fuzzPagerNoExecutable
	}
	return words, fuzzPagerAccepted
}
