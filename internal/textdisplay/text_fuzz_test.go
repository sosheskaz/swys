package textdisplay_test

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/sosheskaz/swys/internal/textdisplay"
)

const maxFuzzTextDisplaySize = 1 << 12

// fuzzZeroWidthJoiner is the only non-printing rune Escape deliberately lets
// through, so emoji sequences such as "\U0001F469\u200d\U0001F4BB" survive.
const fuzzZeroWidthJoiner = '\u200d'

// FuzzEscapeKeepsDisplayLinesSafe drives the shared terminal escaper — the
// last stop for peer-controlled certificate, Connect, and HTTP strings — with
// arbitrary bytes. Output must stay valid UTF-8 made only of printable runes
// (plus the deliberate zero-width joiner), values that are already safe must
// pass through verbatim, and escaping must be idempotent.
func FuzzEscapeKeepsDisplayLinesSafe(f *testing.F) {
	for _, seed := range []string{
		"",
		"printable ASCII",
		"José 世界",
		"line\r\nfeed\tand\x00nul",
		"\x1b[2J\u009b\u202e",
		string([]byte{0xff, 0xfe, 'x'}),
		"emoji \U0001F469\u200d\U0001F4BB sequence",
		"\u007f del\u00a0nbsp",
		"\ufffd replacement",
		"back\\slash and \u200b\u200d marks",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > maxFuzzTextDisplaySize {
			t.Skip()
		}

		escaped := textdisplay.Escape(value)
		if !utf8.ValidString(escaped) {
			t.Fatalf("escaped value is not valid UTF-8: %x", escaped)
		}
		for _, character := range escaped {
			if !strconv.IsPrint(character) && character != fuzzZeroWidthJoiner {
				t.Fatalf("escaped value kept non-printing rune %q", character)
			}
		}
		if fuzzIsPrintableWithJoiner(value) && escaped != value {
			t.Fatalf("already-safe value changed: got %q, want %q", escaped, value)
		}
		if again := textdisplay.Escape(escaped); again != escaped {
			t.Fatalf("escape is not idempotent: %q became %q", escaped, again)
		}
	})
}

func fuzzIsPrintableWithJoiner(value string) bool {
	for _, character := range value {
		if !strconv.IsPrint(character) && character != fuzzZeroWidthJoiner {
			return false
		}
	}
	return utf8.ValidString(value)
}

// fuzzStyleSequence matches only the SGR sequences Style emits, so rich-mode
// output can be checked with the same line-safety rules as plain output.
var fuzzStyleSequence = regexp.MustCompile("\x1b\\[[0-9;]*m")

// FuzzPrinterFieldsAndTablesStayOnTheirLines renders generated peer-controlled
// labels and values through the shared report printer in both layout modes
// and both plain and rich output. Every field must stay on exactly one line,
// plain output must never contain an ANSI escape, all visible runes must be
// printable (or the zero-width joiner), already-safe values must survive
// verbatim, and rich output must reduce to plain output once its SGR styling
// is stripped.
func FuzzPrinterFieldsAndTablesStayOnTheirLines(f *testing.F) {
	f.Add("Subject", "CN=example", "issuer", uint8(80), false)
	f.Add("label\ninjection", "value\x1b[2Jattempt", "second\x00value", uint8(20), true)
	f.Add("José", "世界 \U0001F469\u200d\U0001F4BB", "r\"\tquote", uint8(200), true)
	f.Add("", "", "", uint8(0), false)
	f.Add("very wide label for wrapping", "x", "y", uint8(10), true)

	f.Fuzz(func(t *testing.T, label, value, other string, width uint8, rich bool) {
		if len(label) > maxFuzzTextDisplaySize || len(value) > maxFuzzTextDisplaySize || len(other) > maxFuzzTextDisplaySize {
			t.Skip()
		}

		fields := []textdisplay.Field{
			{Label: label, Value: value, Role: textdisplay.Warning},
			{Label: "second", Value: other, Role: textdisplay.Normal},
		}
		var plain bytes.Buffer
		textdisplay.New(&plain, textdisplay.Options{Width: int(width)}).Fields(fields)
		fuzzCheckFieldLines(t, plain.String(), fields, false)

		var styled bytes.Buffer
		textdisplay.New(&styled, textdisplay.Options{Width: int(width), Rich: rich}).Fields(fields)
		fuzzCheckFieldLines(t, styled.String(), fields, rich)
		if stripped := fuzzStripStyle(styled.String()); stripped != plain.String() {
			t.Fatalf("rich Fields output %q does not reduce to plain %q", stripped, plain.String())
		}

		headers := []string{label, "Header"}
		rows := [][]string{{value, other}, {"row", label}}
		var plainTable bytes.Buffer
		plainPrinter := textdisplay.New(&plainTable, textdisplay.Options{Width: int(width)})
		plainPrinter.Table(headers, rows)
		fuzzCheckTableLines(t, plainTable.String(), headers, rows, false)

		var styledTable bytes.Buffer
		styledPrinter := textdisplay.New(&styledTable, textdisplay.Options{Width: int(width), Rich: rich})
		styledPrinter.Table(headers, rows)
		fuzzCheckTableLines(t, styledTable.String(), headers, rows, rich)
		if stripped := fuzzStripStyle(styledTable.String()); stripped != plainTable.String() {
			t.Fatalf("rich Table output %q does not reduce to plain %q", stripped, plainTable.String())
		}
	})
}

func fuzzCheckFieldLines(t *testing.T, output string, fields []textdisplay.Field, rich bool) {
	t.Helper()
	lines := strings.Split(output, "\n")
	if len(lines) != len(fields)+1 || lines[len(lines)-1] != "" {
		t.Fatalf("Fields emitted %d lines, want exactly one per field: %q", len(lines)-1, output)
	}
	for index, line := range lines[:len(fields)] {
		visible := fuzzStripStyle(line)
		if !rich && visible != line {
			t.Fatalf("plain field line %d carries styling: %q", index, line)
		}
		if !fuzzVisibleLineIsSafe(visible) {
			t.Fatalf("field line %d is unsafe: %q", index, line)
		}
		if fuzzIsPrintableWithJoiner(fields[index].Value) && !strings.HasSuffix(visible, fields[index].Value) {
			t.Fatalf("already-safe value %q not preserved on its line %q", fields[index].Value, line)
		}
	}
}

func fuzzCheckTableLines(t *testing.T, output string, headers []string, rows [][]string, rich bool) {
	t.Helper()
	visible := fuzzStripStyle(output)
	for _, line := range strings.Split(visible, "\n") {
		if !fuzzVisibleLineIsSafe(line) {
			t.Fatalf("table line is unsafe: %q", line)
		}
	}
	if !rich && visible != output {
		t.Fatalf("plain table output carries styling: %q", output)
	}
	cells := make([]string, 0, len(headers)+len(rows)*len(headers))
	cells = append(cells, headers...)
	for _, row := range rows {
		cells = append(cells, row...)
	}
	for _, cell := range cells {
		if fuzzIsPrintableWithJoiner(cell) && !strings.Contains(visible, cell) {
			t.Fatalf("already-safe cell %q missing from table output %q", cell, output)
		}
	}
}

func fuzzStripStyle(value string) string {
	return fuzzStyleSequence.ReplaceAllString(value, "")
}

func fuzzVisibleLineIsSafe(line string) bool {
	if strings.ContainsRune(line, '\x1b') {
		return false // an escape outside SGR styling would reach the terminal
	}
	for _, character := range line {
		if !strconv.IsPrint(character) && character != fuzzZeroWidthJoiner {
			return false
		}
	}
	return utf8.ValidString(line)
}
