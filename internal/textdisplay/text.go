// Package textdisplay renders human-readable reports without owning their content.
package textdisplay

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/clipperhouse/displaywidth"
)

// Options controls layout and terminal styling. A zero value renders plain text.
type Options struct {
	Width int
	Rich  bool
}

// Field is a labeled report value.
type Field struct {
	Label string
	Value string
	Role  Role
}

// Role describes the meaning of styled text.
type Role uint8

// Roles apply restrained styles without replacing textual status.
const (
	Normal Role = iota
	Strong
	Muted
	Success
	Warning
	Failure
)

// Printer writes a report, retaining the first write error.
type Printer struct {
	writer  io.Writer
	err     error
	options Options
}

// New constructs a printer. Invalid or omitted widths use 100 columns.
func New(writer io.Writer, options Options) *Printer {
	if options.Width <= 0 {
		options.Width = 100
	}
	return &Printer{writer: writer, options: options}
}

// Err returns the first output failure, preserving its identity.
func (printer *Printer) Err() error { return printer.err }

// Escape makes an untrusted value safe for a single display line.
func Escape(value string) string {
	var output strings.Builder
	for value != "" {
		character, size := utf8.DecodeRuneInString(value)
		switch {
		case character == utf8.RuneError && size == 1:
			fmt.Fprintf(&output, "\\x%02x", value[0])
		case strconv.IsPrint(character) || character == '\u200d':
			output.WriteRune(character)
		default:
			quoted := strconv.QuoteRune(character)
			output.WriteString(quoted[1 : len(quoted)-1])
		}
		value = value[size:]
	}
	return output.String()
}

// Style adds only SGR styling to already-safe text, closing it at each line.
func Style(value string, role Role, rich bool) string {
	if !rich || role == Normal || value == "" {
		return value
	}
	var code string
	switch role {
	case Normal:
		return value
	case Strong:
		code = "1"
	case Muted:
		code = "2"
	case Success:
		code = "32"
	case Warning:
		code = "33"
	case Failure:
		code = "31"
	}
	lines := strings.Split(value, "\n")
	for index, line := range lines {
		if line != "" {
			lines[index] = "\x1b[" + code + "m" + line + "\x1b[0m"
		}
	}
	return strings.Join(lines, "\n")
}

func (printer *Printer) write(value string) {
	if printer.err != nil {
		return
	}
	n, err := io.WriteString(printer.writer, value)
	if err == nil && n != len(value) {
		err = io.ErrShortWrite
	}
	if err != nil {
		printer.err = fmt.Errorf("write text report: %w", err)
	}
}

// Blank separates report blocks.
func (printer *Printer) Blank() { printer.write("\n") }

// Line writes a safe, unwrapped event or value.
func (printer *Printer) Line(value string, role Role) {
	printer.write(Style(Escape(value), role, printer.options.Rich) + "\n")
}

// Heading writes a report title, leaving wrapping to the terminal.
func (printer *Printer) Heading(value string) {
	printer.Line(value, Strong)
}

// Section separates and names a group of fields or records.
func (printer *Printer) Section(value string) {
	printer.Blank()
	printer.Line("  "+value, Strong)
}

// Fields aligns labels within a group, preserving each value on one logical line.
func (printer *Printer) Fields(fields []Field) {
	labelWidth := 0
	for _, field := range fields {
		labelWidth = max(labelWidth, displaywidth.String(Escape(field.Label)))
	}
	indent := "    "
	if printer.options.Width < 40 {
		indent = "  "
	}
	for _, field := range fields {
		label, value := Escape(field.Label), Escape(field.Value)
		padding := strings.Repeat(" ", labelWidth-displaywidth.String(label)+2)
		printer.write(indent + Style(label, Muted, printer.options.Rich) + padding + Style(value, field.Role, printer.options.Rich) + "\n")
	}
}

func tableWidths(headers []string, rows [][]string) ([]int, int) {
	widths := make([]int, len(headers))
	for index, header := range headers {
		widths[index] = displaywidth.String(Escape(header))
	}
	for _, row := range rows {
		for index, value := range row {
			if index < len(widths) {
				widths[index] = max(widths[index], displaywidth.String(Escape(value)))
			}
		}
	}
	total := 4 + max(0, len(headers)-1)*2
	for _, width := range widths {
		total += width
	}
	return widths, total
}

// TableFits reports whether all cells fit without wrapping or truncation.
func (printer *Printer) TableFits(headers []string, rows [][]string) bool {
	_, total := tableWidths(headers, rows)
	return total <= printer.options.Width
}

// Table writes aligned rows or labeled records when the table cannot fit.
func (printer *Printer) Table(headers []string, rows [][]string) {
	widths, total := tableWidths(headers, rows)
	if total > printer.options.Width {
		for index, row := range rows {
			printer.Section("Record " + strconv.Itoa(index+1))
			fields := make([]Field, 0, len(headers))
			for column, header := range headers {
				if column < len(row) {
					fields = append(fields, Field{Label: header, Value: row[column]})
				}
			}
			printer.Fields(fields)
		}
		return
	}
	printer.tableRow(headers, widths, Strong)
	for _, row := range rows {
		printer.tableRow(row, widths, Normal)
	}
}

func (printer *Printer) tableRow(row []string, widths []int, role Role) {
	printer.write("    ")
	for index, value := range row {
		if index >= len(widths) {
			break
		}
		safe := Escape(value)
		printer.write(Style(safe, role, printer.options.Rich))
		if index < len(widths)-1 {
			printer.write(strings.Repeat(" ", widths[index]-displaywidth.String(safe)+2))
		}
	}
	printer.Blank()
}
