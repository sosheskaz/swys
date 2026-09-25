package commandio

import (
	"io"

	"golang.org/x/term"
)

// InputIsTerminal reports whether input is a terminal stream.
func InputIsTerminal(input io.Reader) bool {
	file, ok := input.(interface{ Fd() uintptr })
	return ok && term.IsTerminal(int(file.Fd()))
}
