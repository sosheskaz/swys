package testcmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/sosheskaz/swys/cmd/internal/cli/commandio"
)

// AssertWindowsModeRejection checks that a rejected mode preserves the output fixture.
func AssertWindowsModeRejection(t *testing.T, err error, path, contents string) {
	t.Helper()
	if !errors.Is(err, commandio.ErrOutputModeUnsupported) {
		t.Fatalf("error = %v, want unsupported output mode", err)
	}
	if contents == "" {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("output stat = %v, want not-exist", err)
		}
		return
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is a test-managed output fixture
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != contents {
		t.Fatalf("output = %q, want preserved %q", data, contents)
	}
}

// AssertNoRawTerminalControls checks that output is valid UTF-8 and carries
// no raw C0 control other than JSON whitespace, no raw C1 control, and no raw
// Unicode bidirectional formatting control. The list is spelled out
// independently of the production escaper.
func AssertNoRawTerminalControls(t *testing.T, output string) {
	t.Helper()
	var found []string
	for index := 0; index < len(output); {
		character, size := utf8.DecodeRuneInString(output[index:])
		switch {
		case character == utf8.RuneError && size == 1:
			found = append(found, fmt.Sprintf("invalid byte %#x at %d", output[index], index))
		case character < 0x20 && character != '\t' && character != '\n' && character != '\r',
			character >= 0x80 && character <= 0x9f,
			character == 0x061c, character == 0x200e, character == 0x200f,
			character >= 0x202a && character <= 0x202e,
			character >= 0x2066 && character <= 0x2069:
			found = append(found, fmt.Sprintf("%U at %d", character, index))
		}
		index += size
	}
	if len(found) > 0 {
		t.Errorf("raw terminal controls in output: %s\noutput: %q", strings.Join(found, ", "), output)
	}
}
