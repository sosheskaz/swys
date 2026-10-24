package textdisplay_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/clipperhouse/displaywidth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/internal/textdisplay"
)

func TestTableColumnBoundary(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"abcd", "界界", "e\u0301e\u0301e\u0301e\u0301", "👩‍💻👩‍💻"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			for _, width := range []int{14, 15, 16} {
				var output bytes.Buffer
				printer := textdisplay.New(&output, textdisplay.Options{Width: width})
				printer.Table([]string{"Name", "Value"}, [][]string{{value, "1234"}})
				require.NoError(t, printer.Err())
				assert.Contains(t, output.String(), value)
				assert.Equal(t, width < 15, strings.Contains(output.String(), "Record 1"), "width=%d", width)
				if width >= 15 {
					for _, line := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
						assert.LessOrEqual(t, displaywidth.String(line), width)
					}
				}
			}
		})
	}
}

func TestFieldsPreserveLongTokensAndEscapeControls(t *testing.T) {
	t.Parallel()
	for _, rich := range []bool{false, true} {
		var output bytes.Buffer
		printer := textdisplay.New(&output, textdisplay.Options{Width: 20, Rich: rich})
		token := strings.Repeat("A", 100) + "  preserve spaces and terminal wrapping"
		printer.Fields([]textdisplay.Field{{Label: "Fingerprint", Value: token}, {Label: "Name", Value: "hello\x1b[2J\nworld\xff"}})
		require.NoError(t, printer.Err())
		assert.Contains(t, output.String(), token)
		assert.Contains(t, output.String(), `hello\x1b[2J\nworld\xff`)
		assert.NotContains(t, output.String(), "\x1b[2J")
	}
}

func TestEscapeJSONControls(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, input, want string }{
		{
			name:  "range boundaries",
			input: "\"\u007f\u0080\u009f\u00a0\u061b\u061c\u200d\u200e\u200f\u2010\u2029\u202a\u202e\u202f\u2066\u2069\u206a\"",
			want:  "\"\u007f\\u0080\\u009f\u00a0\u061b\\u061c\u200d\\u200e\\u200f\u2010\u2029\\u202a\\u202e\u202f\\u2066\\u2069\u206a\"",
		},
		{
			name:  "names and escaped backslashes",
			input: "{\"\u202ename\": [\"\\\\\u009b31m\", \"\\u009b\"]}",
			want:  "{\"\\u202ename\": [\"\\\\\\u009b31m\", \"\\u009b\"]}",
		},
		{name: "invalid UTF-8 is copied", input: "\"\x9b\xc2\"", want: "\"\x9b\xc2\""},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := textdisplay.EscapeJSONControls([]byte(test.input))
			assert.Equal(t, test.want, string(got))
			if !json.Valid([]byte(test.input)) {
				return
			}
			var want, decoded any
			require.NoError(t, json.Unmarshal([]byte(test.input), &want))
			require.NoError(t, json.Unmarshal(got, &decoded))
			assert.Equal(t, want, decoded)
		})
	}
}

var errWriter = errors.New("writer failed")

type failingWriter struct{ calls int }

func (writer *failingWriter) Write([]byte) (int, error) {
	writer.calls++
	return 0, errWriter
}

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 0, nil }

func TestPrinterStopsAfterFailure(t *testing.T) {
	t.Parallel()
	writer := &failingWriter{}
	printer := textdisplay.New(writer, textdisplay.Options{})
	printer.Heading("Title")
	printer.Section("Fields")
	printer.Fields([]textdisplay.Field{{Label: "Name", Value: "value"}})
	require.ErrorIs(t, printer.Err(), errWriter)
	assert.Equal(t, 1, writer.calls)
	printer = textdisplay.New(shortWriter{}, textdisplay.Options{})
	printer.Line("value", textdisplay.Normal)
	require.ErrorIs(t, printer.Err(), io.ErrShortWrite)
}
