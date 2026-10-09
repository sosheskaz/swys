package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/cmd/internal/testcmd"
)

func TestSkillPreservesDocumentAcrossStylesWithoutReadingInput(t *testing.T) {
	t.Parallel()
	want, _, err := executeRootStreams(t, "skill")
	require.NoError(t, err)
	for _, style := range []string{"auto", "plain", "rich"} {
		t.Run(style, func(t *testing.T) {
			t.Parallel()
			output, stderr, err := testcmd.RunStreams(t, NewCommand(), guidePanicReader{}, "skill", "--style", style)
			require.NoError(t, err)
			assert.Equal(t, want, string(output))
			assert.Empty(t, stderr)
			assert.NotContains(t, string(output), "\x1b")
		})
	}
}

func TestSkillRejectsInvalidArgumentsBeforeOutputMutation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{name: "surplus argument", args: []string{"extra"}},
		{name: "payload input", args: []string{"--input", "-"}},
		{name: "input file", args: []string{"--input", "missing"}},
		{name: "format", args: []string{"--format", "json"}},
		{name: "encoding", args: []string{"--encoding", "base64"}},
		{name: "mode", args: []string{"--mode", "invalid"}},
		{name: "style", args: []string{"--style", "invalid"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "existing")
			require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
			args := append([]string{"skill", "-o", path}, test.args...)
			stdout, stderr, err := testcmd.RunStreams(t, NewCommand(), guidePanicReader{}, args...)
			require.Error(t, err)
			assert.Empty(t, stdout)
			assert.Empty(t, stderr)
			contents, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "preserve", string(contents))
		})
	}
}

func TestSkillPropagatesWriterErrors(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		writer io.Writer
		want   error
		name   string
	}{
		{name: "write failure", writer: guideFailingWriter{err: errGuideWriter}, want: errGuideWriter},
		{name: "short write", writer: skillShortWriter{}, want: io.ErrShortWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			err := testcmd.Run(t, NewCommand(), guidePanicReader{}, test.writer, &stderr, "skill")
			require.ErrorIs(t, err, test.want)
			assert.Empty(t, stderr.String())
		})
	}
}

type skillShortWriter struct{}

func (skillShortWriter) Write(data []byte) (int, error) { return len(data) - 1, nil }
