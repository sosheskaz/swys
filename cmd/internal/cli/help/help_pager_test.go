package help

import (
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePagerQuotedArguments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		configuration string
		want          []string
	}{
		{name: "arguments", configuration: "less -R", want: []string{"less", "-R"}},
		{
			name:          "quoted-and-escaped",
			configuration: `'/path with spaces/pager' "two words" plain\ value ''`,
			want:          []string{"/path with spaces/pager", "two words", "plain value", ""},
		},
		{
			name:          "windows-paths",
			configuration: `"C:\Program Files\pager.exe" "--theme=C:\Themes\dark"`,
			want:          []string{`C:\Program Files\pager.exe`, `--theme=C:\Themes\dark`},
		},
		{
			name:          "escaped-quote-in-double-quotes",
			configuration: `pager "say \"hello\""`,
			want:          []string{"pager", `say "hello"`},
		},
		{
			name:          "non-utf8-bytes",
			configuration: "/opt/pager-\xa7 '\xa7 single' \"\xa7 double\" escaped\\\xa7 \"kept\\\xa7\"",
			want:          []string{"/opt/pager-\xa7", "\xa7 single", "\xa7 double", "escaped\xa7", "kept\\\xa7"},
		},
		{
			name:          "non-utf8-bytes-joined-across-quotes",
			configuration: "pager-\xdb\"\"\xad",
			want:          []string{"pager-\xdb\xad"},
		},
		{
			// Go decodes a Windows environment value holding an unpaired
			// surrogate as WTF-8, and exec encodes it back only if argv keeps it.
			name:          "wtf8-unpaired-surrogate",
			configuration: "'C:\\pager-\xed\xa0\x80.exe'",
			want:          []string{"C:\\pager-\xed\xa0\x80.exe"},
		},
		{
			name:          "replacement-character",
			configuration: "pager-�",
			want:          []string{"pager-�"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := parsePager(test.configuration)
			require.NoError(t, err)
			assert.Equal(t, test.want, got, "parsePager(%q)", test.configuration)
		})
	}
}

func TestParsePagerRejectsMalformedConfiguration(t *testing.T) {
	t.Parallel()

	for _, configuration := range []string{"", "   ", "'unterminated", `"unterminated`, "pager\\"} {
		t.Run(fmt.Sprintf("%q", configuration), func(t *testing.T) {
			t.Parallel()
			_, err := parsePager(configuration)
			assert.ErrorIs(t, err, ErrInvalidPager)
		})
	}
}

func TestTerminateOnReceiveEndsThePagerOnASignal(t *testing.T) {
	t.Parallel()
	received := make(chan os.Signal, 1)
	terminated := make(chan struct{})
	stop := terminateOnReceive(received, func() { close(terminated) })
	defer stop()

	received <- syscall.SIGTERM

	select {
	case <-terminated:
	case <-time.After(10 * time.Second):
		t.Fatal("the pager was not terminated")
	}
}

func TestTerminateOnReceiveStaysQuietOnceStopped(t *testing.T) {
	t.Parallel()
	received := make(chan os.Signal, 1)
	terminated := make(chan struct{})
	stop := terminateOnReceive(received, func() { close(terminated) })

	stop()
	received <- syscall.SIGTERM

	select {
	case <-terminated:
		t.Fatal("a stopped subscription still terminated the pager")
	case <-time.After(50 * time.Millisecond):
	}
}
