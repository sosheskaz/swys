package connectrpc_test

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/internal/connectrpc"
)

func TestJSONLinesBoundaries(t *testing.T) {
	t.Parallel()
	const limit = 128 << 10
	large := `"` + strings.Repeat("x", limit-2) + `"`
	for _, test := range []struct {
		name, input string
		want        []string
		tooLarge    bool
	}{
		{"CRLF, blanks, and final EOF", "\r\n{}\r\n\n9007199254740993", []string{`{}`, `9007199254740993`}, false},
		{"empty stream", "\n \n", nil, false},
		{"beyond Scanner default and exactly at limit", large + "\r\n{}\n", []string{large, "{}"}, false},
		{"oversized line", large + " \n", nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for _, fragmented := range []bool{false, true} {
				var input io.Reader = strings.NewReader(test.input)
				if fragmented {
					input = iotest.OneByteReader(input)
				}
				lines := connectrpc.NewJSONLines(input, limit)
				var got []string
				for {
					value, err := lines.Next()
					if err != nil {
						if test.tooLarge {
							require.ErrorIs(t, err, connectrpc.ErrMessageSize)
						} else {
							require.ErrorIs(t, err, io.EOF)
						}
						break
					}
					got = append(got, string(value))
				}
				assert.Equal(t, test.want, got)
			}
		})
	}
}

func FuzzJSONLinesFragmentation(f *testing.F) {
	f.Add("{}\n[1,2]\r\n\"done\"")
	f.Add(`{"n":9007199254740993}`)
	f.Add("\"\xff\"\n{}")
	f.Add(`"` + strings.Repeat("x", 8190) + "\"\n")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64<<10 {
			return
		}
		whole := connectrpc.NewJSONLines(strings.NewReader(input), 8192)
		fragments := connectrpc.NewJSONLines(iotest.OneByteReader(strings.NewReader(input)), 8192)
		for {
			left, leftErr := whole.Next()
			right, rightErr := fragments.Next()
			require.Equal(t, left, right)
			require.Equal(t, leftErr == nil, rightErr == nil)
			if leftErr != nil {
				assert.Equal(t, errors.Is(leftErr, io.EOF), errors.Is(rightErr, io.EOF))
				return
			}
		}
	})
}
