package artifact

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errArtifactTestReadFailure = errors.New("test read failure")

func TestReadArtifactBoundaries(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, 1, 31, 32, 33, 4096} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()
			input := bytes.NewReader(bytes.Repeat([]byte{'x'}, size))
			data, err := Read(input, 32)
			if size > 32 {
				require.ErrorIs(t, err, ErrTooLarge)
				assert.Nil(t, data)
				assert.Equal(t, size-33, input.Len(), "read beyond overflow probe")
				return
			}
			require.NoError(t, err)
			assert.Len(t, data, size)
		})
	}
}

func TestReadArtifactPreservesIOErrors(t *testing.T) {
	t.Parallel()
	input := io.MultiReader(strings.NewReader("partial"), artifactFailingReader{err: errArtifactTestReadFailure})
	data, err := Read(input, 32)
	require.ErrorIs(t, err, errArtifactTestReadFailure)
	assert.Nil(t, data)
	_, err = ReadFile(filepath.Join(t.TempDir(), "missing"), 32)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = ReadFile(t.TempDir(), 32)
	require.Error(t, err, "directory read succeeded")
}

type artifactFailingReader struct{ err error }

func (reader artifactFailingReader) Read([]byte) (int, error) { return 0, reader.err }

func BenchmarkReadArtifact(b *testing.B) {
	for _, size := range []int{4096, 1 << 20, 16 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			data := bytes.Repeat([]byte{'x'}, size)
			b.ReportAllocs()
			for b.Loop() {
				_, err := Read(bytes.NewReader(data), MaxKeyBytes)
				if err != nil && !errors.Is(err, ErrTooLarge) {
					b.Fatal(err)
				}
			}
		})
	}
}
