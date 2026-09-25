//go:build unix

package interrupt

import (
	"io"
	"testing"
)

func StallPipeForTest(t *testing.T) io.Writer {
	t.Helper()
	return stallPipe(t)
}
