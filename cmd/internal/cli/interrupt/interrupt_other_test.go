//go:build !unix

package interrupt

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInterruptSignalsArePortable(t *testing.T) {
	t.Parallel()
	want := []os.Signal{os.Interrupt}
	assert.Equal(t, want, interruptSignals())
}
