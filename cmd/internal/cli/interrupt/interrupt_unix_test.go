//go:build unix

package interrupt

import (
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

// SIGPIPE must stay out of the set: notifying it would turn a closed stdout
// from "end the process" into write errors and break "swys ... | head".
func TestInterruptSignalsLeaveSIGPIPEAndSIGQUITAlone(t *testing.T) {
	t.Parallel()
	want := []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
	assert.Equal(t, want, interruptSignals())
}
