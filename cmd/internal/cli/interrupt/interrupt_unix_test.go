//go:build unix

package interrupt

import (
	"os"
	"slices"
	"syscall"
	"testing"
)

// SIGPIPE must stay out of the set: notifying it would turn a closed stdout
// from "end the process" into write errors and break "npc ... | head".
func TestInterruptSignalsLeaveSIGPIPEAndSIGQUITAlone(t *testing.T) {
	t.Parallel()
	want := []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
	if got := interruptSignals(); !slices.Equal(got, want) {
		t.Fatalf("interrupt signals = %v, want %v", got, want)
	}
}
