//go:build !unix

package interrupt

import (
	"os"
	"slices"
	"testing"
)

func TestInterruptSignalsArePortable(t *testing.T) {
	t.Parallel()
	want := []os.Signal{os.Interrupt}
	if got := interruptSignals(); !slices.Equal(got, want) {
		t.Fatalf("interrupt signals = %v, want %v", got, want)
	}
}
