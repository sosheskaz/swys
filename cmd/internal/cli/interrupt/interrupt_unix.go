//go:build unix

package interrupt

import (
	"os"
	"syscall"
)

// interruptSignals end a run gracefully; SIGQUIT stays with the runtime for goroutine dumps.
func interruptSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
}
