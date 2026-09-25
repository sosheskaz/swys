//go:build unix

package help

import (
	"os"
	"syscall"
)

func guidePagerInterruptSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGQUIT}
}

func guidePagerTerminationSignals() []os.Signal {
	return []os.Signal{syscall.SIGTERM, syscall.SIGHUP}
}
