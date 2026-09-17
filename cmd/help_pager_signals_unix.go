//go:build unix

package cmd

import (
	"os"
	"syscall"
)

func guidePagerInterruptSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGQUIT}
}
