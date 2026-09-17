//go:build !unix

package cmd

import "os"

func guidePagerInterruptSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
