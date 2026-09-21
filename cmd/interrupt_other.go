//go:build !unix

package cmd

import "os"

// interruptSignals end a run gracefully; os.Interrupt is the only portable one.
func interruptSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
