//go:build !unix

package help

import "os"

func guidePagerInterruptSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

func guidePagerTerminationSignals() []os.Signal {
	return nil
}
