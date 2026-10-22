package password_test

import (
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

const promptTermiosRequest = unix.TCGETS

// openPromptPTY returns a pseudo-terminal master and slave; the caller closes both.
func openPromptPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master := openPromptPTMX(t)
	if err := controlPromptPTY(master, func(fd int) error { return unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0) }); err != nil {
		_ = master.Close() //nolint:errcheck // the unlock failure is the reported error
		t.Fatalf("unlock pseudo-terminal: %v", err)
	}
	return master, openPromptPTYSlave(t, master, "/dev/pts/"+strconv.Itoa(promptPTYNumber(t, master)))
}
