package password_test

import (
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

const promptTermiosRequest = unix.TIOCGETA

// openPromptPTY returns a pseudo-terminal master and slave; the caller closes both.
// FreeBSD's pts(4) slaves need no unlock.
func openPromptPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master := openPromptPTMX(t)
	return master, openPromptPTYSlave(t, master, "/dev/pts/"+strconv.Itoa(promptPTYNumber(t, master)))
}
