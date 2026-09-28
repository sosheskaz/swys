//go:build darwin

package password_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/sosheskaz-systems/npc/cmd"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/interrupt"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/password"
)

//nolint:paralleltest,nestif // the helper process re-enters this test using its own controlling PTY
func TestPromptRestoresTerminalAfterInput(t *testing.T) {
	if source := os.Getenv("NPC_PROMPT_HELPER"); source != "" {
		var value []byte
		var err error
		if strings.HasPrefix(source, "command") {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			script := `printf 'Supplier: ' >/dev/tty; IFS= read -r p </dev/tty; printf '%s\n' "$p"`
			switch source {
			case "command_noecho_interrupt":
				script = `stty -echo </dev/tty; ` + script
			case "command_suspend":
				script = `printf 'Supplier: %d\n' "$$" >/dev/tty; IFS= read -r p </dev/tty; printf '%s\n' "$p"`
			case "command_suspend_external", "command_suspend_root":
				script = `printf 'Supplier: %d\n' "$$" >/dev/tty; cat </dev/tty >/dev/null`
			}
			if source == "command_suspend_root" {
				root := cmd.NewCommand()
				root.SetArgs([]string{"aes", "encrypt", "payload", "--password-command", script, "--output", os.Getenv("NPC_PROMPT_OUTPUT")})
				root.SetOut(io.Discard)
				root.SetErr(io.Discard)
				err = root.ExecuteContext(ctx)
			} else {
				value, err = password.Command(ctx, script, io.Discard)
			}
			cancel()
		} else {
			value, err = password.Prompt(t.Context(), false)
		}
		accepted := err == nil && bytes.Equal(value, []byte(os.Getenv("NPC_PROMPT_EXPECT")))
		if source == "command_interrupt" || source == "command_noecho_interrupt" {
			accepted = interrupt.ExitCode(err) == 130
		} else if strings.HasPrefix(source, "command_suspend") {
			accepted = err != nil && strings.Contains(err.Error(), "password command suspended") && !errors.Is(err, context.DeadlineExceeded)
		}
		if !accepted {
			_, _ = fmt.Fprintf(os.Stderr, "prompt error=%v value length=%d\n", err, len(value))
			os.Exit(2)
		}
		ready := os.NewFile(3, "ready")
		release := os.NewFile(4, "release")
		terminal, err := os.Open("/dev/tty")
		if err != nil {
			os.Exit(3)
		}
		foreground, err := unix.IoctlGetInt(int(terminal.Fd()), unix.TIOCGPGRP)
		if err := terminal.Close(); err != nil {
			os.Exit(3)
		}
		if err != nil {
			os.Exit(3)
		}
		var group [4]byte
		binary.LittleEndian.PutUint32(group[:], uint32(foreground))
		if _, err := ready.Write(group[:]); err != nil {
			os.Exit(3)
		}
		var signal [1]byte
		if _, err := release.Read(signal[:]); err != nil {
			os.Exit(4)
		}
		os.Exit(0)
	}
	runPromptFixture(t, "synthetic\n", "synthetic", "prompt")
}

//nolint:paralleltest // the helper process re-enters the fixture using a controlling PTY
func TestPromptBackspaceRemovesWholeUTF8Rune(t *testing.T) {
	runPromptFixture(t, "é\x7fab\n", "ab", "prompt")
}

//nolint:paralleltest // the helper process re-enters the fixture using a controlling PTY
func TestCommandReadsControllingTerminalAndRestoresForeground(t *testing.T) {
	runPromptFixture(t, "synthetic\n", "synthetic", "command")
}

//nolint:paralleltest // the helper process re-enters the fixture using a controlling PTY
func TestCommandInterruptRestoresForeground(t *testing.T) {
	runPromptFixture(t, "\x03", "", "command_interrupt")
}

//nolint:paralleltest // the helper process re-enters the fixture using a controlling PTY
func TestCommandInterruptRestoresTerminalMode(t *testing.T) {
	runPromptFixture(t, "\x03", "", "command_noecho_interrupt")
}

//nolint:paralleltest // the helper process re-enters the fixture using a controlling PTY
func TestCommandSuspensionCancelsAndRestoresTerminal(t *testing.T) {
	runPromptFixture(t, "\x1a", "", "command_suspend")
}

//nolint:paralleltest // the helper process re-enters the fixture using a controlling PTY
func TestCommandExternalReaderSuspensionCancels(t *testing.T) {
	runPromptFixture(t, "\x1a", "", "command_suspend_external")
}

//nolint:paralleltest // the helper process re-enters the fixture using a controlling PTY
func TestCommandSuspensionKeepsAESOutput(t *testing.T) {
	runPromptFixture(t, "\x1a", "", "command_suspend_root")
}

func runPromptFixture(t *testing.T, input, expected, source string) {
	t.Helper()
	fixtureCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_CLOEXEC, 0)
	require.NoError(t, err)
	stopClose := context.AfterFunc(fixtureCtx, func() { _ = master.Close() }) //nolint:errcheck // timed-out fixture closes its blocked PTY read
	defer stopClose()
	defer func() {
		err := master.Close()
		if !errors.Is(err, os.ErrClosed) {
			require.NoError(t, err)
		}
	}()
	name := make([]byte, 128)
	for _, request := range []uintptr{syscall.TIOCPTYGNAME, syscall.TIOCPTYGRANT, syscall.TIOCPTYUNLK} {
		argument := uintptr(0)
		if request == syscall.TIOCPTYGNAME {
			argument = uintptr(unsafe.Pointer(&name[0]))
		}
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), request, argument)
		require.Zero(t, errno)
	}
	end := bytes.IndexByte(name, 0)
	require.Positive(t, end)
	slave, err := os.OpenFile(string(name[:end]), os.O_RDWR|syscall.O_NOCTTY, 0)
	require.NoError(t, err)
	defer func() {
		err := slave.Close()
		if !errors.Is(err, os.ErrClosed) {
			require.NoError(t, err)
		}
	}()
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TIOCGETA)
	require.NoError(t, err)
	output := filepath.Join(t.TempDir(), "cipher")
	if source == "command_suspend_root" {
		require.NoError(t, os.WriteFile(output, []byte("sentinel"), 0o600))
	}
	if source == "command_noecho_interrupt" {
		require.NotZero(t, before.Lflag&unix.ECHO)
	}
	helper := exec.CommandContext(fixtureCtx, os.Args[0], "-test.run=^TestPromptRestoresTerminalAfterInput$")
	readyRead, readyWrite, err := os.Pipe()
	require.NoError(t, err)
	defer closeTestFile(t, readyRead)
	defer closeTestFile(t, readyWrite)
	releaseRead, releaseWrite, err := os.Pipe()
	require.NoError(t, err)
	defer closeTestFile(t, releaseRead)
	defer closeTestFile(t, releaseWrite)
	helper.ExtraFiles = []*os.File{readyWrite, releaseRead}
	helper.Env = append(os.Environ(), "NPC_PROMPT_HELPER="+source, "NPC_PROMPT_EXPECT="+expected, "NPC_PROMPT_OUTPUT="+output)
	helper.Stdin = slave
	helper.Stdout = slave
	helper.Stderr = os.Stderr
	helper.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	require.NoError(t, helper.Start())
	require.NoError(t, readyWrite.Close())
	require.NoError(t, releaseRead.Close())
	prompt := make([]byte, 128)
	marker := "Password: "
	if strings.HasPrefix(source, "command") {
		marker = "Supplier: "
	}
	count := 0
	for {
		var read int
		read, err = master.Read(prompt[count:])
		require.NoError(t, err)
		count += read
		if strings.HasPrefix(source, "command_suspend") {
			if bytes.Contains(prompt[:count], []byte{'\n'}) {
				break
			}
		} else if bytes.Contains(prompt[:count], []byte(marker)) {
			break
		}
		require.Less(t, count, len(prompt), "supplier prompt exceeded fixture buffer")
	}
	require.Contains(t, string(prompt[:count]), marker)
	var supplierPID int
	if strings.HasPrefix(source, "command_suspend") {
		fields := strings.Fields(string(prompt[:count]))
		require.Len(t, fields, 2)
		supplierPID, err = strconv.Atoi(fields[1])
		require.NoError(t, err)
	}
	if source == "command_noecho_interrupt" {
		during, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TIOCGETA)
		require.NoError(t, err)
		require.Zero(t, during.Lflag&unix.ECHO)
	}
	_, err = master.WriteString(input)
	require.NoError(t, err)
	drained := make(chan error, 1)
	go func() { _, copyErr := io.Copy(io.Discard, master); drained <- copyErr }()
	var ready [4]byte
	_, err = io.ReadFull(readyRead, ready[:])
	require.NoError(t, err)
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TIOCGETA)
	require.NoError(t, err)
	require.Equal(t, helper.Process.Pid, int(binary.LittleEndian.Uint32(ready[:])))
	require.Equal(t, before.Lflag&^unix.PENDIN, after.Lflag&^unix.PENDIN)
	require.Equal(t, before.Iflag, after.Iflag)
	require.Equal(t, before.Oflag, after.Oflag)
	require.Equal(t, before.Cflag, after.Cflag)
	if strings.HasPrefix(source, "command_suspend") {
		require.ErrorIs(t, unix.Kill(-supplierPID, 0), unix.ESRCH)
	}
	if source == "command_suspend_root" {
		contents, err := os.ReadFile(output)
		require.NoError(t, err)
		require.Equal(t, []byte("sentinel"), contents)
	}
	_, err = releaseWrite.Write([]byte{1})
	require.NoError(t, err)
	waited := make(chan error, 1)
	go func() { waited <- helper.Wait() }()
	select {
	case err := <-waited:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		_ = master.Close()        //nolint:errcheck // release a blocked PTY reader on test failure
		_ = slave.Close()         //nolint:errcheck // release a blocked PTY reader on test failure
		_ = helper.Process.Kill() //nolint:errcheck // helper may already have exited
		select {
		case <-waited:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("password prompt helper did not finish")
	}
	require.NoError(t, master.Close())
	copyErr := <-drained
	if !errors.Is(copyErr, os.ErrClosed) {
		require.NoError(t, copyErr)
	}
}

func closeTestFile(t *testing.T, file *os.File) {
	t.Helper()
	err := file.Close()
	if !errors.Is(err, os.ErrClosed) {
		require.NoError(t, err)
	}
}
