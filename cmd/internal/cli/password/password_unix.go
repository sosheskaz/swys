//go:build !windows

package password

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/sosheskaz/swys/cmd/internal/cli/interrupt"
)

var (
	errNoControllingTerminal = errors.New("password prompt requires a controlling terminal")
	errPasswordMismatch      = errors.New("password confirmation does not match")
	foregroundMu             sync.Mutex
)

func openTerminal() (*os.File, error) {
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open controlling terminal: %w", err)
	}
	return terminal, nil
}
func shellCommand(script string) (string, []string) { return "/bin/sh", []string{"-c", script} }
func configureProcess(process *exec.Cmd) (func(context.Context, *exec.Cmd) (func() processWatchResult, error), func() error, error) {
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	foregroundMu.Lock()
	terminal, err := openTerminal()
	if err != nil {
		foregroundMu.Unlock()
		return watchUnixProcess, func() error { return nil }, nil //nolint:nilerr // no controlling terminal is valid for a noninteractive supplier
	}
	fd := int(terminal.Fd())
	foreground, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil {
		foregroundMu.Unlock()
		return nil, nil, errors.Join(fmt.Errorf("read password command terminal group: %w", err), terminal.Close())
	}
	parentGroup := unix.Getpgrp()
	if foreground != parentGroup {
		foregroundMu.Unlock()
		if closeErr := terminal.Close(); closeErr != nil {
			return nil, nil, fmt.Errorf("close password command terminal: %w", closeErr)
		}
		return watchUnixProcess, func() error { return nil }, nil
	}
	terminalState, err := term.GetState(fd)
	if err != nil {
		foregroundMu.Unlock()
		return nil, nil, errors.Join(fmt.Errorf("read password command terminal mode: %w", err), terminal.Close())
	}
	process.SysProcAttr.Foreground = true
	process.SysProcAttr.Ctty = fd
	sigchld := make(chan os.Signal, 1)
	signal.Notify(sigchld, syscall.SIGCHLD)
	cleanup := func() error {
		defer foregroundMu.Unlock()
		defer signal.Stop(sigchld)
		if !signal.Ignored(syscall.SIGTTOU) {
			// This CLI owns SIGTTOU while restoring; background ioctl otherwise stops it.
			signal.Ignore(syscall.SIGTTOU)
			defer signal.Reset(syscall.SIGTTOU)
		}
		restoreErr := unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, parentGroup)
		return errors.Join(restoreErr, term.Restore(fd, terminalState), terminal.Close())
	}
	return func(ctx context.Context, process *exec.Cmd) (func() processWatchResult, error) {
		return watchForegroundProcess(ctx, process, sigchld), nil
	}, cleanup, nil
}

func watchUnixProcess(ctx context.Context, process *exec.Cmd) (func() processWatchResult, error) {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		_ = syscall.Kill(-process.Process.Pid, syscall.SIGKILL) //nolint:errcheck // process group may already be gone
	})
	return func() processWatchResult {
		stopped := stop()
		if !stopped {
			<-done
		}
		return processWatchResult{}
	}, nil
}

func watchForegroundProcess(ctx context.Context, process *exec.Cmd, sigchld <-chan os.Signal) func() processWatchResult {
	stop := make(chan struct{})
	done := make(chan struct{})
	var result processWatchResult
	go func() {
		defer close(done)
		for {
			suspended, err := passwordProcessStopped(process.Process.Pid)
			if err != nil {
				result.err = err
				killProcessGroup(process)
				return
			}
			if suspended {
				result.suspended = true
				killProcessGroup(process)
				return
			}
			select {
			case <-stop:
				return
			case <-ctx.Done():
				killProcessGroup(process)
				return
			case <-sigchld:
			}
		}
	}()
	return func() processWatchResult {
		close(stop)
		<-done
		return result
	}
}
func killProcessGroup(process *exec.Cmd) { _ = syscall.Kill(-process.Process.Pid, syscall.SIGKILL) } //nolint:errcheck // process group may already be gone

// Prompt reads a password from the controlling terminal with echo disabled.
//
//nolint:nonamedreturns // named error collects terminal restoration failures
func Prompt(ctx context.Context, confirm bool) (value []byte, err error) {
	terminal, err := openTerminal()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNoControllingTerminal, err)
	}
	defer func() { err = errors.Join(err, terminal.Close()) }()
	fd := int(terminal.Fd())
	if !term.IsTerminal(fd) {
		return nil, errNoControllingTerminal
	}
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("prepare password terminal: %w", err)
	}
	defer func() { err = errors.Join(err, term.Restore(fd, state)) }()
	flags, err := unix.FcntlInt(terminal.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return nil, fmt.Errorf("read password terminal flags: %w", err)
	}
	if err = unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("prepare password terminal read: %w", err)
	}
	defer func() {
		_, restoreErr := unix.FcntlInt(terminal.Fd(), unix.F_SETFL, flags)
		err = errors.Join(err, restoreErr)
	}()
	value, err = readTerminalPassword(ctx, terminal, "Password: ")
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	if !confirm {
		return value, nil
	}
	again, err := readTerminalPassword(ctx, terminal, "Confirm password: ")
	if err != nil {
		return nil, fmt.Errorf("read password confirmation: %w", err)
	}
	if !bytes.Equal(value, again) {
		return nil, errPasswordMismatch
	}
	return value, nil
}

//nolint:gocyclo // terminal byte handling keeps cancellation and editing together
func readTerminalPassword(ctx context.Context, terminal *os.File, label string) ([]byte, error) {
	if _, err := terminal.WriteString(label); err != nil {
		return nil, fmt.Errorf("write password prompt: %w", err)
	}
	defer func() { _, _ = terminal.WriteString("\r\n") }() //nolint:errcheck // prompt teardown restores terminal regardless
	fd := int(terminal.Fd())
	value := make([]byte, 0, 64)
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("password prompt interrupted: %w", err)
		}
		var one [1]byte
		count, err := unix.Read(fd, one[:])
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("password prompt interrupted: %w", ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
			continue
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read password terminal: %w", err)
		}
		if count == 0 {
			return nil, io.EOF
		}
		switch one[0] {
		case '\r', '\n':
			return value, Validate(value)
		case 3:
			return nil, interrupt.NewError(os.Interrupt)
		case 8, 127:
			if len(value) > 0 {
				_, size := utf8.DecodeLastRune(value)
				value = value[:len(value)-size]
			}
		default:
			if len(value) >= MaxBytes {
				return nil, errTooLong
			}
			value = append(value, one[0])
		}
	}
}
