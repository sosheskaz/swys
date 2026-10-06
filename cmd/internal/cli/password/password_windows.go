//go:build windows

package password

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/sosheskaz/swys/cmd/internal/cli/interrupt"
)

var (
	readConsoleInputW         = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadConsoleInputW")
	errUnexpectedConsoleWait  = errors.New("unexpected console wait state")
	errWindowsPasswordTooLong = fmt.Errorf("password exceeds %d bytes", MaxBytes)
	errPasswordConfirmation   = errors.New("password confirmation does not match")
	errPasswordPIDRange       = errors.New("password command PID out of range")
)

// closeWindowsHandle makes a best-effort release when no error return channel remains.
func closeWindowsHandle(handle windows.Handle) {
	if err := windows.CloseHandle(handle); err != nil {
		return
	}
}

func openTerminal() (*os.File, error) {
	input, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open console input: %w", err)
	}
	return input, nil
}

func shellCommand(script string) (string, []string) {
	return "cmd.exe", []string{"/D", "/S", "/C", script}
}

func configureProcess(process *exec.Cmd) (func(context.Context, *exec.Cmd) (func() processWatchResult, error), func() error, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("create password command job: %w", err)
	}
	var once sync.Once
	closeJob := func() { once.Do(func() { closeWindowsHandle(job) }) }
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err != nil {
		closeJob()
		return nil, nil, fmt.Errorf("configure password command job: %w", err)
	}
	// cmd.exe parses the remainder after /S /C as a shell script. Give it
	// one outer quote pair so inner quotes survive cmd's /S processing.
	script := process.Args[len(process.Args)-1]
	process.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.CREATE_SUSPENDED,
		CmdLine:       syscall.EscapeArg(process.Path) + ` /D /S /C "` + script + `"`,
	}
	return func(ctx context.Context, child *exec.Cmd) (func() processWatchResult, error) {
		if child.Process.Pid < 0 || uint64(child.Process.Pid) > math.MaxUint32 {
			closeJob()
			return nil, fmt.Errorf("%w: %d", errPasswordPIDRange, child.Process.Pid)
		}
		pid := uint32(child.Process.Pid)
		handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
		if err != nil {
			closeJob()
			return nil, fmt.Errorf("open password command process: %w", err)
		}
		err = windows.AssignProcessToJobObject(job, handle)
		closeWindowsHandle(handle)
		if err != nil {
			closeJob()
			return nil, fmt.Errorf("assign password command job: %w", err)
		}
		done := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { defer close(done); closeJob() })
		cleanup := func() processWatchResult {
			stopped := stop()
			if !stopped {
				<-done
			}
			closeJob()
			return processWatchResult{}
		}
		if err := resumePrimaryThread(pid); err != nil {
			cleanup()
			return nil, err
		}
		return cleanup, nil
	}, func() error { closeJob(); return nil }, nil
}

func resumePrimaryThread(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("snapshot password command threads: %w", err)
	}
	defer closeWindowsHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	if err := windows.Thread32First(snapshot, &entry); err != nil {
		return fmt.Errorf("find password command thread: %w", err)
	}
	for {
		if entry.OwnerProcessID == pid {
			thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if err != nil {
				return fmt.Errorf("open password command thread: %w", err)
			}
			_, err = windows.ResumeThread(thread)
			closeWindowsHandle(thread)
			if err != nil {
				return fmt.Errorf("resume password command: %w", err)
			}
			return nil
		}
		if err := windows.Thread32Next(snapshot, &entry); err != nil {
			return fmt.Errorf("find password command primary thread: %w", err)
		}
	}
}

func killProcessGroup(*exec.Cmd) {}

type consoleInputRecord struct {
	eventType       uint16
	_               uint16
	keyDown         uint32
	repeat          uint16
	virtualKey      uint16
	scanCode        uint16
	char            uint16
	controlKeyState uint32
}

func readConsoleRecord(handle windows.Handle) (consoleInputRecord, error) {
	var record consoleInputRecord
	var n uint32
	result, _, err := readConsoleInputW.Call(uintptr(handle), uintptr(unsafe.Pointer(&record)), 1, uintptr(unsafe.Pointer(&n)))
	if result == 0 {
		return record, fmt.Errorf("read console input: %w", err)
	}
	if n != 1 {
		return record, io.ErrNoProgress
	}
	return record, nil
}

func readHiddenLine(ctx context.Context, input, output *os.File, label string) ([]byte, error) {
	if _, err := output.WriteString(label); err != nil {
		return nil, fmt.Errorf("write password prompt: %w", err)
	}
	handle := windows.Handle(input.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return nil, fmt.Errorf("get console input mode: %w", err)
	}
	if err := windows.SetConsoleMode(handle, mode&^(windows.ENABLE_ECHO_INPUT|windows.ENABLE_LINE_INPUT)); err != nil {
		return nil, fmt.Errorf("set hidden console input mode: %w", err)
	}
	value, readErr := readHiddenConsole(ctx, handle)
	if restoreErr := windows.SetConsoleMode(handle, mode); restoreErr != nil {
		readErr = errors.Join(readErr, fmt.Errorf("restore console input mode: %w", restoreErr))
	}
	if _, writeErr := output.WriteString("\r\n"); writeErr != nil {
		readErr = errors.Join(readErr, fmt.Errorf("finish password prompt: %w", writeErr))
	}
	if readErr != nil {
		return nil, readErr
	}
	return value, nil
}

func readHiddenConsole(ctx context.Context, handle windows.Handle) ([]byte, error) {
	units := make([]uint16, 0, 64)
	for {
		record, err := nextConsoleKey(ctx, handle)
		if err != nil {
			return nil, err
		}
		for range max(int(record.repeat), 1) {
			var done bool
			units, done, err = applyConsoleKey(units, record.char)
			if err != nil {
				return nil, err
			}
			if done {
				value := []byte(string(utf16.Decode(units)))
				return value, Validate(value)
			}
		}
	}
}

func nextConsoleKey(ctx context.Context, handle windows.Handle) (consoleInputRecord, error) {
	for {
		if err := ctx.Err(); err != nil {
			return consoleInputRecord{}, fmt.Errorf("password prompt interrupted: %w", err)
		}
		state, err := windows.WaitForSingleObject(handle, 50)
		if err != nil {
			return consoleInputRecord{}, fmt.Errorf("wait for console input: %w", err)
		}
		if state == uint32(windows.WAIT_TIMEOUT) {
			continue
		}
		if state != windows.WAIT_OBJECT_0 {
			return consoleInputRecord{}, fmt.Errorf("%w %d", errUnexpectedConsoleWait, state)
		}
		record, err := readConsoleRecord(handle)
		if err != nil {
			return consoleInputRecord{}, err
		}
		if record.eventType == 1 && record.keyDown != 0 && record.char != 0 {
			return record, nil
		}
	}
}

func applyConsoleKey(units []uint16, key uint16) ([]uint16, bool, error) {
	switch key {
	case '\r':
		return units, true, nil
	case 3:
		return nil, false, interrupt.NewError(os.Interrupt)
	case '\b':
		if len(units) == 0 {
			return units, false, nil
		}
		units = units[:len(units)-1]
		if len(units) > 0 && units[len(units)-1] >= 0xD800 && units[len(units)-1] <= 0xDBFF {
			units = units[:len(units)-1]
		}
		return units, false, nil
	default:
		if len(units) >= MaxBytes {
			return nil, false, errWindowsPasswordTooLong
		}
		return append(units, key), false, nil
	}
}

// Prompt reads hidden password bytes from the controlling console and checks cancellation while waiting.
func Prompt(ctx context.Context, confirm bool) ([]byte, error) {
	input, err := openTerminal()
	if err != nil {
		return nil, fmt.Errorf("password prompt requires a controlling terminal: %w", err)
	}
	defer func() {
		if err := input.Close(); err != nil {
			return
		}
	}()
	output, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open password terminal output: %w", err)
	}
	defer func() {
		if err := output.Close(); err != nil {
			return
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("password prompt interrupted: %w", err)
	}
	value, err := readHiddenLine(ctx, input, output, "Password: ")
	if err != nil {
		return nil, err
	}
	if confirm {
		again, err := readHiddenLine(ctx, input, output, "Confirm password: ")
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(value, again) {
			return nil, errPasswordConfirmation
		}
	}
	return value, nil
}
