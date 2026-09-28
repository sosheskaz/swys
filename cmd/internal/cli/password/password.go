// Package password acquires AES passwords without reading payload input.
package password

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/interrupt"
)

// MaxBytes is the maximum accepted password length.
const MaxBytes = 64 * 1024

var (
	errEmpty                = errors.New("password is empty")
	errTooLong              = errors.New("password exceeds 65536 bytes")
	errEmptyEnvironmentName = errors.New("password environment variable name is empty")
	errEnvironmentUnset     = errors.New("password environment variable is unset")
	errEmptyCommand         = errors.New("password command is empty")
	errCommandSuspended     = errors.New("password command suspended")
)

// Validate checks the password byte-length contract.
func Validate(value []byte) error {
	if len(value) == 0 {
		return errEmpty
	}
	if len(value) > MaxBytes {
		return errTooLong
	}
	return nil
}

// Environment reads the exact bytes of an explicitly named variable.
func Environment(name string) ([]byte, error) {
	if name == "" {
		return nil, errEmptyEnvironmentName
	}
	value, ok := os.LookupEnv(name)
	if !ok {
		return nil, fmt.Errorf("%w: %q", errEnvironmentUnset, name)
	}
	result := []byte(value)
	return result, Validate(result)
}

type firstLine struct {
	value    []byte
	complete bool
	tooLong  bool
}

type processWatchResult struct {
	err       error
	suspended bool
}

func (line *firstLine) Write(p []byte) (int, error) {
	n := len(p)
	if line.complete {
		return n, nil
	}
	if at := bytes.IndexByte(p, '\n'); at >= 0 {
		p = p[:at]
		line.complete = true
	}
	if len(line.value)+len(p) > MaxBytes+1 {
		line.tooLong = true
		line.complete = true
		return n, nil
	}
	line.value = append(line.value, p...)
	return n, nil
}

// Command runs a password supplier without connecting it to payload stdin.
//
//nolint:gocyclo // process setup, cancellation, and cleanup require distinct error paths
func Command(ctx context.Context, script string, diagnostics io.Writer) ([]byte, error) {
	if script == "" {
		return nil, errEmptyCommand
	}
	name, args := shellCommand(script)
	process := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed platform shell; explicit user-supplied command
	process.Stdin = nil
	process.Stderr = diagnostics
	process.WaitDelay = time.Second
	var line firstLine
	process.Stdout = &line
	watchProcess, cleanupProcess, prepareErr := configureProcess(process)
	if prepareErr != nil {
		return nil, fmt.Errorf("prepare password command: %w", prepareErr)
	}
	if err := process.Start(); err != nil {
		return nil, errors.Join(fmt.Errorf("start password command: %w", err), cleanupProcess())
	}
	stop, watchErr := watchProcess(ctx, process)
	if watchErr != nil {
		_ = process.Process.Kill() //nolint:errcheck // process may already have exited
		_ = process.Wait()         //nolint:errcheck // report the watcher setup failure
		killProcessGroup(process)
		return nil, errors.Join(fmt.Errorf("manage password command: %w", watchErr), cleanupProcess())
	}
	err := process.Wait()
	watchResult := stop()
	killProcessGroup(process)
	cleanupErr := cleanupProcess()
	if watchResult.err != nil {
		return nil, errors.Join(fmt.Errorf("monitor password command: %w", watchResult.err), cleanupErr)
	}
	if watchResult.suspended {
		return nil, errors.Join(errCommandSuspended, cleanupErr)
	}
	if ctx.Err() != nil {
		return nil, errors.Join(fmt.Errorf("password command interrupted: %w", ctx.Err()), cleanupErr)
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() && status.Signal() == syscall.SIGINT {
				return nil, errors.Join(interrupt.NewError(os.Interrupt), cleanupErr)
			}
		}
		return nil, errors.Join(fmt.Errorf("password command failed: %w", err), cleanupErr)
	}
	if cleanupErr != nil {
		return nil, fmt.Errorf("restore password command terminal: %w", cleanupErr)
	}
	if line.tooLong {
		return nil, errTooLong
	}
	value := line.value
	if line.complete && len(value) > 0 && value[len(value)-1] == '\r' {
		value = value[:len(value)-1]
	}
	return value, Validate(value)
}
