package commandio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/spf13/cobra"
)

type stateKey struct{}

// ErrPreparedOutputUnavailable identifies missing or consumed prepared bytes.
var ErrPreparedOutputUnavailable = errors.New("prepared command output is unavailable")

type state struct { //nolint:govet // one state per command; this ordering keeps cleanup state together
	prepared []byte
	writer   io.Writer
	cleanup  func() error
	once     sync.Once
	err      error
}

// Install attaches prepared output and cleanup while preserving command context.
func Install(currentContext, originalContext context.Context, command *cobra.Command, prepared []byte, writer io.Writer, cleanup func() error) {
	state := &state{prepared: prepared, writer: writer}
	state.cleanup = func() error {
		defer func() {
			state.prepared = nil
			state.writer = nil
			command.SetContext(originalContext)
		}()
		return cleanup()
	}
	command.SetContext(context.WithValue(currentContext, stateKey{}, state))
}

// Close runs installed command cleanup once and restores its original context.
func Close(command *cobra.Command) error {
	if command == nil {
		return nil
	}
	state, ok := command.Context().Value(stateKey{}).(*state)
	if !ok {
		return nil
	}
	closed := false
	state.once.Do(func() {
		closed = true
		state.err = state.cleanup()
	})
	if closed {
		return state.err
	}
	return nil
}

// Execute runs a command tree and closes configured command streams.
func Execute(root *cobra.Command) error {
	command, runErr := root.ExecuteC()
	if err := errors.Join(runErr, Close(command)); err != nil {
		return fmt.Errorf("execute command: %w", err)
	}
	return nil
}

// TakePrepared consumes output prepared before opening the destination.
func TakePrepared(command *cobra.Command) ([]byte, io.Writer, error) {
	state, ok := command.Context().Value(stateKey{}).(*state)
	if !ok || state.prepared == nil || state.writer == nil {
		return nil, nil, ErrPreparedOutputUnavailable
	}
	prepared, writer := state.prepared, state.writer
	state.prepared, state.writer = nil, nil
	return prepared, writer, nil
}

// AppendCleanup runs an owner cleanup after the shared I/O cleanup.
func AppendCleanup(command *cobra.Command, cleanup func()) bool {
	state, ok := command.Context().Value(stateKey{}).(*state)
	if !ok {
		return false
	}
	previous := state.cleanup
	state.cleanup = func() error {
		defer cleanup()
		return previous()
	}
	return true
}
