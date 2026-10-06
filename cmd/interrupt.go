package cmd

import (
	"context"

	"github.com/sosheskaz/swys/cmd/internal/cli/interrupt"
)

// ExitCode maps the error from Execute or ExecuteContext to an exit status.
func ExitCode(err error) int { return interrupt.ExitCode(err) }

// WithInterrupt returns a context canceled by the first terminating signal.
func WithInterrupt(parent context.Context) (context.Context, context.CancelFunc) {
	return interrupt.WithInterrupt(parent)
}
