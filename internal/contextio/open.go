package contextio

import (
	"context"
	"fmt"
	"os"
)

// OpenFile stops waiting for an open that may block forever, such as a FIFO
// without a peer, once ctx is done. An abandoned open closes its file if it
// ever completes.
func OpenFile(ctx context.Context, open func() (*os.File, error)) (*os.File, error) {
	if ctx == nil || ctx.Done() == nil {
		return open()
	}
	if ctx.Err() != nil {
		return nil, openError(ctx)
	}

	type opened struct {
		file *os.File
		err  error
	}
	result := make(chan opened)
	go func() {
		file, err := open()
		select {
		case result <- opened{file: file, err: err}:
		case <-ctx.Done():
			if file != nil {
				_ = file.Close() //nolint:errcheck // nothing awaits the abandoned open
			}
		}
	}()

	select {
	case done := <-result:
		return done.file, done.err
	case <-ctx.Done():
		return nil, openError(ctx)
	}
}

func openError(ctx context.Context) error {
	return fmt.Errorf("open canceled: %w", context.Cause(ctx))
}
