package contextio

import (
	"context"
	"fmt"
	"io"
	"os"
)

// readChunk matches the buffer io.Copy allocates.
const readChunk = 32 * 1024

// NewReader returns input unchanged when ctx can never be canceled. Otherwise,
// serial reads fail with the cancellation cause once ctx is done. Regular files
// only check ctx per read; other sources may block forever, so they are read on
// a helper goroutine that never reads ahead of the caller.
//
// A caller that stops reading before EOF should cancel its scoped context. A
// blocked underlying read may outlive cancellation, and NewReader never closes
// the borrowed input.
func NewReader(ctx context.Context, input io.Reader) io.Reader {
	if ctx == nil || ctx.Done() == nil {
		return input
	}
	if file, ok := input.(*os.File); ok && isRegularFile(file) {
		return &checkedReader{ctx: ctx, input: input}
	}
	return &blockingReader{ctx: ctx, input: input}
}

func isRegularFile(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode().IsRegular()
}

func readError(ctx context.Context) error {
	return fmt.Errorf("read canceled: %w", context.Cause(ctx))
}

type checkedReader struct {
	ctx   context.Context //nolint:containedctx // Read has no context parameter
	input io.Reader
}

func (reader *checkedReader) Read(buffer []byte) (int, error) {
	if reader.ctx.Err() != nil {
		return 0, readError(reader.ctx)
	}
	return reader.input.Read(buffer) //nolint:wrapcheck // preserve the wrapped reader's stream semantics
}

type readResult struct {
	err error
	n   int
}

type blockingReader struct {
	ctx      context.Context //nolint:containedctx // Read has no context parameter
	input    io.Reader
	err      error
	requests chan int
	results  chan readResult
	buffer   []byte
}

func (reader *blockingReader) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if reader.err != nil {
		return 0, reader.err
	}
	if reader.ctx.Err() != nil {
		return 0, readError(reader.ctx)
	}
	if reader.requests == nil {
		reader.start()
	}

	select {
	case reader.requests <- min(len(buffer), readChunk):
	case <-reader.ctx.Done():
		return 0, readError(reader.ctx)
	}
	select {
	case result := <-reader.results:
		reader.err = result.err
		return copy(buffer, reader.buffer[:result.n]), result.err
	case <-reader.ctx.Done():
		return 0, readError(reader.ctx)
	}
}

func (reader *blockingReader) start() {
	reader.requests = make(chan int)
	reader.results = make(chan readResult)
	reader.buffer = make([]byte, readChunk)
	go reader.serve()
}

// serve owns buffer until it delivers a result, so cancellation never races Read.
func (reader *blockingReader) serve() {
	for {
		var want int
		select {
		case want = <-reader.requests:
		case <-reader.ctx.Done():
			return
		}
		n, err := reader.input.Read(reader.buffer[:want])
		select {
		case reader.results <- readResult{n: n, err: err}:
		case <-reader.ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}
