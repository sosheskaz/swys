package contextio

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
)

// NewOwnedFileReader returns a streaming reader that closes file when ctx is
// canceled or the reader is closed. Ownership of file transfers to the reader
// when NewOwnedFileReader is called, including when construction fails.
func NewOwnedFileReader(ctx context.Context, file *os.File) (io.ReadCloser, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, errors.Join(readError(ctx), file.Close())
	}
	info, err := file.Stat()
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	done := make(chan struct{})
	reader, cleanup, err := newOwnedFilePlatformReader(ctx, file, info.Mode(), done)
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	owned := &ownedFileReader{
		ctx:     ctx,
		file:    file,
		reader:  reader,
		done:    done,
		cleanup: cleanup,
	}
	if ctx != nil && ctx.Done() != nil {
		go owned.closeOnCancellation()
	}
	return owned, nil
}

type ownedFileReader struct {
	ctx       context.Context //nolint:containedctx // Read has no context parameter
	file      *os.File
	reader    io.Reader
	done      chan struct{}
	cleanup   func() error
	closeErr  error
	closeOnce sync.Once
}

func (reader *ownedFileReader) Read(buffer []byte) (int, error) {
	if reader.ctx != nil && reader.ctx.Err() != nil {
		return 0, readError(reader.ctx)
	}
	n, err := reader.reader.Read(buffer)
	if err != nil && reader.ctx != nil && reader.ctx.Err() != nil {
		return 0, readError(reader.ctx)
	}
	return n, err //nolint:wrapcheck // preserve file stream semantics
}

// Close releases the owned file once and wakes any pending read.
func (reader *ownedFileReader) Close() error {
	reader.closeOnce.Do(func() {
		// Stop platform reads before cleanup restores descriptor state; otherwise
		// a Darwin FIFO read could start after O_NONBLOCK is cleared and never wake.
		close(reader.done)
		var cleanupErr error
		if reader.cleanup != nil {
			cleanupErr = reader.cleanup()
		}
		reader.closeErr = errors.Join(cleanupErr, reader.file.Close())
	})
	return reader.closeErr
}

func (reader *ownedFileReader) closeOnCancellation() {
	select {
	case <-reader.ctx.Done():
		_ = reader.Close() //nolint:errcheck // cancellation is the authoritative error
	case <-reader.done:
	}
}
