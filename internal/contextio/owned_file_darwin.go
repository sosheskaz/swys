//go:build darwin

package contextio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const fifoReadRetryInterval = 10 * time.Millisecond

func newOwnedFilePlatformReader(
	ctx context.Context,
	file *os.File,
	mode os.FileMode,
	done <-chan struct{},
) (io.Reader, func() error, error) {
	if mode&os.ModeNamedPipe == 0 {
		return file, nil, nil
	}
	// Go excludes Darwin FIFOs from netpoll because kqueue misses last-writer
	// EOF events. Nonblocking retries avoid that broken kqueue path (Go issue 24164).
	raw, originalNonblocking, err := setFileNonblocking(file)
	if err != nil {
		return nil, nil, err
	}
	reader := &darwinFIFOReader{
		ctx:                 ctx,
		file:                file,
		raw:                 raw,
		done:                done,
		originalNonblocking: originalNonblocking,
	}
	return reader, reader.restoreNonblocking, nil
}

type darwinFIFOReader struct {
	ctx                 context.Context //nolint:containedctx // Read has no context parameter
	file                *os.File
	raw                 syscall.RawConn
	done                <-chan struct{}
	mu                  sync.Mutex
	originalNonblocking bool
}

func (reader *darwinFIFOReader) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	for {
		reader.mu.Lock()
		select {
		case <-reader.done:
			reader.mu.Unlock()
			return 0, os.ErrClosed
		default:
		}
		if reader.ctx != nil && reader.ctx.Err() != nil {
			reader.mu.Unlock()
			return 0, readError(reader.ctx)
		}
		n, err := reader.readNonblocking(buffer)
		reader.mu.Unlock()
		if !errorsIsWouldBlock(err) {
			return n, err
		}
		timer := time.NewTimer(fifoReadRetryInterval)
		var canceled <-chan struct{}
		if reader.ctx != nil {
			canceled = reader.ctx.Done()
		}
		select {
		case <-reader.done:
			timer.Stop()
			return 0, os.ErrClosed
		case <-canceled:
			timer.Stop()
			return 0, readError(reader.ctx)
		case <-timer.C:
		}
	}
}

func (reader *darwinFIFOReader) readNonblocking(buffer []byte) (int, error) {
	var n int
	var readErr error
	controlErr := reader.raw.Control(func(fd uintptr) {
		for {
			n, readErr = unix.Read(int(fd), buffer)
			if !errors.Is(readErr, syscall.EINTR) {
				break
			}
		}
	})
	if controlErr != nil {
		return 0, fmt.Errorf("access file descriptor: %w", controlErr)
	}
	if n < 0 {
		n = 0
	}
	if n == 0 && readErr == nil {
		return 0, io.EOF
	}
	if readErr != nil {
		return n, fmt.Errorf("read FIFO input: %w", readErr)
	}
	return n, nil
}

func (reader *darwinFIFOReader) restoreNonblocking() error {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return restoreFileNonblocking(reader.file, reader.originalNonblocking)
}

func errorsIsWouldBlock(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK)
}

func setFileNonblocking(file *os.File) (syscall.RawConn, bool, error) {
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, false, fmt.Errorf("access file descriptor: %w", err)
	}
	var originalNonblocking bool
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		flags, flagErr := unix.FcntlInt(fd, unix.F_GETFL, 0)
		if flagErr != nil {
			controlErr = flagErr
			return
		}
		originalNonblocking = flags&unix.O_NONBLOCK != 0
		if !originalNonblocking {
			controlErr = unix.SetNonblock(int(fd), true)
		}
	}); err != nil {
		return nil, false, fmt.Errorf("access file descriptor: %w", err)
	}
	if controlErr != nil {
		return nil, false, fmt.Errorf("configure FIFO input: %w", controlErr)
	}
	return raw, originalNonblocking, nil
}

func restoreFileNonblocking(file *os.File, enabled bool) error {
	raw, err := file.SyscallConn()
	if err != nil {
		return fmt.Errorf("access file descriptor: %w", err)
	}
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		controlErr = unix.SetNonblock(int(fd), enabled)
	}); err != nil {
		return fmt.Errorf("access file descriptor: %w", err)
	}
	if controlErr != nil {
		return fmt.Errorf("restore FIFO input: %w", controlErr)
	}
	return nil
}
