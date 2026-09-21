//go:build darwin

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const grpcFIFOReadRetryInterval = 10 * time.Millisecond

func readGRPCOwnedInput(ctx context.Context, file *os.File, limit int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect gRPC input: %w", err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		data, readErr := io.ReadAll(io.LimitReader(file, limit))
		if readErr != nil {
			return nil, fmt.Errorf("read gRPC input: %w", readErr)
		}
		return data, nil
	}
	// Go excludes Darwin FIFOs from netpoll because kqueue misses last-writer
	// EOF events. Nonblocking retries make this owned reader cancelable without
	// forcing the FIFO through that broken kqueue path (Go issue 24164).
	if err := setGRPCFIFOReadNonblocking(file); err != nil {
		return nil, err
	}

	data := make([]byte, 0)
	buffer := make([]byte, 32*1024)
	for int64(len(data)) < limit {
		readSize := min(int64(len(buffer)), limit-int64(len(data)))
		count, readErr := file.Read(buffer[:readSize])
		data = append(data, buffer[:count]...)
		if readErr == nil && count == 0 {
			return data, nil
		}
		if errors.Is(readErr, syscall.EAGAIN) {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("read gRPC FIFO input: %w", context.Cause(ctx))
			case <-time.After(grpcFIFOReadRetryInterval):
			}
			continue
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return data, nil
			}
			return data, fmt.Errorf("read gRPC FIFO input: %w", readErr)
		}
	}
	return data, nil
}

func setGRPCFIFOReadNonblocking(file *os.File) error {
	raw, err := file.SyscallConn()
	if err != nil {
		return fmt.Errorf("access gRPC FIFO input descriptor: %w", err)
	}
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		controlErr = unix.SetNonblock(int(fd), true)
	}); err != nil {
		return fmt.Errorf("access gRPC FIFO input descriptor: %w", err)
	}
	if controlErr != nil {
		return fmt.Errorf("configure gRPC FIFO input: %w", controlErr)
	}
	return nil
}
