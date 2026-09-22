//go:build darwin

package contextio

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOwnedFileReaderRestoresSharedNonblockingFlagOnClose(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name               string
		initialNonblocking bool
		cancel             bool
	}{
		{name: "blocking/Close"},
		{name: "blocking/cancellation", cancel: true},
		{name: "nonblocking/Close", initialNonblocking: true},
		{name: "nonblocking/cancellation", initialNonblocking: true, cancel: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			original, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = original.Close() //nolint:errcheck // test cleanup is best effort
				_ = writer.Close()   //nolint:errcheck // test cleanup is best effort
			})
			setOwnedTestNonblocking(t, original, test.initialNonblocking)

			fd := ownedTestDescriptor(t, original)
			alias, err := os.Open("/dev/fd/" + strconv.FormatUint(uint64(fd), 10))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = alias.Close() }) //nolint:errcheck // ownership may already have closed it
			if got := ownedTestNonblocking(t, original); got != test.initialNonblocking {
				t.Fatalf("opening descriptor alias changed O_NONBLOCK to %t, want %t", got, test.initialNonblocking)
			}

			ctx := context.WithoutCancel(t.Context())
			cancel := func() {}
			if test.cancel {
				ctx, cancel = context.WithCancel(t.Context())
			}
			t.Cleanup(cancel)
			reader, err := NewOwnedFileReader(ctx, alias)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reader.Close() }) //nolint:errcheck // test cleanup is best effort
			setOwnedTestAppend(t, original)

			if test.cancel {
				cancel()
				waitUntil(t, func() bool {
					_, statErr := alias.Stat()
					return errors.Is(statErr, os.ErrClosed)
				}, "cancellation did not close the owned descriptor alias")
			} else if err := reader.Close(); err != nil {
				t.Fatalf("close owned descriptor alias: %v", err)
			}

			if got := ownedTestNonblocking(t, original); got != test.initialNonblocking {
				t.Fatalf("O_NONBLOCK after owned alias close = %t, want original state %t", got, test.initialNonblocking)
			}
			if flags := ownedTestStatusFlags(t, original); flags&unix.O_APPEND == 0 {
				t.Fatalf("file status flags after owned alias close = %#x, want unrelated O_APPEND preserved", flags)
			}
			if _, err := writer.Write([]byte{'x'}); err != nil {
				t.Fatalf("write through surviving pipe endpoint: %v", err)
			}
			buffer := make([]byte, 1)
			if n, err := original.Read(buffer); n != 1 || err != nil || buffer[0] != 'x' {
				t.Fatalf("read through surviving original = (%q, %v), want (x, nil)", buffer[:n], err)
			}
		})
	}
}

func TestOwnedFileReaderCloseReleasesEnteredDarwinFIFORead(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		cancel bool
	}{
		{name: "Close"},
		{name: "cancellation", cancel: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.WithoutCancel(t.Context())
			cancel := func() {}
			if test.cancel {
				ctx, cancel = context.WithCancel(t.Context())
			}
			t.Cleanup(cancel)
			reader, err := NewOwnedFileReader(ctx, input)
			if err != nil {
				_ = writer.Close() //nolint:errcheck // release the pipe after constructor failure
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = writer.Close() //nolint:errcheck // release a defective blocked Read before cleanup
				_ = reader.Close() //nolint:errcheck // test cleanup is best effort
			})

			labelValue := t.Name()
			readDone := make(chan darwinPollReadResult, 1)
			go pprof.Do(t.Context(), pprof.Labels("contextio-darwin-read-test", labelValue), func(context.Context) {
				n, readErr := reader.Read(make([]byte, 1))
				readDone <- darwinPollReadResult{err: readErr, n: n}
			})
			waitForLabeledDarwinFIFORead(t, labelValue)

			var closeDone chan error
			if test.cancel {
				cancel()
			} else {
				closeDone = make(chan error, 1)
				go func() { closeDone <- reader.Close() }()
			}
			timedOut := false
			closeFinished := false
			if closeDone != nil {
				select {
				case closeErr := <-closeDone:
					closeFinished = true
					if closeErr != nil {
						t.Fatalf("Close runtime-poll reader: %v", closeErr)
					}
				case <-time.After(2 * time.Second):
					timedOut = true
				}
			}

			var result darwinPollReadResult
			if !timedOut {
				select {
				case result = <-readDone:
				case <-time.After(2 * time.Second):
					timedOut = true
				}
			}
			if timedOut {
				if err := writer.Close(); err != nil {
					t.Fatalf("close runtime-poll writer during cleanup: %v", err)
				}
				select {
				case <-readDone:
				case <-time.After(5 * time.Second):
					t.Fatal("runtime-poll Read remained blocked after writer cleanup")
				}
				if closeDone != nil && !closeFinished {
					select {
					case <-closeDone:
					case <-time.After(5 * time.Second):
						t.Fatal("Close remained blocked after writer cleanup")
					}
				}
				t.Fatal("owned reader cleanup did not release a runtime-poll Read")
			}

			if result.n != 0 || result.err == nil {
				t.Fatalf("released runtime-poll Read = (%d, %v), want (0, non-nil error)", result.n, result.err)
			}
			if test.cancel && !errors.Is(result.err, context.Canceled) {
				t.Fatalf("canceled runtime-poll Read error = %v, want context.Canceled", result.err)
			}
			waitUntil(t, func() bool {
				_, statErr := input.Stat()
				return errors.Is(statErr, os.ErrClosed)
			}, "runtime-poll input remained open after cleanup")
		})
	}
}

type darwinPollReadResult struct {
	err error
	n   int
}

func waitForLabeledDarwinFIFORead(t *testing.T, labelValue string) {
	t.Helper()
	profile := pprof.Lookup("goroutine")
	if profile == nil {
		t.Fatal("goroutine profile is unavailable")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var output bytes.Buffer
		if err := profile.WriteTo(&output, 1); err != nil {
			t.Fatalf("write goroutine profile: %v", err)
		}
		for sample := range strings.SplitSeq(output.String(), "\n\n") {
			if strings.Contains(sample, labelValue) && strings.Contains(sample, "contextio.(*darwinFIFOReader).Read") {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("labeled reader did not enter darwinFIFOReader.Read")
}

func ownedTestDescriptor(t *testing.T, file *os.File) uintptr {
	t.Helper()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var descriptor uintptr
	if err := raw.Control(func(fd uintptr) { descriptor = fd }); err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func ownedTestNonblocking(t *testing.T, file *os.File) bool {
	t.Helper()
	return ownedTestStatusFlags(t, file)&unix.O_NONBLOCK != 0
}

func ownedTestStatusFlags(t *testing.T, file *os.File) int {
	t.Helper()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		flags, controlErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if controlErr != nil {
		t.Fatal(controlErr)
	}
	return flags
}

func setOwnedTestNonblocking(t *testing.T, file *os.File, enabled bool) {
	t.Helper()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		controlErr = unix.SetNonblock(int(fd), enabled)
	}); err != nil {
		t.Fatal(err)
	}
	if controlErr != nil {
		t.Fatal(controlErr)
	}
}

func setOwnedTestAppend(t *testing.T, file *os.File) {
	t.Helper()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		flags, flagErr := unix.FcntlInt(fd, unix.F_GETFL, 0)
		if flagErr != nil {
			controlErr = flagErr
			return
		}
		_, controlErr = unix.FcntlInt(fd, unix.F_SETFL, flags|unix.O_APPEND)
	}); err != nil {
		t.Fatal(err)
	}
	if controlErr != nil {
		t.Fatal(controlErr)
	}
	if flags := ownedTestStatusFlags(t, file); flags&unix.O_APPEND == 0 {
		t.Fatalf("set O_APPEND: status flags = %#x, want O_APPEND", flags)
	}
}
