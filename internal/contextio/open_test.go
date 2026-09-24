package contextio

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenFileReturnsTheOpenResult(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "input")
	require.NoError(t, os.WriteFile(path, []byte("data"), 0o600))
	openFile := func() (*os.File, error) { return os.Open(path) }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	for name, ctx := range map[string]context.Context{
		"nil context":                     nil,
		"context that cannot be canceled": context.WithoutCancel(t.Context()),
		"cancelable context":              ctx,
	} {
		file, err := OpenFile(ctx, openFile)
		require.NoError(t, err, name)
		require.NoError(t, file.Close(), name)
		_, err = OpenFile(ctx, func() (*os.File, error) { return nil, os.ErrNotExist })
		assert.ErrorIs(t, err, os.ErrNotExist, name)
	}
}

func TestOpenFileRefusesToStartWhenCanceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(errCause)

	file, err := OpenFile(ctx, func() (*os.File, error) {
		t.Error("open ran after cancellation")
		return nil, nil //nolint:nilnil // the test fails before the result is used
	})

	if file != nil || !errors.Is(err, errCause) {
		t.Fatalf("OpenFile = (%v, %v), want the cancellation cause", file, err)
	}
}

func TestOpenFileStopsWaitingAndClosesTheLateFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	entered := make(chan struct{})
	release := make(chan struct{})
	opened := make(chan *os.File, 1)
	result := make(chan error, 1)
	go func() {
		_, err := OpenFile(ctx, func() (*os.File, error) {
			close(entered)
			<-release
			file, err := os.Open(path)
			opened <- file
			return file, err //nolint:wrapcheck // the test inspects the raw open result
		})
		result <- err
	}()
	waitForSignal(t, entered, "open did not start")

	cancel(errCause)

	select {
	case err := <-result:
		if !errors.Is(err, errCause) {
			t.Fatalf("error = %v, want the cancellation cause", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("OpenFile stayed blocked after cancellation")
	}
	// The abandoned open completes later; its file must not leak.
	close(release)
	file := <-opened
	waitUntil(t, func() bool { _, err := file.Stat(); return errors.Is(err, os.ErrClosed) }, "abandoned open leaked its file")
}

func TestOpenFileCancellationLeavesOneWorkerForBlockedOpen(t *testing.T) {
	t.Parallel()
	const labelKey = "contextio-open-test"
	labelValue := t.Name() + ":canceled-blocked-open"

	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(t.Context())
		entered := make(chan struct{})
		release := make(chan struct{})
		defer close(release)
		result := make(chan error)

		go pprof.Do(ctx, pprof.Labels(labelKey, labelValue), func(ctx context.Context) {
			_, err := OpenFile(ctx, func() (*os.File, error) {
				close(entered)
				<-release
				return nil, os.ErrNotExist
			})
			result <- err
		})
		<-entered
		cancel(errCause)
		if err := <-result; !errors.Is(err, errCause) {
			t.Fatalf("error = %v, want the cancellation cause", err)
		}

		synctest.Wait()
		var profile bytes.Buffer
		if err := pprof.Lookup("goroutine").WriteTo(&profile, 1); err != nil {
			t.Fatalf("write goroutine profile: %v", err)
		}
		if got := strings.Count(profile.String(), labelValue); got != 1 {
			t.Fatalf("workers retained by canceled blocked open = %d, want 1", got)
		}
	})
}
