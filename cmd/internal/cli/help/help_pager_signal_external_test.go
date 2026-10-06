//go:build unix

package help_test

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/spf13/cobra"

	"github.com/sosheskaz/swys/cmd/internal/cli/help"
)

func TestGuidePagerWaitsThroughTerminalInterrupts(t *testing.T) {
	t.Parallel()
	for _, interrupt := range []syscall.Signal{syscall.SIGINT, syscall.SIGQUIT} {
		t.Run(interrupt.String(), func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			process := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGuidePagerInterruptHelperProcess$", "--", "swys-pager-interrupt", "controller", directory)
			process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			process.Stdout = io.Discard
			process.Stderr = io.Discard
			if err := process.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := syscall.Kill(-process.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
					t.Errorf("clean helper group: %v", err)
				}
			}()
			exited := make(chan error, 1)
			go func() { exited <- process.Wait() }()
			ready := waitPagerSignalFile(ctx, t, filepath.Join(directory, "ready"))
			pagerPID, err := strconv.Atoi(string(ready))
			if err != nil {
				t.Fatal(err)
			}
			if err := syscall.Kill(-process.Process.Pid, interrupt); err != nil {
				t.Fatal(err)
			}
			waitPagerSignalFile(ctx, t, filepath.Join(directory, "handled"))
			select {
			case err := <-exited:
				t.Fatalf("SwYS exited before its pager after %s: %v", interrupt, err)
			case <-time.After(100 * time.Millisecond):
			}
			if err := os.WriteFile(filepath.Join(directory, "release"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			waitPagerSignalFile(ctx, t, filepath.Join(directory, "reaped"))
			if err := syscall.Kill(pagerPID, 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatalf("pager was not reaped: %v", err)
			}
			if err := process.Process.Signal(interrupt); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-exited:
				if err == nil || ctx.Err() != nil {
					t.Fatal("interrupt behavior was not restored after paging")
				}
			case <-ctx.Done():
				t.Fatal("interrupt behavior was not restored after paging")
			}
		})
	}
}

func waitPagerSignalFile(ctx context.Context, t *testing.T, path string) []byte {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		contents, err := os.ReadFile(path)
		if err == nil && len(contents) > 0 {
			return contents
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("wait for helper %s: %v", filepath.Base(path), ctx.Err())
		}
	}
}

func TestGuidePagerInterruptHelperProcess(t *testing.T) { //nolint:paralleltest // subprocess branch exits the test process
	marker := slices.Index(os.Args, "swys-pager-interrupt")
	if marker < 0 {
		t.Parallel()
		return
	}
	arguments := os.Args[marker+1:]
	if len(arguments) != 2 {
		os.Exit(90)
	}
	directory := arguments[1]
	switch arguments[0] {
	case "controller":
		root := &cobra.Command{Use: "swys"}
		root.AddCommand(&cobra.Command{Use: "net", Run: func(*cobra.Command, []string) {}})
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs([]string{"help", "net"})
		if err := help.RegisterGuides(root, fstest.MapFS{"guides/net.md": &fstest.MapFile{Data: []byte("# Net\n")}}); err != nil {
			t.Fatal(err)
		}
		help.Configure(root, help.Dependencies{
			Getenv: func(key string) (string, bool) {
				if key == "PAGER" {
					return "hold", true
				}
				return "", false
			},
			Terminal: func(io.Writer) (bool, int) { return true, 80 },
			Command: func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
				return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGuidePagerInterruptHelperProcess$", "--", "swys-pager-interrupt", "pager", directory)
			},
		}, nil)
		if err := root.Execute(); err != nil {
			os.Exit(91)
		}
		if err := os.WriteFile(filepath.Join(directory, "reaped"), []byte("done"), 0o600); err != nil {
			os.Exit(92)
		}
		time.Sleep(30 * time.Second)
		os.Exit(93)
	case "pager":
		interrupts := make(chan os.Signal, 1)
		signal.Notify(interrupts, syscall.SIGINT, syscall.SIGQUIT)
		if err := os.WriteFile(filepath.Join(directory, "ready"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			os.Exit(94)
		}
		<-interrupts
		if err := os.WriteFile(filepath.Join(directory, "handled"), []byte("handled"), 0o600); err != nil {
			os.Exit(95)
		}
		for {
			if _, err := os.Stat(filepath.Join(directory, "release")); err == nil {
				os.Exit(0)
			}
			time.Sleep(10 * time.Millisecond)
		}
	default:
		os.Exit(96)
	}
}
