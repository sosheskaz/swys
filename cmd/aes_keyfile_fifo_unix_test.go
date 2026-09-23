//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const aesKeyfileOrderProcessEnv = "NPC_AES_KEYFILE_ORDER_PROCESS"

func TestAESValidKeyfileFIFOIsReadOnce(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "key.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x42}, 16)
	writerDone := make(chan error, 1)
	go func() {
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err == nil {
			_, writeErr := file.Write(key)
			err = errors.Join(writeErr, file.Close())
		}
		writerDone <- err
	}()

	type commandResult struct {
		err    error
		stdout string
	}
	commandDone := make(chan commandResult, 1)
	go func() {
		stdout, _, err := executeRootStreams(t, "aes", "encrypt", "payload", "--keyfile", path)
		commandDone <- commandResult{stdout: stdout, err: err}
	}()

	select {
	case result := <-commandDone:
		if result.err != nil || result.stdout == "" {
			t.Fatalf("single-read FIFO encryption = %d bytes, error %v", len(result.stdout), result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AES command did not finish after one FIFO key write; keyfile may have been read more than once")
	}
	select {
	case err := <-writerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out writing one AES key to FIFO")
	}
}

func TestAESInvalidInputPrecedesUnreadKeyfileFIFO(t *testing.T) {
	t.Parallel()

	tests := []struct {
		args func(string, string, string) []string
		name string
		want string
	}{
		{
			name: "missing input",
			want: "missing-input",
			args: func(fifo, output, directory string) []string {
				return []string{
					"aes", "encrypt", "--keyfile", fifo,
					"--input", filepath.Join(directory, "missing-input"),
					"--output", output,
				}
			},
		},
		{
			name: "invalid input encoding",
			want: "unknown input encoding",
			args: func(fifo, output, _ string) []string {
				return []string{
					"aes", "encrypt", "payload", "--keyfile", fifo,
					"--input-encoding", "rot13", "--output", output,
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			fifo := filepath.Join(directory, "key.fifo")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(directory, "output")
			if err := os.WriteFile(output, []byte(testPreservedOutput), 0o600); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			arguments := []string{"-test.run=^TestAESKeyfileValidationOrderProcess$", "-test.count=1", "--"}
			arguments = append(arguments, test.args(fifo, output, directory)...)
			command := exec.CommandContext(ctx, os.Args[0], arguments...)
			command.Env = append(os.Environ(), aesKeyfileOrderProcessEnv+"=1")
			var stderr bytes.Buffer
			command.Stderr = &stderr
			err := command.Run()
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatalf("command blocked opening unused key FIFO instead of reporting %s", test.want)
			}
			if err == nil || !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("command error = %v, stderr = %q; want prompt %q error", err, stderr.String(), test.want)
			}
			data, readErr := os.ReadFile(output)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(data) != testPreservedOutput {
				t.Fatalf("invalid input changed output to %q", data)
			}
		})
	}
}

func TestAESKeyfileValidationOrderProcess(_ *testing.T) { //nolint:paralleltest // helper exits the subprocess
	if os.Getenv(aesKeyfileOrderProcessEnv) != "1" {
		return
	}
	separator := -1
	for i, argument := range os.Args {
		if argument == "--" {
			separator = i
			break
		}
	}
	if separator < 0 || separator == len(os.Args)-1 {
		fmt.Fprintln(os.Stderr, "missing AES keyfile-order child command")
		os.Exit(2)
	}
	root := newRootCmd()
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	root.SetArgs(os.Args[separator+1:])
	if err := executeCommand(root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}
