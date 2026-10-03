//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package aes_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rootcmd "github.com/sosheskaz-systems/npc/cmd"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
)

const (
	aesKeyfileOrderProcessEnv = "NPC_AES_KEYFILE_ORDER_PROCESS"
	testPreservedOutput       = "preserve this output"
)

func TestAESValidKeyfileFIFOIsReadOnce(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "key.fifo")
	require.NoError(t, syscall.Mkfifo(path, 0o600))
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
		stdout, _, err := executeRootStreams(t, "aes", "encrypt", "payload", "--key", path)
		commandDone <- commandResult{stdout: stdout, err: err}
	}()

	select {
	case result := <-commandDone:
		require.NoError(t, result.err, "single-read FIFO encryption")
		require.NotEmpty(t, result.stdout, "single-read FIFO encryption")
	case <-time.After(5 * time.Second):
		t.Fatal("AES command did not finish after one FIFO key write; keyfile may have been read more than once")
	}
	select {
	case err := <-writerDone:
		require.NoError(t, err)
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
					"aes", "encrypt", "--key", fifo,
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
					"aes", "encrypt", "payload", "--key", fifo,
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
			require.NoError(t, syscall.Mkfifo(fifo, 0o600))
			output := filepath.Join(directory, "output")
			require.NoError(t, os.WriteFile(output, []byte(testPreservedOutput), 0o600))

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
			require.Error(t, err, "command must report prompt %q error", test.want)
			require.Contains(t, stderr.String(), test.want, "prompt error")
			data, readErr := os.ReadFile(output)
			require.NoError(t, readErr)
			assert.Equal(t, testPreservedOutput, string(data), "invalid input changed output")
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
	root := rootcmd.NewCommand()
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	root.SetArgs(os.Args[separator+1:])
	if err := commandio.Execute(root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}
