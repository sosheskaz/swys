package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
)

func TestCommandTreesOwnFlagsAndAnnotations(t *testing.T) {
	t.Parallel()
	first := newRootCmd()
	second := newRootCmd()
	firstLeaf, _, err := first.Find([]string{"cert", "create"})
	require.NoError(t, err)
	secondLeaf, _, err := second.Find([]string{"cert", "create"})
	require.NoError(t, err)
	assert.NotSame(t, firstLeaf, secondLeaf, "command trees share a leaf")
	require.NoError(t, firstLeaf.Flags().Set("dns", "first.test"))
	require.NoError(t, first.PersistentFlags().Set("output", "first.pem"))
	commandio.AddShape(firstLeaf, "test-only")
	secondDNS, err := secondLeaf.Flags().GetStringArray("dns")
	require.NoError(t, err)
	assert.Empty(t, secondDNS, "DNS flag leaked between command trees")
	assert.False(t, secondLeaf.Flags().Changed("dns"), "DNS flag changed in second command tree")
	assert.False(t, second.PersistentFlags().Changed("output"), "output flag changed in second command tree")
	assert.False(t, commandio.HasShape(secondLeaf, "test-only"), "annotations leaked between command trees")
}

func TestIndependentCommandCompletion(t *testing.T) {
	t.Parallel()
	for range 8 {
		t.Run("completion", func(t *testing.T) {
			t.Parallel()
			stdout, _, err := executeRootStreams(t, "__complete", "aes", "encrypt", "--wire-format", "")
			require.NoError(t, err)
			if !strings.Contains(stdout, "openpgp") || !strings.Contains(stdout, "tink") || !strings.HasSuffix(stdout, ":4\n") {
				t.Fatalf("completion = %q, want values and no-file directive", stdout)
			}
			stdout, _, err = executeRootStreams(t, "__complete", "cert", "keygen", "")
			require.NoError(t, err)
			assert.Equal(t, ":4\n", stdout, "completed key argument")
		})
	}
}

func TestCommandExecutionRestoresStreamsAndContext(t *testing.T) {
	t.Parallel()
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			t.Parallel()
			root := newRootCmd()
			originalContext, cancel := context.WithCancel(t.Context())
			defer cancel()
			input := strings.NewReader("input")
			var output bytes.Buffer
			command := commandio.BinaryOutputCommand(&cobra.Command{
				Use: "isolation-test",
				RunE: func(cmd *cobra.Command, _ []string) error {
					if _, err := io.WriteString(cmd.OutOrStdout(), "A"); err != nil {
						return fmt.Errorf("write test output: %w", err)
					}
					if fail {
						return errTestCommandFailed
					}
					return nil
				},
			}, true)
			root.AddCommand(command)
			root.SetContext(originalContext)
			root.SetIn(input)
			root.SetOut(&output)
			root.SetArgs([]string{"isolation-test", "--encoding", "base64"})
			err := executeCommand(root)
			if fail && !errors.Is(err, errTestCommandFailed) || !fail && err != nil {
				t.Fatalf("execute error = %v, failing command = %v", err, fail)
			}
			assert.Equal(t, "QQ==", output.String(), "flushed encoder")
			if command.Context() != originalContext || command.InOrStdin() != input || command.OutOrStdout() != &output {
				t.Fatal("execution did not restore its original context and streams")
			}
		})
	}
}

func TestExecuteBuildsFreshTreeEachTime(t *testing.T) { //nolint:paralleltest // exercises Execute using process-wide os.Args
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	first := filepath.Join(t.TempDir(), "encoded.key")
	second := filepath.Join(t.TempDir(), "raw.key")
	os.Args = []string{"npc", "aes", "keygen", "--bits", "128", "--encoding", "hex", "--output", first}
	if err := Execute(); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"npc", "aes", "keygen", "--bits", "128", "--output", second}
	if err := Execute(); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]int64{first: 32, second: 16} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() != want {
			t.Fatalf("%s size = %d, want %d; encoding persisted across Execute calls", path, info.Size(), want)
		}
	}
}

func TestStreamCommandShapeDoesNotRequireTLSFlags(t *testing.T) {
	t.Parallel()
	root := newRootCmd()
	called := false
	command := commandio.StreamNetworkCommandWithTimeout(&cobra.Command{
		Use: "custom-stream host:port",
		RunE: func(*cobra.Command, []string) error {
			called = true
			return nil
		},
	}, commandio.DefaultStreamConnectTimeout, "TCP setup and TLS handshake timeout (0 disables)", false)
	root.AddCommand(command)
	if _, err := executeRootCommand(t, root, "custom-stream", "localhost:443"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("stream command did not run")
	}
}
