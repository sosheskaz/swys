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
)

func TestCommandTreesOwnFlagsAndAnnotations(t *testing.T) {
	t.Parallel()
	first := newRootCmd()
	second := newRootCmd()
	firstLeaf, _, err := first.Find([]string{"cert", "create"})
	if err != nil {
		t.Fatal(err)
	}
	secondLeaf, _, err := second.Find([]string{"cert", "create"})
	if err != nil {
		t.Fatal(err)
	}
	if firstLeaf == secondLeaf {
		t.Fatal("command trees share a leaf")
	}
	if err := firstLeaf.Flags().Set("dns", "first.test"); err != nil {
		t.Fatal(err)
	}
	if err := first.PersistentFlags().Set("output", "first.pem"); err != nil {
		t.Fatal(err)
	}
	addCommandShape(firstLeaf, "test-only")
	secondDNS, err := secondLeaf.Flags().GetStringArray("dns")
	if err != nil {
		t.Fatal(err)
	}
	if len(secondDNS) != 0 || secondLeaf.Flags().Changed("dns") || second.PersistentFlags().Changed("output") {
		t.Fatal("flags leaked between command trees")
	}
	if commandHasShape(secondLeaf, "test-only") {
		t.Fatal("annotations leaked between command trees")
	}
}

func TestIndependentCommandCompletion(t *testing.T) {
	t.Parallel()
	for range 8 {
		t.Run("completion", func(t *testing.T) {
			t.Parallel()
			stdout, _, err := executeRootStreams(t, "__complete", "aes", "encrypt", "--cipher-mode", "")
			if err != nil {
				t.Fatal(err)
			}
			if stdout != "cbc\tcompatibility mode\ngcm\tauthenticated default\n:4\n" {
				t.Fatalf("completion = %q, want values and no-file directive", stdout)
			}
			stdout, _, err = executeRootStreams(t, "__complete", "key", "generate", "ed25519", "")
			if err != nil {
				t.Fatal(err)
			}
			if stdout != ":4\n" {
				t.Fatalf("completed key argument = %q, want only no-file directive", stdout)
			}
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
			command := binaryOutputCommand(&cobra.Command{
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
			if output.String() != "QQ==" {
				t.Fatalf("output = %q, want flushed encoder", output.String())
			}
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
	os.Args = []string{"npc", "key", "generate", "aes128", "--encoding", "hex", "--output", first}
	if err := Execute(); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"npc", "key", "generate", "aes128", "--output", second}
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
	command := streamNetworkCommand(&cobra.Command{
		Use: "custom-stream host:port",
		RunE: func(*cobra.Command, []string) error {
			called = true
			return nil
		},
	})
	root.AddCommand(command)
	if _, err := executeRootCommand(t, root, "custom-stream", "localhost:443"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("stream command did not run")
	}
}
