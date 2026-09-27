package cmd

import (
	"fmt"
	"slices"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
)

func TestCommandTreeConformsToNounVerbGrammar(t *testing.T) {
	t.Parallel()
	for _, violation := range commandTreeViolations(newRootCmd()) {
		t.Error(violation)
	}
}

func TestCommandTreeRejectsUnclassifiedLeaf(t *testing.T) {
	t.Parallel()
	root := &cobra.Command{Use: "root"}
	group := &cobra.Command{Use: "noun"}
	group.AddCommand(&cobra.Command{Use: "inspect", Run: func(*cobra.Command, []string) {}})
	root.AddCommand(group)

	violations := commandTreeViolations(root)
	if len(violations) != 1 || violations[0] != `leaf command "root noun inspect" has no output shape` {
		t.Fatalf("violations = %q, want missing output shape", violations)
	}
}

func TestCommandTreeScopesHashAlgorithmsToRootGroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		algorithm string
		want      []string
		nested    bool
	}{
		{name: "approved root algorithm", algorithm: "sha256"},
		{
			name:      "unapproved root algorithm",
			algorithm: "crc32",
			want:      []string{`leaf command "root hash crc32" is not an allowed verb`},
		},
		{
			name:      "approved name in nested hash group",
			algorithm: "sha256",
			nested:    true,
			want:      []string{`leaf command "root crypto hash sha256" is not an allowed verb`},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := &cobra.Command{Use: "root"}
			hash := &cobra.Command{Use: "hash"}
			hash.AddCommand(commandio.BinaryOutputCommand(&cobra.Command{
				Use: test.algorithm,
				Run: func(*cobra.Command, []string) {},
			}, true))
			if test.nested {
				parent := &cobra.Command{Use: "crypto"}
				parent.AddCommand(hash)
				root.AddCommand(parent)
			} else {
				root.AddCommand(hash)
			}

			violations := commandTreeViolations(root)
			if !slices.Equal(violations, test.want) {
				t.Fatalf("violations = %q, want %q", violations, test.want)
			}
		})
	}
}

func TestCommandTreeScopesRunnableHashGroupToRoot(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		group  string
		want   []string
		nested bool
	}{
		{name: "root hash group", group: "hash"},
		{
			name:   "nested hash group",
			group:  "hash",
			nested: true,
			want:   []string{`group command "root crypto hash" must not be runnable`},
		},
		{
			name:  "unrelated root group",
			group: "noun",
			want:  []string{`group command "root noun" must not be runnable`},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := &cobra.Command{Use: "root"}
			group := &cobra.Command{Use: test.group, Run: func(*cobra.Command, []string) {}}
			group.AddCommand(commandio.BinaryOutputCommand(&cobra.Command{
				Use: "inspect",
				Run: func(*cobra.Command, []string) {},
			}, false))
			if test.nested {
				parent := &cobra.Command{Use: "crypto"}
				parent.AddCommand(group)
				root.AddCommand(parent)
			} else {
				root.AddCommand(group)
			}

			violations := commandTreeViolations(root)
			if !slices.Equal(violations, test.want) {
				t.Fatalf("violations = %q, want %q", violations, test.want)
			}
		})
	}
}

func commandTreeViolations(root *cobra.Command) []string {
	// Cobra's generated help/completion trees are outside npc's command grammar.
	verbs := map[string]bool{
		"connect":  true,
		"decrypt":  true,
		"encrypt":  true,
		"generate": true,
		"keygen":   true,
		"inspect":  true,
		"listen":   true,
		"match":    true,
		"public":   true,
		"verify":   true,
		"convert":  true,
		"create":   true,
		"csr":      true,
	}
	transportLeaves := map[string]bool{"tcp": true, "tls": true, "udp": true}
	hashAlgorithmLeaves := map[string]bool{"md5": true, "sha1": true, "sha256": true, "sha512": true}

	var violations []string
	var walk func(*cobra.Command)
	walk = func(command *cobra.Command) {
		for _, child := range command.Commands() {
			if child.Name() == "completion" || child.Name() == "help" {
				continue
			}

			if child.HasSubCommands() {
				isRunnableRootHash := command == root && child.Name() == "hash"
				// AES is technically runnable so Cobra validates removed nested commands;
				// its argument contract returns help before I/O for the bare noun.
				isHelpOnlyParent := command == root && (child.Name() == "aes" || child.Name() == "key")
				if (child.Run != nil || child.RunE != nil) && !isRunnableRootHash && !isHelpOnlyParent {
					violations = append(violations, fmt.Sprintf("group command %q must not be runnable", child.CommandPath()))
				}
			} else {
				isTransportVerb := command.Name() == "connect" || command.Name() == "listen"
				isTransport := isTransportVerb && command.Parent() != nil && command.Parent().Name() == "net" && transportLeaves[child.Name()]
				isRootUtility := command == root && ((child.Name() == "http" && commandio.HasShape(child, "http-request")) ||
					(child.Name() == "dns" && commandio.HasShape(child, "dns-query")) ||
					(child.Name() == "grpc" && commandio.HasShape(child, "grpc-request")))
				isHashAlgorithm := command.Name() == "hash" && command.Parent() == root && hashAlgorithmLeaves[child.Name()]
				isAESKeyVerb := command.Name() == "aes" && command.Parent() == root &&
					(child.Name() == "key-convert" || child.Name() == "key-inspect")
				if !verbs[child.Name()] && !isTransport && !isRootUtility && !isHashAlgorithm && !isAESKeyVerb {
					violations = append(violations, fmt.Sprintf("leaf command %q is not an allowed verb", child.CommandPath()))
				}
				binary := commandio.HasShape(child, "binary-output")
				structured := commandio.HasShape(child, "structured-output")
				switch {
				case !binary && !structured:
					violations = append(violations, fmt.Sprintf("leaf command %q has no output shape", child.CommandPath()))
				case binary && structured:
					violations = append(violations, fmt.Sprintf("leaf command %q has conflicting output shapes", child.CommandPath()))
				case binary && child.Flag("encoding") == nil:
					violations = append(violations, fmt.Sprintf("binary command %q has no --encoding flag", child.CommandPath()))
				case structured && child.Flag("format") == nil:
					violations = append(violations, fmt.Sprintf("structured command %q has no --format flag", child.CommandPath()))
				}
			}

			if commandio.HasShape(child, "network") && child.Flag("timeout") == nil {
				violations = append(violations, fmt.Sprintf("network command %q has no --timeout flag", child.CommandPath()))
			}
			if commandio.HasShape(child, "sensitive-output") && !commandio.HasShape(child, "binary-output") {
				violations = append(violations, fmt.Sprintf("sensitive command %q must have binary output", child.CommandPath()))
			}
			if child.Flags().Lookup("output-format") != nil {
				violations = append(violations, fmt.Sprintf("command %q still exposes --output-format", child.CommandPath()))
			}
			walk(child)
		}
	}
	walk(root)
	return violations
}
