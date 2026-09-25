package help_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	rootcmd "github.com/sosheskaz-systems/npc/cmd"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/cmd/internal/cli/help"
	"github.com/sosheskaz-systems/npc/cmd/internal/testcmd"
)

func TestEmbeddedGuidesCoverEveryPublicCommand(t *testing.T) {
	t.Parallel()

	root := initializedGuideRoot()
	guides, err := loadEmbeddedGuides(root)
	if err != nil {
		t.Fatal(err)
	}
	want := publicGuidePaths(root)
	got := make([]string, 0, len(guides))
	for path := range guides {
		got = append(got, path)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("embedded guide paths = %q, want public command paths %q", got, want)
	}

	for _, path := range want {
		command, err := resolveGuideTarget(root, strings.Fields(path))
		if err != nil {
			t.Fatalf("resolve canonical guide %q: %v", path, err)
		}
		source := guides[path]
		blocks, err := parseGuide(source)
		if err != nil {
			t.Fatalf("parse guide %q: %v", guideDisplayPath(path), err)
		}
		if command == root || len(publicGuideChildren(command)) > 0 {
			if !guideHasBlock(blocks, guideListBlock) {
				t.Errorf("root or branch guide %q has no chooser list", guideDisplayPath(path))
			}
		} else if !guideHasBlock(blocks, guideCodeBlock) {
			t.Errorf("leaf guide %q has no executable example", guideDisplayPath(path))
		}

		reference := "npc --help"
		if path != "" {
			reference = "npc " + path + " --help"
		}
		if !sourceHasCommand(source, reference) {
			t.Errorf("guide %q does not contain reference invocation %q", guideDisplayPath(path), reference)
		}
	}
}

func TestGuideNavigationReferencesResolveThroughCommandTree(t *testing.T) {
	t.Parallel()

	root := initializedGuideRoot()
	guides, err := loadEmbeddedGuides(root)
	if err != nil {
		t.Fatal(err)
	}
	navigation := regexp.MustCompile(`(?m)^npc help(?: ([^\r\n]+))?$`)
	for path, source := range guides {
		for _, match := range navigation.FindAllSubmatch(source, -1) {
			fields := strings.Fields(string(match[1]))
			if slices.ContainsFunc(fields, func(field string) bool { return strings.HasPrefix(field, "-") }) {
				continue
			}
			if _, err := resolveGuideTarget(root, fields); err != nil {
				t.Errorf("guide %q has unresolved navigation %q: %v", guideDisplayPath(path), match[0], err)
			}
		}
	}
}

func TestEveryEmbeddedGuideRendersPlainAndRich(t *testing.T) {
	t.Parallel()

	root := initializedGuideRoot()
	guides, err := loadEmbeddedGuides(root)
	if err != nil {
		t.Fatal(err)
	}
	for path, source := range guides {
		t.Run(strings.ReplaceAll(guideDisplayPath(path), " ", "_"), func(t *testing.T) {
			t.Parallel()
			plain, err := renderGuide(source, guideRenderOptions{width: 47})
			if err != nil {
				t.Fatal(err)
			}
			rich, err := renderGuide(source, guideRenderOptions{width: 47, rich: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(plain) == 0 || bytes.Contains(plain, []byte("\x1b[")) || bytes.Contains(plain, []byte("```")) {
				t.Fatalf("plain guide contains raw presentation syntax: %q", plain)
			}
			if !bytes.Contains(rich, []byte("\x1b[")) {
				t.Fatalf("rich guide contains no styling: %q", rich)
			}
			plainLabels := regexp.MustCompile(`\s+\(https?://[^)]+\)`).ReplaceAllString(string(plain), "")
			if stripped := stripGuideANSI(string(rich)); strings.Join(strings.Fields(stripped), " ") != strings.Join(strings.Fields(plainLabels), " ") {
				t.Fatalf("rich and plain content differ\nrich: %q\nplain: %q", stripped, plain)
			}
		})
	}
}

func TestEveryCommandAliasCombinationResolvesCanonicalGuide(t *testing.T) {
	t.Parallel()

	root := initializedGuideRoot()
	var visit func(*cobra.Command, [][]string)
	visit = func(parent *cobra.Command, parentPaths [][]string) {
		for _, child := range publicGuideChildren(parent) {
			names := append([]string{child.Name()}, child.Aliases...)
			var childPaths [][]string
			for _, parentPath := range parentPaths {
				for _, name := range names {
					path := append(append([]string{}, parentPath...), name)
					resolved, err := resolveGuideTarget(root, path)
					if err != nil {
						t.Errorf("resolve alias path %q: %v", path, err)
						continue
					}
					if got, want := canonicalGuideKey(root, resolved), canonicalGuideKey(root, child); got != want {
						t.Errorf("alias path %q resolved to %q, want %q", path, got, want)
					}
					childPaths = append(childPaths, path)
				}
			}
			visit(child, childPaths)
		}
	}
	visit(root, [][]string{{}})
}

func TestEveryPublicCommandReferenceHelpPointsToItsGuide(t *testing.T) {
	t.Parallel()

	for _, path := range publicGuidePaths(initializedGuideRoot()) {
		t.Run(strings.ReplaceAll(guideDisplayPath(path), " ", "_"), func(t *testing.T) {
			t.Parallel()

			args := strings.Fields(path)
			args = append(args, "--help")
			stdout, stderr, err := executeRootStreams(t, args...)
			if err != nil {
				t.Fatal(err)
			}
			invocation := "npc help"
			if path != "" {
				invocation += " " + path
			}
			if !strings.Contains(stdout, "For a usage guide, run '"+invocation+"'.") {
				t.Fatalf("reference help lacks guide pointer %q:\n%s", invocation, stdout)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q", stderr)
			}
		})
	}
}

func publicGuidePaths(root *cobra.Command) []string {
	paths := []string{""}
	var visit func(*cobra.Command)
	visit = func(parent *cobra.Command) {
		for _, child := range publicGuideChildren(parent) {
			paths = append(paths, canonicalGuideKey(root, child))
			visit(child)
		}
	}
	visit(root)
	slices.Sort(paths)
	return paths
}

func sourceHasCommand(source []byte, command string) bool {
	return regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(command) + `$`).Match(source)
}

type (
	guideBlock         = help.GuideBlockForTest
	guideBlockKind     = help.GuideBlockKindForTest
	guideRenderOptions struct {
		width int
		rich  bool
	}
)

const (
	guideListBlock     = help.GuideListBlockForTest
	guideCodeBlock     = help.GuideCodeBlockForTest
	guideMarkupFixture = help.GuideMarkupFixtureForTest
)

var errGuideOperationalFlag = help.ErrGuideOperationalFlag

func loadEmbeddedGuides(root *cobra.Command) (map[string][]byte, error) {
	return help.LoadEmbeddedGuidesForTest(root)
}

func resolveGuideTarget(root *cobra.Command, path []string) (*cobra.Command, error) {
	return help.ResolveGuideTargetForTest(root, path)
}
func parseGuide(source []byte) ([]guideBlock, error) { return help.ParseGuideForTest(source) }
func renderGuide(source []byte, options guideRenderOptions) ([]byte, error) {
	return help.RenderGuideForTest(source, options.width, options.rich)
}

func publicGuideChildren(command *cobra.Command) []*cobra.Command {
	return help.PublicGuideChildrenForTest(command)
}

func canonicalGuideKey(root, command *cobra.Command) string {
	return help.CanonicalGuideKeyForTest(root, command)
}
func guideDisplayPath(key string) string { return help.GuideDisplayPathForTest(key) }
func guideHasBlock(blocks []guideBlock, kind guideBlockKind) bool {
	return help.HasGuideBlockForTest(blocks, kind)
}
func stripGuideANSI(value string) string { return help.StripGuideANSIForTest(value) }

func initializedGuideRoot() *cobra.Command {
	root := rootcmd.NewCommand()
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	return root
}

func newGuideTestRoot(terminal bool, width int, environment map[string]string) *cobra.Command {
	root := rootcmd.NewCommand()
	for _, command := range root.Commands() {
		if help.IsGuideCommand(command) {
			root.RemoveCommand(command)
		}
	}
	help.Configure(root, help.Dependencies{
		Getenv: func(name string) (string, bool) {
			value, ok := environment[name]
			return value, ok
		},
		Terminal: func(io.Writer) (bool, int) { return terminal, width },
	}, nil)
	return root
}

func executeRootStreams(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	stdout, stderr, err := testcmd.RunStreams(t, rootcmd.NewCommand(), nil, args...)
	return string(stdout), string(stderr), err
}

func executeRootCommandStreams(t *testing.T, root *cobra.Command, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err := commandio.Execute(root)
	return stdout.String(), stderr.String(), err
}

type guidePanicReader struct{}

func (guidePanicReader) Read([]byte) (int, error) {
	panic("guide command read operational stdin")
}

func TestHelpRejectsOperationalIOFlagsWithoutSideEffects(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	for _, flag := range []string{"input", "output", "mode"} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(directory, flag)
			value := path
			if flag == "mode" {
				value = "0600"
			}
			root := newGuideTestRoot(false, 0, nil)
			root.SetIn(guidePanicReader{})
			_, _, err := executeRootCommandStreams(t, root, "help", "cert", "connect", "--"+flag, value)
			if !errors.Is(err, errGuideOperationalFlag) {
				t.Fatalf("error = %v, want errGuideOperationalFlag", err)
			}
			if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("operational flag touched %q: %v", path, statErr)
			}
		})
	}
}

func TestGuideRenderingGoldens(t *testing.T) {
	t.Parallel()

	root := initializedGuideRoot()
	guides, err := loadEmbeddedGuides(root)
	require.NoError(t, err)
	tests := []struct {
		name   string
		source []byte
		rich   bool
	}{
		{name: "root.plain", source: guides[""]},
		{name: "branch.plain", source: guides["net"]},
		{name: "leaf.plain", source: guides["cert connect"]},
		{name: "markup.plain", source: []byte(guideMarkupFixture)},
		{name: "markup.rich", source: []byte(guideMarkupFixture), rich: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rendered, err := renderGuide(test.source, guideRenderOptions{width: 80, rich: test.rich})
			require.NoError(t, err)
			got := string(rendered)
			if test.rich {
				got = strings.ReplaceAll(got, "\x1b", "<ESC>")
			}
			goldenPath := filepath.Join("testdata", test.name+".golden")
			want, err := os.ReadFile(goldenPath)
			require.NoError(t, err)
			if got != string(want) {
				t.Fatalf("rendering differs from %s\n--- got ---\n%s\n--- want ---\n%s", goldenPath, got, want)
			}
		})
	}
}
