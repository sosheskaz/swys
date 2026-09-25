package help

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisteredGuidesStayWithTheirCommandTree(t *testing.T) {
	t.Parallel()
	newTree := func() (*cobra.Command, *cobra.Command) {
		root := &cobra.Command{Use: "npc"}
		child := &cobra.Command{Use: "net"}
		root.AddCommand(child)
		return root, child
	}
	firstRoot, firstChild := newTree()
	secondRoot, secondChild := newTree()
	require.NoError(t, RegisterGuides(firstRoot, fstest.MapFS{"guides/net.md": &fstest.MapFile{Data: []byte("# First\n")}}))
	require.NoError(t, RegisterGuides(secondRoot, fstest.MapFS{"guides/net.md": &fstest.MapFile{Data: []byte("# Second\n")}}))
	firstSource, firstPresent := guideSource(firstChild)
	secondSource, secondPresent := guideSource(secondChild)
	assert.True(t, firstPresent, "first command guide")
	assert.Equal(t, "# First\n", string(firstSource), "first command guide")
	assert.True(t, secondPresent, "second command guide")
	assert.Equal(t, "# Second\n", string(secondSource), "second command guide")
}

func TestGuideDependenciesDefaultAndDetectNonterminalWriters(t *testing.T) {
	t.Parallel()

	dependencies := (Dependencies{}).WithDefaults()
	if dependencies.Getenv == nil || dependencies.Terminal == nil || dependencies.Command == nil {
		t.Fatal("default guide dependencies are incomplete")
	}
	if terminal, width := dependencies.Terminal(&bytes.Buffer{}); terminal || width != 0 {
		t.Fatalf("buffer terminal result = (%t, %d), want (false, 0)", terminal, width)
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := errors.Join(reader.Close(), writer.Close()); err != nil {
			t.Errorf("close terminal test pipe: %v", err)
		}
	})
	if terminal, width := dependencies.Terminal(writer); terminal || width != 0 {
		t.Fatalf("pipe terminal result = (%t, %d), want (false, 0)", terminal, width)
	}
}

func TestPublicGuideTreeExcludesInternalCommandsAndRejectsAmbiguousAliases(t *testing.T) {
	t.Parallel()

	root := &cobra.Command{Use: "root"}
	visible := &cobra.Command{Use: "visible", Run: func(*cobra.Command, []string) {}}
	branch := &cobra.Command{Use: "branch"}
	branch.AddCommand(&cobra.Command{Use: "leaf", Run: func(*cobra.Command, []string) {}})
	hidden := &cobra.Command{Use: "hidden", Hidden: true, Run: func(*cobra.Command, []string) {}}
	deprecated := &cobra.Command{Use: "deprecated", Deprecated: "removed", Run: func(*cobra.Command, []string) {}}
	inert := &cobra.Command{Use: "inert"}
	aliasOne := &cobra.Command{Use: "alias-one", Aliases: []string{"shared"}, Run: func(*cobra.Command, []string) {}}
	aliasTwo := &cobra.Command{Use: "alias-two", Aliases: []string{"shared"}, Run: func(*cobra.Command, []string) {}}
	root.AddCommand(visible, branch, hidden, deprecated, inert, aliasOne, aliasTwo)

	children := publicGuideChildren(root)
	names := make([]string, 0, len(children))
	for _, child := range children {
		names = append(names, child.Name())
	}
	if want := []string{"alias-one", "alias-two", "branch", "visible"}; !slices.Equal(names, want) {
		t.Fatalf("public children = %q, want %q", names, want)
	}
	if got := guideCommandPath(root, root); got != "root" {
		t.Fatalf("root command path = %q, want root", got)
	}
	if got := guideCommandPath(root, branch); got != "root branch" {
		t.Fatalf("branch command path = %q, want root branch", got)
	}
	if _, err := resolveGuideTarget(root, []string{"shared"}); !errors.Is(err, errGuidePath) {
		t.Fatalf("ambiguous alias error = %v, want errGuidePath", err)
	}
}
