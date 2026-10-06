package help

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"testing/fstest"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisteredGuidesStayWithTheirCommandTree(t *testing.T) {
	t.Parallel()
	newTree := func() (*cobra.Command, *cobra.Command) {
		root := &cobra.Command{Use: "swys"}
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
	require.NotNil(t, dependencies.Getenv)
	require.NotNil(t, dependencies.Terminal)
	require.NotNil(t, dependencies.Command)
	terminal, width := dependencies.Terminal(&bytes.Buffer{})
	assert.False(t, terminal, "buffer terminal")
	assert.Zero(t, width, "buffer terminal width")

	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := errors.Join(reader.Close(), writer.Close()); err != nil {
			t.Errorf("close terminal test pipe: %v", err)
		}
	})
	terminal, width = dependencies.Terminal(writer)
	assert.False(t, terminal, "pipe terminal")
	assert.Zero(t, width, "pipe terminal width")
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
	assert.Equal(t, []string{"alias-one", "alias-two", "branch", "visible"}, names)
	assert.Equal(t, "root", guideCommandPath(root, root))
	assert.Equal(t, "root branch", guideCommandPath(root, branch))
	_, err := resolveGuideTarget(root, []string{"shared"})
	assert.ErrorIs(t, err, errGuidePath, "ambiguous alias")
}
