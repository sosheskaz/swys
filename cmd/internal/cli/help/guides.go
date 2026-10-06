package help

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/spf13/cobra"
)

const (
	guideSourceAnnotation = "npc.help.guide.source."
	rootGuidePath         = "root"
)

// RegisterGuides binds embedded Markdown to canonical paths within tree.
// Sources stay on tree so replacing a generated child retains its guide.
func RegisterGuides(tree *cobra.Command, files fs.FS) error {
	type binding struct {
		key    string
		source string
	}
	var pending []binding
	err := fs.WalkDir(files, "guides", func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk embedded guide %q: %w", filePath, walkErr)
		}
		if entry.IsDir() || path.Ext(filePath) != ".md" {
			return nil
		}
		contents, err := fs.ReadFile(files, filePath)
		if err != nil {
			return fmt.Errorf("read embedded guide %q: %w", filePath, err)
		}
		if len(bytes.TrimSpace(contents)) == 0 {
			return fmt.Errorf("%w: guide %q is empty", errEmbeddedGuide, filePath)
		}
		key := strings.TrimSuffix(strings.TrimPrefix(filePath, "guides/"), ".md")
		if !canonicalGuidePathExists(tree, key) {
			return fmt.Errorf("%w: guide %q has no canonical command", errEmbeddedGuide, filePath)
		}
		annotation := guideSourceAnnotation + key
		if tree.Annotations[annotation] != "" {
			return fmt.Errorf("%w: duplicate mapping for %q", errEmbeddedGuide, key)
		}
		pending = append(pending, binding{key: annotation, source: string(contents)})
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk embedded guides: %w", err)
	}
	if tree.Annotations == nil {
		tree.Annotations = make(map[string]string)
	}
	for _, guide := range pending {
		tree.Annotations[guide.key] = guide.source
	}
	return nil
}

func canonicalGuidePathExists(tree *cobra.Command, key string) bool {
	if key == rootGuidePath {
		return true
	}
	current := tree
	for _, name := range strings.Split(key, "/") {
		if name == "" || name == rootGuidePath {
			return false
		}
		var child *cobra.Command
		for _, candidate := range current.Commands() {
			if candidate.Name() == name {
				child = candidate
				break
			}
		}
		if child == nil {
			return false
		}
		current = child
	}
	return true
}

func guideSource(command *cobra.Command) ([]byte, bool) {
	// Scoped help commands share the root help guide rather than duplicate it.
	if IsGuideCommand(command) {
		source, ok := command.Root().Annotations[guideSourceAnnotation+"help"]
		return []byte(source), ok
	}
	for tree := command; tree != nil; tree = tree.Parent() {
		key := strings.ReplaceAll(canonicalGuideKey(tree, command), " ", "/")
		if key == "" {
			key = rootGuidePath
		}
		if source, ok := tree.Annotations[guideSourceAnnotation+key]; ok {
			return []byte(source), true
		}
	}
	return nil, false
}
