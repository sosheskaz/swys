package help

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

type (
	GuideBlockForTest     = guideBlock
	GuideBlockKindForTest = guideBlockKind
)

const (
	GuideListBlockForTest     = guideListBlock
	GuideCodeBlockForTest     = guideCodeBlock
	GuideMarkupFixtureForTest = guideMarkupFixture
)

func PresentGuideThroughPagerForTest(command *cobra.Command, dependencies Dependencies, configuration string, rendered []byte) error {
	return presentGuideThroughPager(command, dependencies, configuration, rendered)
}

func LoadEmbeddedGuidesForTest(root *cobra.Command) (map[string][]byte, error) {
	guides := make(map[string][]byte)
	var walk func(*cobra.Command) error
	walk = func(tree *cobra.Command) error {
		base := canonicalGuideKey(root, tree)
		if IsGuideCommand(tree) && tree.Parent() != root {
			if source, ok := guideSource(tree); ok {
				guides[base] = source
			}
		}
		for annotation, source := range tree.Annotations {
			if !strings.HasPrefix(annotation, guideSourceAnnotation) {
				continue
			}
			relative := strings.TrimPrefix(annotation, guideSourceAnnotation)
			key := base
			if relative != "root" {
				key = strings.TrimSpace(base + " " + strings.ReplaceAll(relative, "/", " "))
			}
			if _, exists := guides[key]; exists {
				return fmt.Errorf("%w: duplicate mapping for %q", errEmbeddedGuide, key)
			}
			guides[key] = []byte(source)
		}
		for _, child := range tree.Commands() {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root); err != nil {
		return nil, err
	}
	return guides, nil
}

func ResolveGuideTargetForTest(root *cobra.Command, path []string) (*cobra.Command, error) {
	return resolveGuideTarget(root, path)
}
func ParseGuideForTest(source []byte) ([]GuideBlockForTest, error) { return parseGuide(source) }
func RenderGuideForTest(source []byte, width int, rich bool) ([]byte, error) {
	return renderGuide(source, guideRenderOptions{width: width, rich: rich})
}

func PublicGuideChildrenForTest(command *cobra.Command) []*cobra.Command {
	return publicGuideChildren(command)
}

func CanonicalGuideKeyForTest(root, command *cobra.Command) string {
	return canonicalGuideKey(root, command)
}
func GuideDisplayPathForTest(key string) string { return guideDisplayPath(key) }
func HasGuideBlockForTest(blocks []GuideBlockForTest, kind GuideBlockKindForTest) bool {
	for _, block := range blocks {
		if block.kind == kind {
			return true
		}
	}
	return false
}
func StripGuideANSIForTest(value string) string { return stripGuideANSI(value) }
