package help

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const guideMarkupFixture = "# Rendering example\n\n" +
	"Plain paragraph with *emphasis*, **strong text**, an escaped \\*literal asterisk\\*, and [documentation](https://example.test/reference?a=1&amp;b=2).\n\n" +
	"## Lists\n\n" +
	"- First unordered item.\n" +
	"- Second unordered item with **weight**.\n\n" +
	"1. First ordered item.\n" +
	"2. Second ordered item.\n\n" +
	"## Code\n\n" +
	"```sh\n" +
	"printf '$HOME * [literal](punctuation) \\\\ tail\\n'\n" +
	"```\n"

func TestGuideRichStylesIncludeSpacesInsidePhrases(t *testing.T) {
	t.Parallel()

	output, err := renderGuide([]byte("# Work with X.509 certificates\n\nUse **a private key** here.\n"), guideRenderOptions{width: 80, rich: true})
	require.NoError(t, err)
	for _, want := range []string{
		"\x1b[1;4mWork with X.509 certificates\x1b[0m\n",
		"Use \x1b[1ma private key\x1b[0m here.",
	} {
		assert.Contains(t, string(output), want, "rich phrase styling")
	}
}

func TestGuideRichLinksWrapByLabelAndCloseAtLineBoundaries(t *testing.T) {
	t.Parallel()

	const destination = "https://example.test/a/long/path"
	output, err := renderGuide([]byte("# Links\n\n[read **more** here]("+destination+"). Done.\n"), guideRenderOptions{width: 10, rich: true})
	require.NoError(t, err)
	visible := stripGuideANSI(string(output))
	assert.Equal(t, "Links\n\nread more\nhere.\nDone.\n", visible, "visible wrapping")
	for _, line := range strings.Split(string(output), "\n") {
		opens := strings.Count(line, "\x1b]8;;"+destination+"\x1b\\")
		closes := strings.Count(line, "\x1b]8;;\x1b\\")
		assert.Equal(t, opens, closes, "hyperlink remains open across line %q", line)
	}
	assert.Contains(t, string(output), "\x1b]8;;\x1b\\\x1b[0m.", "hyperlink closure")
}

func TestGuideRendererSupportsBoundedMarkdownVocabulary(t *testing.T) {
	t.Parallel()

	plain, err := renderGuide([]byte(guideMarkupFixture), guideRenderOptions{width: 80})
	require.NoError(t, err)
	plainText := string(plain)
	for _, want := range []string{
		"Rendering example\n",
		"Plain paragraph with emphasis, strong text, an escaped *literal asterisk*,",
		"documentation (https://example.test/reference?a=1&b=2).",
		"• First unordered item.",
		"1. First ordered item.",
		"  printf '$HOME * [literal](punctuation) \\\\ tail\\n'",
	} {
		assert.Contains(t, plainText, want)
	}
	for _, marker := range []string{"\x1b[", "```", "**strong text**", "[documentation]("} {
		assert.NotContains(t, plainText, marker)
	}

	rich, err := renderGuide([]byte(guideMarkupFixture), guideRenderOptions{width: 80, rich: true})
	require.NoError(t, err)
	assert.Contains(t, string(rich), "\x1b[", "rich rendering styling")
	visible := stripGuideANSI(string(rich))
	assert.NotContains(t, visible, "https://", "rich rendering shows only the link label")
	assert.Contains(t, visible, "documentation.", "rich rendering shows the link label")
}

func TestGuideRendererRejectsUnsupportedMarkdown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		markup string
	}{
		{name: "empty-document"},
		{name: "paragraph-before-heading", markup: "Paragraph.\n"},
		{name: "multiple-level-one-headings", markup: "# Guide\n\n# Another guide\n"},
		{name: "level-three-heading", markup: "# Guide\n\n### Too deep\n"},
		{name: "blockquote", markup: "# Guide\n\n> quoted\n"},
		{name: "image", markup: "# Guide\n\n![alt](image.png)\n"},
		{name: "raw-html", markup: "# Guide\n\n<div>raw</div>\n"},
		{name: "inline-code", markup: "# Guide\n\nUse `code`.\n"},
		{name: "unmatched-backtick", markup: "# Guide\n\nA stray ` character.\n"},
		{name: "indented-code", markup: "# Guide\n\n    command\n"},
		{name: "nested-list", markup: "# Guide\n\n- outer\n  - inner\n"},
		{name: "multi-block-list", markup: "# Guide\n\n- first paragraph\n\n  second paragraph\n"},
		{name: "hard-break", markup: "# Guide\n\nfirst  \nsecond\n"},
		{name: "link-title", markup: "# Guide\n\n[docs](https://example.test \"title\")\n"},
		{name: "link-control-character", markup: "# Guide\n\n[docs](https://example.test/&#27;)\n"},
		{name: "autolink", markup: "# Guide\n\n<https://example.test>\n"},
		{name: "thematic-break", markup: "# Guide\n\n---\n"},
		{name: "table", markup: "# Guide\n\n| A | B |\n| - | - |\n"},
		{name: "table-without-outer-pipes", markup: "# Guide\n\nA | B\n--- | ---\nvalue | value\n"},
		{name: "link-reference-definition", markup: "# Guide\n\nParagraph.\n\n[docs]: https://example.test\n"},
		{name: "unsupported-code-language", markup: "# Guide\n\n```markdown\ntext\n```\n"},
		{name: "empty-code-block", markup: "# Guide\n\n```text\n```\n"},
		{name: "control-character-in-prose", markup: "# Guide\n\ninvalid \x01 text\n"},
		{name: "control-character-in-code", markup: "# Guide\n\n```text\ninvalid \x01 text\n```\n"},
		{name: "tilde-fence", markup: "# Guide\n\n~~~sh\ncommand\n~~~\n"},
		{name: "open-fence", markup: "# Guide\n\n```sh\ncommand\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := renderGuide([]byte(test.markup), guideRenderOptions{width: 80})
			assert.ErrorContains(t, err, "unsupported guide Markdown")
		})
	}
}

func TestGuideRendererRejectsInvalidWidthAndPreservesCodeTabs(t *testing.T) {
	t.Parallel()

	_, err := renderGuide([]byte("# Guide\n"), guideRenderOptions{})
	require.ErrorIs(t, err, errInvalidGuideWidth)
	output, err := renderGuide([]byte("# Guide\n\n```text\none\ttwo\n```\n"), guideRenderOptions{width: 80})
	require.NoError(t, err)
	assert.Contains(t, string(output), "  one\ttwo\n", "code tab preservation")
}

func TestGuideRendererWrapsProseButPreservesCodeAndLongDestinations(t *testing.T) {
	t.Parallel()

	const longURL = "https://example.test/a/very/long/path/that/must/remain/copyable"
	source := []byte("# Narrow output\n\n" +
		"This paragraph wraps at a deliberately narrow width for deterministic output.\n\n" +
		"[long destination](" + longURL + ")\n\n" +
		"```sh\nprintf 'this command line intentionally exceeds the prose width'\n```\n")
	output, err := renderGuide(source, guideRenderOptions{width: 24})
	require.NoError(t, err)
	for _, line := range strings.Split(strings.TrimSuffix(string(output), "\n"), "\n") {
		if strings.Contains(line, "printf '") || strings.Contains(line, longURL) {
			continue
		}
		assert.LessOrEqual(t, utf8.RuneCountInString(line), 24, "line: %q", line)
	}
	assert.Contains(t, string(output), longURL, "long link destination")
	assert.Contains(t, string(output), "  printf 'this command line intentionally exceeds the prose width'", "code line")
}

func stripGuideANSI(value string) string {
	value = regexp.MustCompile(`\x1b\]8;;[^\x1b]*\x1b\\`).ReplaceAllString(value, "")
	return regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAllString(value, "")
}
