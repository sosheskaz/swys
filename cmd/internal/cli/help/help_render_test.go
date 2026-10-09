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

func TestGuideResolvedValuesDecodeOnce(t *testing.T) {
	t.Parallel()
	source := []byte("# Decoding\n\n" +
		"Keep &amp;amp; and &#38;amp; literal. Use **strong *nested emphasis*** and \\*punctuation\\*.\n\n" +
		"[reference](https://example.test/?a=1&amp;b=2&amp;amp;c=3)\n\n" +
		"```text\n&amp;amp; \\*literal\\*\n```\n")
	for _, rich := range []bool{false, true} {
		output, err := renderGuide(source, guideRenderOptions{width: 80, rich: rich})
		require.NoError(t, err)
		visible := stripGuideANSI(string(output))
		assert.Contains(t, visible, "Keep &amp; and &amp; literal.")
		assert.Contains(t, visible, "strong nested emphasis")
		assert.Contains(t, visible, "*punctuation*")
		assert.Contains(t, visible, "  &amp;amp; \\*literal\\*\n")
		if rich {
			assert.Contains(t, string(output), "https://example.test/?a=1&b=2&amp;c=3")
		} else {
			assert.Contains(t, visible, "reference (https://example.test/?a=1&b=2&amp;c=3)")
		}
	}
}

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

func TestGuideRendererDecodesTextAndLinksOnce(t *testing.T) {
	t.Parallel()

	const source = "# Decoding\n\n" +
		"&amp;lt; &#38;lt; &#60; &lt; \\*literal\\* &#92;*escaped*\n\n" +
		"[&amp;lt;](https://example.test/?a=1&amp;b=&amp;lt;)\n"
	plain, err := renderGuide([]byte(source), guideRenderOptions{width: 80})
	require.NoError(t, err)
	assert.Equal(t, "Decoding\n\n&lt; &lt; < < *literal* \\escaped\n\n"+
		"&lt; (https://example.test/?a=1&b=&lt;)\n", string(plain))

	rich, err := renderGuide([]byte(source), guideRenderOptions{width: 80, rich: true})
	require.NoError(t, err)
	assert.Equal(t, "Decoding\n\n&lt; &lt; < < *literal* \\escaped\n\n&lt;\n", stripGuideANSI(string(rich)))
	assert.Contains(t, string(rich), "\x1b]8;;https://example.test/?a=1&b=&lt;\x1b\\")
}

func TestGuideRendererPreservesNestedEmphasis(t *testing.T) {
	t.Parallel()

	output, err := renderGuide([]byte("# Styles\n\n***both*** and **bold *both* bold**.\n"), guideRenderOptions{width: 80, rich: true})
	require.NoError(t, err)
	assert.Equal(t, "Styles\n\nboth and bold both bold.\n", stripGuideANSI(string(output)))
	assert.Contains(t, string(output), "\x1b[1;3mboth\x1b[0m")
	assert.Contains(t, string(output), "\x1b[1mbold ")
}

func TestGuideRendererUsesV2AmbiguousEmphasis(t *testing.T) {
	t.Parallel()

	for _, rich := range []bool{false, true} {
		output, err := renderGuide([]byte("# Styles\n\n0**0* *0**\n"), guideRenderOptions{width: 80, rich: rich})
		require.NoError(t, err)
		assert.Equal(t, "Styles\n\n0**0* 0*\n", stripGuideANSI(string(output)), "rich: %t", rich)
	}
}

func TestGuideRendererPreservesLiteralCodeAndLineEndings(t *testing.T) {
	t.Parallel()

	const source = "# Code\r\n\r\n```sh\r\none\ttwo &amp; &#60; \\*literal\\*\r\n\r\nlast\r\n```\r\n"
	const want = "Code\n\n  one\ttwo &amp; &#60; \\*literal\\*\n  \n  last\n"
	for _, rich := range []bool{false, true} {
		output, err := renderGuide([]byte(source), guideRenderOptions{width: 80, rich: rich})
		require.NoError(t, err)
		assert.Equal(t, want, stripGuideANSI(string(output)), "rich: %t", rich)
	}
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
		{name: "html-block-newline", markup: "# Guide\n\n<div\n*raw*\n"},
		{name: "html-block-crlf", markup: "# Guide\r\n\r\n<DIV\r\n*raw*\r\n"},
		{name: "html-closing-block", markup: "# Guide\n\n</table\n*raw*\n"},
		{name: "html-block-interrupts-paragraph", markup: "# Guide\n\nText\n<div\n*raw*\n"},
		{name: "html-block-before-setext-underline", markup: "# Guide\n\n<div\n---\n"},
		{name: "html-block-in-list", markup: "# Guide\n\n- <div\n  *raw*\n"},
		{name: "inline-code", markup: "# Guide\n\nUse `code`.\n"},
		{name: "unmatched-backtick", markup: "# Guide\n\nA stray ` character.\n"},
		{name: "indented-code", markup: "# Guide\n\n    command\n"},
		{name: "empty-list-item", markup: "# Guide\n\n- item\n-\n"},
		{name: "empty-list-item-crlf", markup: "# Guide\r\n\r\n- item\r\n-\r\n"},
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
		{name: "code-language-with-metadata", markup: "# Guide\n\n```sh extra\ntext\n```\n"},
		{name: "encoded-code-language", markup: "# Guide\n\n```s&#104;\ntext\n```\n"},
		{name: "empty-code-block", markup: "# Guide\n\n```text\n```\n"},
		{name: "control-character-in-prose", markup: "# Guide\n\ninvalid \x01 text\n"},
		{name: "encoded-control-character-in-prose", markup: "# Guide\n\ninvalid &#27; text\n"},
		{name: "stray-cr-before-crlf-in-code", markup: "# Guide\n\n```text\nx\r\r\n```\n"},
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

func TestGuideRendererPreservesLiteralTagLikeText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		markup string
		want   string
	}{
		{name: "unknown-tag", markup: "# Guide\n\n<widget\ntext\n", want: "Guide\n\n<widget text\n"},
		{name: "escaped-tag", markup: "# Guide\n\n\\<div\ntext\n", want: "Guide\n\n<div text\n"},
		{name: "heading", markup: "# Guide <div\n", want: "Guide <div\n"},
		{name: "inline", markup: "# Guide\n\nLiteral <div\n", want: "Guide\n\nLiteral <div\n"},
		{name: "indented-continuation", markup: "# Guide\n\nLiteral\n    <div\n", want: "Guide\n\nLiteral <div\n"},
		{name: "code", markup: "# Guide\n\n```text\n<div\n```\n", want: "Guide\n\n  <div\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output, err := renderGuide([]byte(test.markup), guideRenderOptions{width: 80})
			require.NoError(t, err)
			assert.Equal(t, test.want, string(output))
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

func TestGuideRendererWrapsOnlyRichProse(t *testing.T) {
	t.Parallel()

	const longURL = "https://example.test/a/very/long/path/that/must/remain/copyable"
	const heading = "Narrow output with a longer heading"
	const paragraph = "This paragraph wraps only in rich style, even when its Markdown source\ncontains a soft line break."
	const item = "A list item also stays on one line in plain style."
	const code = "  printf 'this command line intentionally exceeds the prose width'"
	source := []byte("# " + heading + "\n\n" + paragraph + "\n\n- " + item + "\n\n" +
		"[long destination](" + longURL + ")\n\n" +
		"```sh\nprintf 'this command line intentionally exceeds the prose width'\n```\n")
	wantPlain := heading + "\n\n" + strings.ReplaceAll(paragraph, "\n", " ") + "\n\n• " + item +
		"\n\nlong destination (" + longURL + ")\n\n" + code + "\n"
	for _, width := range []int{1, 24, 80} {
		output, err := renderGuide(source, guideRenderOptions{width: width})
		require.NoError(t, err)
		assert.Equal(t, wantPlain, string(output), "plain width: %d", width)
	}

	output, err := renderGuide(source, guideRenderOptions{width: 24, rich: true})
	require.NoError(t, err)
	visible := stripGuideANSI(string(output))
	for _, line := range strings.Split(strings.TrimSuffix(visible, "\n"), "\n") {
		if strings.Contains(line, "printf '") {
			continue
		}
		assert.LessOrEqual(t, utf8.RuneCountInString(line), 24, "line: %q", line)
	}
	assert.Contains(t, string(output), longURL, "OSC 8 destination")
	assert.Contains(t, visible, code, "code line")
}

func stripGuideANSI(value string) string {
	value = regexp.MustCompile(`\x1b\]8;;[^\x1b]*\x1b\\`).ReplaceAllString(value, "")
	return regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAllString(value, "")
}
