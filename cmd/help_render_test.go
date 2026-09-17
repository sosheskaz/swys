package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
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
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"\x1b[1;4mWork with X.509 certificates\x1b[0m\n",
		"Use \x1b[1ma private key\x1b[0m here.",
	} {
		if !bytes.Contains(output, []byte(want)) {
			t.Errorf("rich output does not preserve phrase styling %q: %q", want, output)
		}
	}
}

func TestGuideRichLinksWrapByLabelAndCloseAtLineBoundaries(t *testing.T) {
	t.Parallel()

	const destination = "https://example.test/a/long/path"
	output, err := renderGuide([]byte("# Links\n\n[read **more** here]("+destination+"). Done.\n"), guideRenderOptions{width: 10, rich: true})
	if err != nil {
		t.Fatal(err)
	}
	visible := stripGuideANSI(string(output))
	if visible != "Links\n\nread more\nhere.\nDone.\n" {
		t.Fatalf("hyperlink controls or URL changed visible wrapping: %q", visible)
	}
	for _, line := range strings.Split(string(output), "\n") {
		opens := strings.Count(line, "\x1b]8;;"+destination+"\x1b\\")
		closes := strings.Count(line, "\x1b]8;;\x1b\\")
		if opens != closes {
			t.Errorf("hyperlink remains open across a line boundary: %q", line)
		}
	}
	if !strings.Contains(string(output), "\x1b]8;;\x1b\\\x1b[0m.") {
		t.Fatalf("hyperlink includes punctuation after its label: %q", output)
	}
}

func TestRootGuideHighlightsCommandKeywords(t *testing.T) {
	t.Parallel()

	output, _, err := executeRootCommandStreams(t, newGuideTestRoot(false, 0, nil), "help", "--rich")
	if err != nil {
		t.Fatal(err)
	}
	for _, keyword := range []string{"dns", "http", "net", "cert", "key", "aes", "hash"} {
		if !strings.Contains(output, "• \x1b[1m"+keyword+"\x1b[0m ") {
			t.Errorf("command keyword %q has no distinct styling", keyword)
		}
	}
}

func TestGuideRendererSupportsBoundedMarkdownVocabulary(t *testing.T) {
	t.Parallel()

	plain, err := renderGuide([]byte(guideMarkupFixture), guideRenderOptions{width: 80})
	if err != nil {
		t.Fatal(err)
	}
	plainText := string(plain)
	for _, want := range []string{
		"Rendering example\n",
		"Plain paragraph with emphasis, strong text, an escaped *literal asterisk*,",
		"documentation (https://example.test/reference?a=1&b=2).",
		"• First unordered item.",
		"1. First ordered item.",
		"  printf '$HOME * [literal](punctuation) \\\\ tail\\n'",
	} {
		if !strings.Contains(plainText, want) {
			t.Errorf("plain rendering does not contain %q:\n%s", want, plainText)
		}
	}
	for _, marker := range []string{"\x1b[", "```", "**strong text**", "[documentation]("} {
		if strings.Contains(plainText, marker) {
			t.Errorf("plain rendering retained presentation marker %q:\n%s", marker, plainText)
		}
	}

	rich, err := renderGuide([]byte(guideMarkupFixture), guideRenderOptions{width: 80, rich: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rich, []byte("\x1b[")) {
		t.Fatalf("rich rendering has no ANSI styling: %q", rich)
	}
	if visible := stripGuideANSI(string(rich)); strings.Contains(visible, "https://") || !strings.Contains(visible, "documentation.") {
		t.Fatalf("rich rendering must show only the link label: %q", visible)
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
			if _, err := renderGuide([]byte(test.markup), guideRenderOptions{width: 80}); err == nil || !strings.Contains(err.Error(), "unsupported guide Markdown") {
				t.Fatalf("error = %v, want unsupported Markdown rejection", err)
			}
		})
	}
}

func TestGuideRendererRejectsInvalidWidthAndPreservesCodeTabs(t *testing.T) {
	t.Parallel()

	if _, err := renderGuide([]byte("# Guide\n"), guideRenderOptions{}); !errors.Is(err, errInvalidGuideWidth) {
		t.Fatalf("invalid width error = %v, want errInvalidGuideWidth", err)
	}
	output, err := renderGuide([]byte("# Guide\n\n```text\none\ttwo\n```\n"), guideRenderOptions{width: 80})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output, []byte("  one\ttwo\n")) {
		t.Fatalf("code tab was not preserved: %q", output)
	}
}

func TestGuideRendererWrapsProseButPreservesCodeAndLongDestinations(t *testing.T) {
	t.Parallel()

	const longURL = "https://example.test/a/very/long/path/that/must/remain/copyable"
	source := []byte("# Narrow output\n\n" +
		"This paragraph wraps at a deliberately narrow width for deterministic output.\n\n" +
		"[long destination](" + longURL + ")\n\n" +
		"```sh\nprintf 'this command line intentionally exceeds the prose width'\n```\n")
	output, err := renderGuide(source, guideRenderOptions{width: 24})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(output), "\n"), "\n") {
		if strings.Contains(line, "printf '") || strings.Contains(line, longURL) {
			continue
		}
		if utf8.RuneCountInString(line) > 24 {
			t.Errorf("line exceeds width 24: %q", line)
		}
	}
	if !strings.Contains(string(output), longURL) {
		t.Fatalf("long link destination was split:\n%s", output)
	}
	if !strings.Contains(string(output), "  printf 'this command line intentionally exceeds the prose width'") {
		t.Fatalf("code line was changed:\n%s", output)
	}
}

func TestGuideRenderingGoldens(t *testing.T) {
	t.Parallel()

	guides, err := loadEmbeddedGuides()
	if err != nil {
		t.Fatal(err)
	}
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
			if err != nil {
				t.Fatal(err)
			}
			got := string(rendered)
			if test.rich {
				got = strings.ReplaceAll(got, "\x1b", "<ESC>")
			}
			goldenPath := filepath.Join("testdata", "help", test.name+".golden")
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Fatalf("rendering differs from %s\n--- got ---\n%s\n--- want ---\n%s", goldenPath, got, want)
			}
		})
	}
}

func stripGuideANSI(value string) string {
	value = regexp.MustCompile(`\x1b\]8;;[^\x1b]*\x1b\\`).ReplaceAllString(value, "")
	return regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAllString(value, "")
}
