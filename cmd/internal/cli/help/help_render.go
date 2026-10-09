package help

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/yuin/goldmark/v2/ast"
	"github.com/yuin/goldmark/v2/extension"
	"github.com/yuin/goldmark/v2/parser"
)

type guideRenderOptions struct {
	width int
	rich  bool
}

type guideBlockKind uint8

const (
	guideHeadingBlock guideBlockKind = iota + 1
	guideParagraphBlock
	guideListBlock
	guideCodeBlock
)

type guideBlock struct {
	spans     []guideSpan
	items     [][]guideSpan
	codeLines []string
	heading   int
	listStart int
	kind      guideBlockKind
	ordered   bool
}

type guideStyle uint8

const (
	guideStyleBold guideStyle = 1 << iota
	guideStyleItalic
	guideStyleUnderline
	guideStyleLink
	guideStyleCode
)

type guideSpan struct {
	text      string
	link      string
	style     guideStyle
	plainOnly bool
}

type guideCell struct {
	link  string
	rune  rune
	style guideStyle
}

func renderGuide(source []byte, options guideRenderOptions) ([]byte, error) {
	if options.width <= 0 {
		return nil, fmt.Errorf("%w: %d", errInvalidGuideWidth, options.width)
	}
	blocks, err := parseGuide(source)
	if err != nil {
		return nil, err
	}

	var output bytes.Buffer
	for index, block := range blocks {
		if index > 0 {
			output.WriteByte('\n')
		}
		switch block.kind {
		case guideHeadingBlock:
			style := guideStyleBold
			if block.heading == 1 {
				style |= guideStyleUnderline
			}
			writeWrappedGuideSpans(&output, addGuideStyle(block.spans, style), "", "", options)
		case guideParagraphBlock:
			writeWrappedGuideSpans(&output, block.spans, "", "", options)
		case guideListBlock:
			for itemIndex, item := range block.items {
				prefix := "• "
				if block.ordered {
					prefix = strconv.Itoa(block.listStart+itemIndex) + ". "
				}
				writeWrappedGuideSpans(&output, item, prefix, strings.Repeat(" ", utf8.RuneCountInString(prefix)), options)
			}
		case guideCodeBlock:
			for _, line := range block.codeLines {
				output.WriteString("  ")
				writeStyledGuideCells(&output, cellsFromText(line, guideStyleCode), options.rich)
				output.WriteByte('\n')
			}
		default:
			return nil, fmt.Errorf("%w kind %d", errUnsupportedGuideBlock, block.kind)
		}
	}
	return output.Bytes(), nil
}

func parseGuide(source []byte) ([]guideBlock, error) {
	if !utf8.Valid(source) {
		return nil, errorsNewGuideMarkdown("source is not valid UTF-8")
	}
	if err := validateGuideSourceSyntax(source); err != nil {
		return nil, err
	}
	document := parser.New(parser.WithExtensions(extension.TableParser)).Parse(source)
	blocks := make([]guideBlock, 0, document.ChildCount())
	levelOneHeadings := 0
	for node := document.FirstChild(); node != nil; node = node.NextSibling() {
		block, err := guideBlockFromNode(source, node)
		if err != nil {
			return nil, err
		}
		if block.kind == guideHeadingBlock && block.heading == 1 {
			levelOneHeadings++
		}
		blocks = append(blocks, block)
	}
	if len(blocks) == 0 {
		return nil, errorsNewGuideMarkdown("document is empty")
	}
	if blocks[0].kind != guideHeadingBlock || blocks[0].heading != 1 {
		return nil, errorsNewGuideMarkdown("document must begin with one level-one heading")
	}
	if levelOneHeadings != 1 {
		return nil, errorsNewGuideMarkdown("document must contain exactly one level-one heading")
	}
	return blocks, nil
}

func validateGuideSourceSyntax(source []byte) error {
	inCodeBlock := false
	for _, line := range strings.Split(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inCodeBlock = !inCodeBlock
			continue
		}
		if inCodeBlock {
			continue
		}
		if strings.HasPrefix(trimmed, "~~~") {
			return errorsNewGuideMarkdown("code blocks must use backtick fences")
		}
		if strings.Contains(line, "`") {
			return errorsNewGuideMarkdown("inline code and unmatched backticks are not supported")
		}
		if strings.HasPrefix(trimmed, "[") {
			if closingBracket := strings.Index(trimmed, "]:"); closingBracket > 1 {
				return errorsNewGuideMarkdown("link reference definitions are not supported")
			}
		}
	}
	if inCodeBlock {
		return errorsNewGuideMarkdown("code block fence is not closed")
	}
	return nil
}

func guideBlockFromNode(source []byte, node ast.Node) (guideBlock, error) {
	switch typed := node.(type) {
	case *ast.Heading:
		if typed.Level < 1 || typed.Level > 2 {
			return guideBlock{}, errorsNewGuideMarkdown("only level-one and level-two headings are supported")
		}
		spans, err := guideInlineSpans(source, typed, 0)
		if err != nil {
			return guideBlock{}, err
		}
		return guideBlock{kind: guideHeadingBlock, spans: spans, heading: typed.Level}, nil
	case *ast.Paragraph:
		spans, err := guideInlineSpans(source, typed, 0)
		if err != nil {
			return guideBlock{}, err
		}
		return guideBlock{kind: guideParagraphBlock, spans: spans}, nil
	case *ast.List:
		return guideListFromNode(source, typed)
	case *ast.CodeBlock:
		return guideCodeFromNode(source, typed)
	default:
		return guideBlock{}, errorsNewGuideMarkdown("unsupported block " + node.Kind().String())
	}
}

func guideListFromNode(source []byte, list *ast.List) (guideBlock, error) {
	block := guideBlock{
		kind:      guideListBlock,
		ordered:   list.IsOrdered(),
		listStart: list.Start,
	}
	for itemNode := list.FirstChild(); itemNode != nil; itemNode = itemNode.NextSibling() {
		item, ok := itemNode.(*ast.ListItem)
		if !ok {
			return guideBlock{}, errorsNewGuideMarkdown("list contains an unsupported child")
		}
		contents := item.FirstChild()
		if contents == nil || contents.NextSibling() != nil {
			return guideBlock{}, errorsNewGuideMarkdown("list items must contain exactly one paragraph")
		}
		switch contents.(type) {
		case *ast.Paragraph:
		default:
			return guideBlock{}, errorsNewGuideMarkdown("nested or multi-block list items are not supported")
		}
		spans, err := guideInlineSpans(source, contents, 0)
		if err != nil {
			return guideBlock{}, err
		}
		block.items = append(block.items, spans)
	}
	if len(block.items) == 0 {
		return guideBlock{}, errorsNewGuideMarkdown("lists must contain at least one item")
	}
	return block, nil
}

func guideCodeFromNode(source []byte, code *ast.CodeBlock) (guideBlock, error) {
	if code.CodeBlockKind != ast.CodeBlockKindFenced {
		return guideBlock{}, errorsNewGuideMarkdown("indented code blocks are not supported")
	}
	if !code.Info.IsEmpty() {
		language := strings.TrimSpace(string(code.Info.Bytes(source)))
		switch language {
		case "", "sh", "bash", "fish", "powershell", "text":
		default:
			return guideBlock{}, errorsNewGuideMarkdown("unsupported code-block language " + strconv.Quote(language))
		}
	}
	block := guideBlock{kind: guideCodeBlock}
	for _, segment := range code.Value.Segments() {
		line := segment.Str(source)
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		if err := validateGuideText(line, true); err != nil {
			return guideBlock{}, err
		}
		block.codeLines = append(block.codeLines, line)
	}
	if len(block.codeLines) == 0 {
		return guideBlock{}, errorsNewGuideMarkdown("code blocks must not be empty")
	}
	return block, nil
}

func guideInlineSpans(source []byte, parent ast.Node, inherited guideStyle) ([]guideSpan, error) {
	var spans []guideSpan
	for node := parent.FirstChild(); node != nil; node = node.NextSibling() {
		nodeSpans, err := guideInlineNodeSpans(source, node, inherited)
		if err != nil {
			return nil, err
		}
		spans = append(spans, nodeSpans...)
	}
	if len(spans) == 0 {
		return nil, errorsNewGuideMarkdown("headings, paragraphs, and list items must not be empty")
	}
	return spans, nil
}

func guideInlineNodeSpans(source []byte, node ast.Node, inherited guideStyle) ([]guideSpan, error) {
	switch typed := node.(type) {
	case *ast.Text:
		return guideTextNodeSpans(source, typed, inherited)
	case *ast.Emphasis:
		return guideInlineSpans(source, typed, inherited|guideStyleItalic)
	case *ast.Strong:
		return guideInlineSpans(source, typed, inherited|guideStyleBold)
	case *ast.Link:
		return guideLinkNodeSpans(source, typed, inherited)
	case *ast.CodeSpan:
		return nil, errorsNewGuideMarkdown("inline code is not supported; use a fenced code block")
	default:
		return nil, errorsNewGuideMarkdown("unsupported inline " + node.Kind().String())
	}
}

func guideTextNodeSpans(source []byte, node *ast.Text, inherited guideStyle) ([]guideSpan, error) {
	if node.HardLineBreak() {
		return nil, errorsNewGuideMarkdown("hard line breaks are not supported")
	}
	textValue := node.Value.Value(source)
	if node.SoftLineBreak() {
		textValue += " "
	}
	if err := validateGuideText(textValue, false); err != nil {
		return nil, err
	}
	return appendGuideSpan(nil, textValue, inherited), nil
}

func guideLinkNodeSpans(source []byte, node *ast.Link, inherited guideStyle) ([]guideSpan, error) {
	if node.Reference != nil || !node.Title.IsEmpty() {
		return nil, errorsNewGuideMarkdown("only inline links without titles are supported")
	}
	children, err := guideInlineSpans(source, node, inherited|guideStyleLink|guideStyleUnderline)
	if err != nil {
		return nil, err
	}
	destination := node.Destination.Value(source)
	if destination == "" {
		return nil, errorsNewGuideMarkdown("links must have a destination")
	}
	if err := validateGuideText(destination, false); err != nil {
		return nil, err
	}
	for index := range children {
		children[index].link = destination
	}
	return append(children, guideSpan{text: " (" + destination + ")", style: inherited, plainOnly: true}), nil
}

func validateGuideText(value string, allowTab bool) error {
	for _, character := range value {
		if allowTab && character == '\t' {
			continue
		}
		if unicode.IsControl(character) {
			return errorsNewGuideMarkdown(fmt.Sprintf("control character U+%04X is not supported", character))
		}
	}
	return nil
}

func errorsNewGuideMarkdown(message string) error {
	return fmt.Errorf("%w: %s", errUnsupportedGuideMarkdown, message)
}

func appendGuideSpan(spans []guideSpan, value string, style guideStyle) []guideSpan {
	if value == "" {
		return spans
	}
	if len(spans) > 0 && spans[len(spans)-1].style == style && spans[len(spans)-1].link == "" && !spans[len(spans)-1].plainOnly {
		spans[len(spans)-1].text += value
		return spans
	}
	return append(spans, guideSpan{text: value, style: style})
}

func addGuideStyle(spans []guideSpan, style guideStyle) []guideSpan {
	styled := make([]guideSpan, len(spans))
	for index, span := range spans {
		styled[index] = span
		styled[index].style |= style
	}
	return styled
}

func writeWrappedGuideSpans(
	output *bytes.Buffer,
	spans []guideSpan,
	firstPrefix string,
	continuationPrefix string,
	options guideRenderOptions,
) {
	words := guideWords(spans, options.rich)
	output.WriteString(firstPrefix)
	var line []guideCell
	lineWidth := utf8.RuneCountInString(firstPrefix)
	prefixWidth := lineWidth
	for wordIndex, word := range words {
		space := wordIndex > 0 && lineWidth > prefixWidth
		wordWidth := len(word)
		if options.rich && space && lineWidth+1+wordWidth > options.width {
			writeStyledGuideCells(output, line, options.rich)
			line = nil
			output.WriteByte('\n')
			output.WriteString(continuationPrefix)
			lineWidth = utf8.RuneCountInString(continuationPrefix)
			prefixWidth = lineWidth
			space = false
		}
		if space {
			previous := line[len(line)-1]
			separator := guideCell{rune: ' ', style: previous.style & word[0].style}
			if previous.link == word[0].link {
				separator.link = previous.link
			}
			line = append(line, separator)
			lineWidth++
		}
		line = append(line, word...)
		lineWidth += wordWidth
	}
	writeStyledGuideCells(output, line, options.rich)
	output.WriteByte('\n')
}

func guideWords(spans []guideSpan, rich bool) [][]guideCell {
	var words [][]guideCell
	var current []guideCell
	for _, span := range spans {
		if rich && span.plainOnly {
			continue
		}
		for _, character := range span.text {
			if unicode.IsSpace(character) {
				if len(current) > 0 {
					words = append(words, current)
					current = nil
				}
				continue
			}
			current = append(current, guideCell{rune: character, style: span.style, link: span.link})
		}
	}
	if len(current) > 0 {
		words = append(words, current)
	}
	return words
}

func cellsFromText(value string, style guideStyle) []guideCell {
	cells := make([]guideCell, 0, utf8.RuneCountInString(value))
	for _, character := range value {
		cells = append(cells, guideCell{rune: character, style: style})
	}
	return cells
}

func writeStyledGuideCells(output *bytes.Buffer, cells []guideCell, rich bool) {
	if !rich {
		for _, cell := range cells {
			output.WriteRune(cell.rune)
		}
		return
	}
	active := guideStyle(0)
	activeLink := ""
	for _, cell := range cells {
		if cell.link != activeLink {
			writeGuideHyperlink(output, cell.link)
			activeLink = cell.link
		}
		if cell.style != active {
			if active != 0 {
				output.WriteString("\x1b[0m")
			}
			if cell.style != 0 {
				output.WriteString(guideANSIStart(cell.style))
			}
			active = cell.style
		}
		output.WriteRune(cell.rune)
	}
	if active != 0 {
		output.WriteString("\x1b[0m")
	}
	if activeLink != "" {
		writeGuideHyperlink(output, "")
	}
}

func writeGuideHyperlink(output *bytes.Buffer, destination string) {
	output.WriteString("\x1b]8;;")
	output.WriteString(destination)
	output.WriteString("\x1b\\")
}

func guideANSIStart(style guideStyle) string {
	codes := make([]string, 0, 4)
	if style&guideStyleBold != 0 {
		codes = append(codes, "1")
	}
	if style&guideStyleItalic != 0 {
		codes = append(codes, "3")
	}
	if style&guideStyleUnderline != 0 {
		codes = append(codes, "4")
	}
	if style&guideStyleCode != 0 {
		codes = append(codes, "36")
	} else if style&guideStyleLink != 0 {
		codes = append(codes, "34")
	}
	return "\x1b[" + strings.Join(codes, ";") + "m"
}
