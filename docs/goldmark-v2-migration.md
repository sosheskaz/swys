# Goldmark v2 migration

Help uses `github.com/yuin/goldmark/v2` v2.1.6. Command-result reports use the
separate text renderer and do not parse Markdown.

The migration was checked against the tagged upstream
[application migration guide](https://github.com/yuin/goldmark/blob/v2.1.6/.agent-plugins/migrate-goldmark-v1-to-v2/skills/migrate-goldmark-app-v1-to-v2/SKILL.md),
[breaking changes](https://github.com/yuin/goldmark/blob/v2.1.6/.agent-plugins/migrate-goldmark-v1-to-v2/references/breaking-changes-in-v2.md),
and [CommonMark notes](https://github.com/yuin/goldmark/blob/v2.1.6/.agent-plugins/migrate-goldmark-v1-to-v2/references/commonmark-key-points.md).

## Changes applied

| Upstream change | SwYS migration |
| --- | --- |
| Module path gains `/v2` | All help imports use v2; remove the v1 module through `go mod tidy`. |
| Parser and renderer are separate | Construct `parser.New` directly and parse source bytes. SwYS keeps its terminal renderer. |
| Parser extensions replace combined extenders | Register the built-in `extension.TableParser` so unsupported Markdown tables remain detectable and rejected. No third-party extensions are used. |
| Text values own their decoding policy | Read `Text.Value.Value(source)` and link `Destination.Value(source)`. Remove manual punctuation/entity decoding to avoid decoding twice. |
| `String` nodes removed | Handle resolved `Text` nodes instead. |
| Strong emphasis is a separate node | Handle `ast.Emphasis` and `ast.Strong` separately, preserving nested styles. |
| Fenced and indented code share `CodeBlock` | Check `CodeBlockKindFenced`; continue rejecting indented code. |
| Code body uses `text.Lines` | Read `Value.Str(source)`, preserving code punctuation, tabs, and line boundaries. Reject an empty body using its source segments. |
| Code info is a text value | Use `Info.IsEmpty` and `Info.Value`; retain the full existing language allowlist and rejection of additional info. |
| Tight-list `TextBlock` removed | Require a single `Paragraph` within each list item; retain rejection of nested and multi-block items. |
| Link title is a text value | Use `Title.IsEmpty`; continue rejecting titles and reference links. |

## Reviewed changes without consumers

SwYS does not implement Goldmark node constructors, tree mutation, AST dumps,
attributes, ID generators, delimiter parsers, parser context references, HTML
renderers, or renderer decorators. Their v2 API changes require no adapters.
The generic renderer API likewise does not affect the independent terminal
renderer. Removed utility functions beyond text decoding have no consumers.

Task lists, definition lists, footnotes, autolinks, images, raw HTML, code spans,
and extension tables remain outside the supported guide vocabulary. Their
changed AST fields and constructors do not expand that vocabulary. The table
parser is enabled for rejection, not rendering.

No v1 attribute compatibility build tag, replacement Markdown facade, or new
HTML renderer is needed.

## Behavioral validation

Retain all existing plain/rich guide goldens, public-tree coverage, unsupported
Markdown rejection cases, link boundaries, wrapping checks, code-tab preservation,
and pager/process-lifecycle tests. Add focused decoding cases for escaped
punctuation, nested entities, links, and code literals to guard against accidental
second decoding after the AST change.

The CommonMark review preserves the existing handling of inline elements across
source lines, nested emphasis, tight-list paragraphs, and code indentation. SwYS
does not introduce custom CommonMark character-class logic.
