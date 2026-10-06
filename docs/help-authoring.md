# Help guide authoring

NPC ships curated usage guides inside the binary. The guides orient readers toward a task and a useful first invocation. Cobra's generated reference remains the source for every argument, flag, alias, and default.

## Audience and scope

Write for experienced operators who want a quick working example and for readers with basic command-line familiarity who need help choosing the next command. Use precise task language. Name a concept when the reader may need to learn it and link selectively to an authoritative explanation; do not teach networking, cryptography, certificate formats, or protocol internals inside a guide.

The 80/20 rule limits depth on each page. It does not permit missing pages: the root and every public command path, including generated help and completion commands, have a guide. Hidden and deprecated commands are excluded because they are not part of the discoverable public tree. Aliases reuse the canonical command's guide and never receive separate files. Scoped help commands, such as `cert help`, share the root `help` guide and its `npc help --help` reference. Register them only on non-runnable command groups; their guide paths and completions are relative to the group.

## Editorial contract

### Root page

Establish NPC's mental model and get the reader started. Cover tool conventions, how to select a command family, common input and output patterns, a few useful examples, and directions to guides and root reference help.

### Branch page

Help the reader choose an operation. Describe the family, list selected children and their practical differences, show a useful workflow, and point to more specific guides. Use bold command names in chooser lists so rich output distinguishes the keywords from their explanations. Apply this contract at every intermediate level, such as net connect. A future runnable command with children remains a branch for editorial purposes.

### Leaf page

Help the reader accomplish common tasks. Explain what the command does, show a few invocations, state setup or input-file prerequisites, call out consequential surprises, and end with related guides when useful plus the exact reference-help invocation.

Every page includes the corresponding reference command. Use npc --help for the root guide and npc followed by the canonical command path and --help for command guides. Do not reproduce every flag.

## Supported Markdown

Guide files use UTF-8 and a deliberately bounded CommonMark vocabulary parsed by Goldmark:

- One level-one heading at the start of the file, followed by level-two section headings.
- Paragraphs with single or double emphasis.
- Flat unordered or ordered lists whose items contain one paragraph.
- Inline links written with visible labels and destinations, without titles or reference definitions.
- Fenced code blocks using backticks. The optional language is sh, bash, fish, powershell, or text.

Inline code, hard line breaks, nested or multi-paragraph list items, level-three or deeper headings, indented code, block quotes, thematic breaks, auto-links, images, tables, raw HTML, custom extensions, and tilde fences are unsupported. Rendering rejects unsupported parsed nodes instead of printing Markdown source.

## Page layout and file mapping

Each command family embeds guides beside its constructor. `root.md` names the
family command; child filenames mirror canonical paths relative to that family.
The root embeds its own and generated-command guides:

```text
cmd/guides/root.md                               npc help
cmd/guides/help.md                               npc help help
cmd/guides/completion/bash.md                    npc help completion bash
cmd/internal/commands/net/guides/root.md         npc help net
cmd/internal/commands/net/guides/connect.md      npc help net connect
cmd/internal/commands/net/guides/listen.md       npc help net listen
```

The constructor registers its embedded guides on its command subtree; the root
registers its guides after creating generated commands. The relative filesystem
path is the canonical mapping. Do not create an alias registry or an
alias-named file. Resolution walks the initialized Cobra tree, accepts aliases
at every level, and selects the source for the resulting canonical path.

Use this page order unless a shorter page remains clearer:

1. A task-oriented level-one title.
2. One short orientation paragraph.
3. Level-two task or choice sections with examples.
4. Behavioral surprises that affect the examples.
5. Related guide commands when they help the reader choose.
6. The canonical --help invocation.

## Examples

Examples must use supported command syntax and preserve copyable command text. State prerequisites immediately before the example, including required files, a listener that must already be running, or a second terminal. Prefer portable shell syntax shared by documented shells. Label shell-specific examples in prose and use the matching fence language.

Prefer -o for NPC file output so the command applies its output permissions and sensitive-file protections. Use pipes when demonstrating composition between commands. Use shell redirection when it is itself the subject of the example or the command does not support -o.

When a guide describes output selection, formatting, or encoding, follow the [command output contract](command-output.md). Document the command's actual supported combinations.

Prefer a short end-to-end example where it adds context: create an input, use it with a related command, and inspect or recover the result. Key guides should show where keys are used with certificates or AES, not only how to generate or transform them. Usually one or two such workflows are enough; avoid repeating the same setup in every section.

Explain only defaults that materially affect the demonstrated task. Do not use public services in automated workflow tests; use temporary fixtures or local servers. Manually select representative examples for execution rather than scanning and running arbitrary Markdown fences.

## Rendering and paging

NPC interprets Markdown before writing or paging. Plain output removes presentation delimiters, retains link destinations, preserves code punctuation and indentation, and contains no NPC-generated ANSI controls. Rich output adds SGR text styles and OSC 8 hyperlinks: show the clickable label without appending a second visible destination. Plain output keeps the label and visible destination. Close hyperlink and style controls at each rendered line boundary; controls never count toward the wrapping width. Do not emit cursor movement or other terminal commands. Terminals and pagers without OSC 8 support can use plain output for visible destinations.

Prose wraps at the smaller of the original terminal width and 80 columns. Redirected output uses 80 columns. Code lines are never split. A single non-whitespace token longer than the layout width remains intact so a destination stays copyable.

Automatic rich output requires a supported direct terminal, no nonempty NO_COLOR, no TERM=dumb, and no configured pager. Rich and plain explicitly override that policy. No-pager changes only pager selection.

NPC honors a nonempty PAGER only when its original stdout is a terminal. It parses the value as an executable plus whitespace-separated, single-quoted, double-quoted, or backslash-escaped arguments without invoking a shell. Within double quotes, a backslash escapes a quote or another backslash and is otherwise preserved, including in Windows paths. Pipelines, expansions, and redirections require a wrapper script. NPC does not inject pager flags, inspect executable names, use MANPAGER, or supply a default pager.

A pager receives plain rendering unless rich is explicit. Pager startup failure warns on stderr and writes the rendered guide directly. After a pager starts, a successful early exit and its broken pipe are normal; other write failures and nonzero exits are errors and do not trigger duplicate direct output.

While paging, the pager handles terminal interrupts such as Ctrl-C. NPC stays alive to wait for and reap it, then restores its prior interrupt handling. Ctrl-C does not cancel the pager's process, and repeating it does not end NPC or trigger the 5-second forced exit while the pager runs; SIGTERM or SIGHUP sent to NPC alone does cancel it, so the pager does not outlive it.

## Add or update a guide

1. Initialize the command in the normal Cobra tree and decide whether it is a root, branch, or leaf page.
2. Add the canonical Markdown file under `cmd/guides/` or the owning `cmd/internal/commands/<family>/guides/` and follow the corresponding editorial contract.
3. Add or update consumer-facing examples and manually exercised documented workflows.
4. Update rendering goldens when an intentional presentation change affects them.
5. Run focused command tests, both plain and rich rendering tests, the full public-tree coverage test, mise run check, and race tests for pager or process-lifecycle changes.

The coverage test compares embedded mappings with the initialized public command tree in both directions. It fails for missing pages and stale files, and it explicitly includes generated completion shell commands and the help command. Navigation references in guides must resolve through that same tree.
