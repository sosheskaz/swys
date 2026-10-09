# Load SwYS instructions for an agent

Print a complete Agent Skills document from this binary. It includes the running build's version and provenance, so an agent can use instructions that match the executable.

## Read the bundled skill

```sh
swys skill
```

The output is raw Markdown with YAML frontmatter. It is never styled, wrapped, or paged, including when shared styling is rich. This command reads no input and makes no network requests.

## Save a standalone skill

Create the destination directory first. For example, after creating .agents/skills/swys in your project:

```sh
swys skill -o .agents/skills/swys/SKILL.md
```

The output file can be replaced. The shared output option applies normal SwYS file permissions; --mode selects explicit permissions where supported. Saved instructions check build identity and refresh from the CLI when needed.

For managed installation and source tracking, install the repository's discovery skill with gh skill. That small entry loads the complete instructions from swys skill at runtime. See the repository README for agent selection, installation scope, and release pinning.

## Reference

```sh
swys skill --help
```
