# Generate shell completion

Generate a completion script for the shell that will load it. NPC writes the script to stdout; your shell decides whether to source it for one session or install it in a startup directory.

## Choose your shell

- **bash** generates Bash completion.
- **fish** generates Fish completion.
- **powershell** generates PowerShell completion.
- **zsh** generates Zsh completion.

Read the shell-specific reference before choosing a persistent installation path, because package managers and shell frameworks use different directories.

## Try completion for one session

The following example is for Fish.

```fish
npc completion fish | source
```

## Next steps

```sh
npc help completion fish
npc completion --help
```
