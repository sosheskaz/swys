# Generate shell completion

Generate a completion script for the shell that will load it. NPC writes the script to stdout; your shell decides whether to source it for one session or install it in a startup directory.

Shell generators also accept --output to save the script and --mode to select file permissions. They reject --input because the script comes from NPC's command tree.

## Choose your shell

Run npc completion for the shell generator reference.

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

## Save a script for later

From a writable local directory, save the Fish script and load that file in a Fish session. Choose your shell's configured completion directory when installing it persistently.

```fish
npc completion fish > npc.fish
source npc.fish
```

Regenerate the script after changing the installed NPC version. Completion reflects the installed command tree.

## Next steps

```sh
npc help completion fish
npc completion --help
```
