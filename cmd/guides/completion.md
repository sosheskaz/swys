# Generate shell completion

Generate a completion script for the shell that will load it. SwYS writes the script to stdout; your shell decides whether to source it for one session or install it in a startup directory.

Shell generators also accept --output to save the script and --mode to select file permissions. They reject --input because the script comes from SwYS's command tree.

## Choose your shell

Run swys completion for the shell generator reference.

- **bash** generates Bash completion.
- **fish** generates Fish completion.
- **powershell** generates PowerShell completion.
- **zsh** generates Zsh completion.

Read the shell-specific reference before choosing a persistent installation path, because package managers and shell frameworks use different directories.

## Try completion for one session

The following example is for Fish.

```fish
swys completion fish | source
```

## Save a script for later

From a writable local directory, save the Fish script and load that file in a Fish session. Choose your shell's configured completion directory when installing it persistently.

```fish
swys completion fish > swys.fish
source swys.fish
```

Regenerate the script after changing the installed SwYS version. Completion reflects the installed command tree.

## Next steps

```sh
swys help completion fish
swys completion --help
```
