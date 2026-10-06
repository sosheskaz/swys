# Enable Zsh completion

Generate Zsh completion and load it for one session or place it in a directory on the Zsh function path.

## Load it for the current Zsh session

Run this in Zsh. Initialize its completion system before sourcing the generated script.

```sh
autoload -Uz compinit
compinit
source <(npc completion zsh)
```

For persistent use, save the generated function with the name expected by Zsh in a function-path directory. Regenerate it when the installed NPC command tree changes.

## Reference

```sh
npc completion zsh --help
```
