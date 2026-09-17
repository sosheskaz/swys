# Enable Zsh completion

Generate Zsh completion and load it for one session or place it in a directory on the Zsh function path.

## Load it for the current Zsh session

This example requires Zsh process substitution and an initialized completion system.

```sh
source <(npc completion zsh)
```

For persistent use, save the generated function with the name expected by Zsh in a function-path directory. Regenerate it when the installed NPC command tree changes.

## Reference

```sh
npc completion zsh --help
```
