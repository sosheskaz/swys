# Enable Fish completion

Generate Fish completion and load it for one session or save it in Fish's user completion directory.

## Load it for the current Fish session

```fish
npc completion fish | source
```

For persistent user completion, save the generated output as npc.fish under the completions directory reported by your Fish configuration. Regenerate it when the installed NPC command tree changes.

## Reference

```sh
npc completion fish --help
```
