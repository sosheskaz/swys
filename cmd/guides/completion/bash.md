# Enable Bash completion

Generate Bash completion and load it into the current shell or install it where your Bash completion setup reads scripts.

## Load it for the current Bash session

This example requires Bash process substitution.

```bash
source <(npc completion bash)
```

For persistent use, write the generated script to a completion directory used by your operating system or Bash framework. Regenerate it when the installed NPC command tree changes.

## Reference

```sh
npc completion bash --help
```
