# Read NPC usage guides

The help command displays curated task guidance. A command's help flag remains the generated reference for arguments, flags, defaults, and aliases.

## Select a guide

Use canonical command names or their aliases. Output always uses canonical names so examples remain consistent.

```sh
npc help net connect
npc help x509 connect
```

## Control presentation

Direct supported terminals use styled rendering automatically. Redirected output and configured pagers receive plain rendered text by default. Rich and plain override that choice; no-pager bypasses a configured pager.

NPC starts PAGER only when its original stdout is a terminal. The value is parsed as an executable plus quoted arguments without shell evaluation. Use a wrapper script when a pager setup needs pipelines, expansions, or redirections.

```fish
env PAGER='less -R' npc help net --rich
npc help net --rich | less -R
npc help net --no-pager
```

Rich rendering uses text styles and clickable link labels on terminals that support OSC 8 hyperlinks. Plain rendering keeps destinations visible. NPC does not infer pager capabilities from an executable name; choose plain output when a pager or terminal cannot display the links.

## Reference

```sh
npc help --help
```
