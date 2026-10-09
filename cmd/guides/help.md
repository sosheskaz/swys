# Read SwYS usage guides

The help command displays curated task guidance. A command's help flag remains the generated reference for arguments, flags, defaults, and aliases.

The shared **--style auto|rich|plain** option also applies to guides. Help's **--rich** and **--plain** switches take precedence; rich help retains its prose wrapping, while plain help stays unwrapped. Pager behavior is unchanged.

## Select a guide

Use canonical command names or their aliases. Output always uses canonical names so examples remain consistent.

```sh
swys help net connect
swys help x509 connect
```

Command groups such as cert, aes, net, and completion also accept help before a relative command path. With no path, group help shows the group's overview. Runnable commands such as dns and http keep their normal operands.

```sh
swys cert help
swys cert help connect
swys aes help encrypt
swys net help listen
```

## Control presentation

Direct supported terminals use styled rendering automatically. Redirected output and configured pagers receive plain rendered text by default. Rich and plain override that choice; no-pager bypasses a configured pager.

SwYS starts PAGER only when its original stdout is a terminal. The value is parsed as an executable plus quoted arguments without shell evaluation. Use a wrapper script when a pager setup needs pipelines, expansions, or redirections.

```fish
env PAGER='less -R' swys help net --rich
swys help net --rich | less -R
swys help net --no-pager
```

Rich rendering uses text styles and clickable link labels on terminals that support OSC 8 hyperlinks. Plain rendering keeps destinations visible. SwYS does not infer pager capabilities from an executable name; choose plain output when a pager or terminal cannot display the links.

Plain output never adds line wrapping, including when redirected or sent to a pager. Rich output wraps prose to fit the terminal, up to 80 columns. Code lines keep their original layout in either style.

## Reference

```sh
swys help --help
```
