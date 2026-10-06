# Contributing

SwYS is a Go CLI for networking, protocols, cryptography, and X.509 tasks.
Start with the [README](README.md) and the embedded `swys help` guides.

## Development setup

Install [mise](https://mise.jdx.dev), then run from your checkout:

```sh
mise trust
mise install
mise run install:hooks
mise run build:dev
./swys --help
```

Mise pins the toolchain and validation tools in
[`.config/mise/config.toml`](.config/mise/config.toml). Run `mise tasks` to
see the available tasks. Docker is needed only for
[Renovate-specific validation](docs/renovate.md).

## Propose a change

Open an issue to discuss substantial interface or architecture changes before
implementing them. For a bug, include the command, expected result, actual result,
SwYS version, and operating system. Use disposable examples and remove passwords,
keys, tokens, and private endpoint details. Report vulnerabilities through the
[security policy](SECURITY.md).

Keep a pull request focused and explain the observable change and its validation.
Use a Conventional Commit title, such as `fix(dns): preserve lookup errors`;
the title and description become the squash commit. Mark breaking changes with
`!` and describe their impact. Update the owning command's embedded guide when
its interface changes.

## Validate the affected behavior

```sh
mise run test:unit -- -run TestName
mise run check
```

For concurrency or subprocess changes, also run:

```sh
mise run test:race -- -shuffle=on
```

Follow [TESTING.md](TESTING.md): reuse focused coverage, demonstrate a regression
before fixing a material defect, and prefer deterministic coordination over
sleeping. Pure refactors can rely on existing tests; configuration changes use
native syntax and consumer validation. Add tests for distinct behavior, not every
internal helper or combination of flags. Run relevant fuzz, benchmark,
interoperability, or vulnerability checks when the change calls for them.

See [AGENTS.md](AGENTS.md) for package boundaries and I/O contracts,
[help authoring](docs/help-authoring.md) for guides, and the
[command output contract](docs/command-output.md) for selection, format, and
encoding behavior. Maintainer publication steps live in
[the release guide](docs/releasing.md).
