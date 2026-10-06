# SwYS

[![CI](https://github.com/sosheskaz/swys/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sosheskaz/swys/actions/workflows/ci.yml)

**A sysadmin's Swiss Army knife.** SwYS brings networking, protocols, keys,
certificates, and cryptography into one Go CLI. Use it to inspect an endpoint,
resolve a name, exchange bytes, or prepare a local test identity.

| Task                                                                | Command family           |
| ------------------------------------------------------------------- | ------------------------ |
| Connect or listen over TCP, TLS, or UDP                             | `swys net`               |
| Resolve DNS, including DNS over TLS or HTTPS                        | `swys dns`               |
| Make HTTP requests or discover and call unary gRPC methods          | `swys http`, `swys grpc` |
| Inspect, create, and verify certificates; work with asymmetric keys | `swys cert`              |
| Encrypt/decrypt OpenPGP or Tink streams; manage AES keys            | `swys aes`               |
| Compute streaming checksums                                         | `swys hash`              |

## Install

[Release archives](https://github.com/sosheskaz/swys/releases/latest) are available
for macOS, Linux, Windows, and FreeBSD on arm64 and amd64. SwYS is pre-1.0;
interfaces may change between releases.

### Install a release with mise

[Install and activate mise for your shell](https://mise.jdx.dev/getting-started.html),
then install SwYS globally using its [GitHub backend](https://mise.jdx.dev/dev-tools/backends/github.html):

```sh
mise use --global github:sosheskaz/swys@latest
swys --version
```

Mise selects the release archive for your platform and makes `swys` available
on `PATH` in an activated shell. Set up SwYS completion separately below.

### Install with Homebrew

```sh
brew install --cask sosheskaz/tap/swys
swys --version
```

The cask installs Bash, Zsh, and Fish completions. On macOS it removes the
binary's quarantine attribute; the binary is not Developer ID signed or
notarized. See [Homebrew distribution](docs/homebrew.md) for details.

### Build from source

With [mise](https://mise.jdx.dev) installed:

```sh
git clone https://github.com/sosheskaz/swys.git
cd swys
mise trust
mise install
mise run build:dev
./swys --help
```

The build writes `swys` into the checkout. Put it on your `PATH`, or replace
`swys` with `./swys` in the examples below. Runtime use does not require mise.

### Shell completion

Once `swys` is on `PATH`, run the setup for your shell. These instructions work
with mise or a source build. The Homebrew cask installs them automatically.
Open a new shell after setup, and regenerate the files after upgrading SwYS.

<details>
<summary>Fish</summary>

Run in Fish; it loads files from its user completion directory automatically:

```fish
mkdir -p "$__fish_config_dir/completions"
swys completion fish -o "$__fish_config_dir/completions/swys.fish"
```

</details>

<details>
<summary>Zsh</summary>

```zsh
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/zsh/completions"
swys completion zsh -o "${XDG_CONFIG_HOME:-$HOME/.config}/zsh/completions/_swys"
```

Add to your `.zshrc`. If your shell framework already runs `compinit`, add only
the `fpath` line before that initialization:

```zsh
fpath=("${XDG_CONFIG_HOME:-$HOME/.config}/zsh/completions" $fpath)
autoload -Uz compinit
compinit
```

</details>

<details>
<summary>Bash</summary>

First [install and initialize bash-completion](https://github.com/scop/bash-completion#installation)
for your Bash version, then generate the SwYS script:

```bash
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/bash/completions"
swys completion bash -o "${XDG_CONFIG_HOME:-$HOME/.config}/bash/completions/swys.bash"
```

Add to `~/.bashrc` after bash-completion initialization. On macOS, ensure your
`~/.bash_profile` sources `~/.bashrc` for login shells:

```bash
source "${XDG_CONFIG_HOME:-$HOME/.config}/bash/completions/swys.bash"
```

</details>

For one-session setup and PowerShell instructions, run `swys help completion`.

## Find your way around

Start with an embedded guide, narrow to a command family, then pick an operation:

```sh
swys help
swys help cert
swys help cert connect
swys cert connect --help
```

Guides explain tasks and include examples. `--help` lists arguments, flags, and
defaults. `swys cert help connect` also opens the connection guide. Guides ship
in the binary, so help works without a checkout or network access.

Commands that process bytes generally read stdin and write stdout. Use `-i`
to read a file and `-o` to save output with SwYS's file-permission handling;
`--mode` explicitly selects output permissions. Use pipes to compose operations.
Selection, format, and encoding are separate controls: choose what to output,
how to represent it, and how to encode the resulting bytes. Each command's
guide explains the available choices.

## Useful tasks

Run the file examples in a scratch directory with fresh output paths.

### Create and inspect a local TLS identity

```sh
swys cert keygen -o server-key.pem
swys cert create --key server-key.pem --dns localhost -o server.pem
swys cert verify -i server.pem --ca server.pem --hostname localhost
swys cert inspect -i server.pem --format json -o certificate.json
swys cert match --cert server.pem --key server-key.pem
```

Keep the key private. The explicit `--ca` trusts this self-signed certificate
for that verification; SwYS does not install trust anchors.

### Inspect a server's presented certificate

Replace the endpoint with your TLS server:

```sh
swys cert connect api.example.test:443 --format pem -o peer.pem
swys cert inspect -i peer.pem --format text
```

To save an available root CA as Base64-wrapped PEM:

```sh
swys cert connect api.example.test:443 --select root -f pem -e base64 -o ca.pem.b64
```

Root export needs a verified chain or a supplied chain ending in a self-signed
CA; an untrusted leaf alone is insufficient. Check the separate verification
result: exporting a certificate can succeed even when the peer is not trusted.

### Compare DNS answers

```sh
swys dns example.com
swys dns @1.1.1.1 example.com MX --select values
```

The first lookup uses the system resolver. The second queries the named server
directly; its address can also use `@tls://` or `@https://` for encrypted DNS.

### Exchange bytes over verified TLS

Use the localhost certificate and key created above. In one terminal:

```sh
printf 'hello from server\n' | swys net listen --tls --cert server.pem --key server-key.pem localhost:8443
```

In a second terminal, trust that certificate and send the other half of the exchange:

```sh
printf 'hello from client\n' | swys net connect --tls --ca server.pem localhost:8443
```

Each terminal prints the bytes received from its peer. For raw TCP, omit
`--tls` and the credential flags. For one datagram exchange, use `--udp`
instead of those TLS options.

### Encrypt a file

Given a file named `notes.txt`, generate a fresh key and round-trip its contents:

```sh
swys aes keygen -o aes.key
swys aes encrypt --key aes.key -i notes.txt -o notes.pgp
swys aes decrypt --key aes.key -i notes.pgp -o recovered.txt
```

Keep `aes.key` private. The default format is OpenPGP RFC 9580 AES-GCM; the AES
guides cover passwords and Tink streams. Decryption authenticates chunks as it
streams; a later error can leave earlier verified plaintext in the output.

### Hash an HTTP response without saving it

```sh
swys http https://example.com | swys hash sha256
```

Only response bytes enter the hash; HTTP trace diagnostics stay on stderr.

## Development

[mise](https://mise.jdx.dev) pins the toolchain in
[`.config/mise/config.toml`](.config/mise/config.toml). Run `mise tasks` to
discover the build and validation tasks, and `mise run check` for the standard
local checks.

See the [repository layout](AGENTS.md#project-and-layout),
[testing guide](TESTING.md), [help authoring standard](docs/help-authoring.md),
and [command output contract](docs/command-output.md) when contributing.
