# Homebrew distribution

The [SwYS cask](https://github.com/sosheskaz/homebrew-tap/blob/main/Casks/swys.rb)
is published. Stable releases update the tap directly; prereleases are skipped.
GoReleaser renders
`dist/homebrew/Casks/swys.rb` from the checksummed macOS/Linux arm64 and amd64
archives. The cask installs `swys` and packaged Bash, Zsh, and Fish completions.
GoReleaser generates those scripts from the source command before archiving;
Homebrew does not execute the downloaded binary to generate completions.

The macOS install hook removes `com.apple.quarantine` from the staged binary.
This matches the existing tap's behavior and bypasses that Gatekeeper check; it
is not Developer ID signing or notarization. GoReleaser 2.19 renders the hook as
declarative `postflight_steps`, using `on_macos`, `run`, and the Homebrew
`{{staged_path}}` token. It also puts completion stanzas in Homebrew's required
Bash, Zsh, Fish order. These changes address the legacy `Cask/InstallSteps` and
completion-order findings.

Homebrew's cask style policy exempts casks from the frozen-string-literal header
rule. Validate inside a tap to apply that policy; the generated cask does not
need a header workaround or edits to its generated output. Parsing and style
checks do not establish a new installation or upgrade result.

## Validate without publishing

```sh
mise exec -- goreleaser check
mise exec -- goreleaser release --snapshot --clean --parallelism=2
mise run test:release
validation_config=$(mktemp -d)
brew tap-new --no-git local/swys-validation-219
mkdir -p "$(brew --repository local/swys-validation-219)/Casks"
cp dist/homebrew/Casks/swys.rb "$(brew --repository local/swys-validation-219)/Casks/swys.rb"
brew info --json=v2 --cask local/swys-validation-219/swys
XDG_CONFIG_HOME="$validation_config" brew trust local/swys-validation-219
XDG_CONFIG_HOME="$validation_config" brew readall --os=all --arch=all --debug --verbose local/swys-validation-219
brew style --display-cop-names "$(brew --repository local/swys-validation-219)/Casks/swys.rb"
XDG_CONFIG_HOME="$validation_config" brew untap local/swys-validation-219
rm -r "$validation_config"
```

Use an unused local tap name and stop if `tap-new` fails; Homebrew requires a
cask to be in a tap for CLI parsing. The temporary XDG configuration keeps
fixture trust separate from normal Homebrew trust settings; `readall` otherwise
skips an untrusted tap with a successful exit status. Confirm the loader output
names `Casks/swys.rb`, then remove only the temporary validation tap and
configuration. These checks do not replace an actual install check.

Snapshot versions and checksums describe local builds, while their generated
URLs can point at the last release tag. Do not install a snapshot cask from
those URLs or change the published tap to test it. A local installation probe
must use local archive URLs and an isolated Homebrew prefix.

## Release publishing configuration

The initial activation is complete. The steps below document the gating and
credential setup for recovery or a future repository migration. The 0.1.0 cask
was published after anonymous archive verification; the first automatic update
with `BREW_PAT`, and Linux installation, still require live validation.

1. Keep the Release and Release Please workflows disabled until release
   publishing is authorized. Set `homebrew_casks[].skip_upload: true` in
   `.config/goreleaser.yaml` until anonymous release downloads have been verified.
2. Provision the repository secret `BREW_PAT` privately. Use a fine-grained PAT
   restricted to `sosheskaz/homebrew-tap`, with Contents read/write. The selected
   direct cask update does not require Pull requests permission. Set an expiry
   and rotate it privately; do not put tokens in workflow inputs or source.
3. Follow the [first-release sequence](releasing.md#first-release) for the
   initial release. After release authorization, set `RELEASE_ENABLED=true`
   and enable the artifact Release workflow. Keep the
   combined Release Please workflow disabled until the curated first release
   has been verified; subsequent releases can enable both workflows. Publishing
   jobs require main, an explicitly public event repository, and this opt-in.
   The reusable caller passes only `BREW_PAT`; the release job maps it to
   `TAP_GITHUB_TOKEN` and refuses an empty value. SwYS release/GHCR publishing
   continues to use its own `GITHUB_TOKEN`.
4. Publish the first release with tap upload still disabled. Verify all four
   cask archives download anonymously and match the release checksums. Validate
   the generated cask and its actual macOS installation, completions, and smoke
   commands. Linux installation needs its own validation before claiming that
   platform works.
5. In a reviewed change, set `skip_upload: auto` to publish stable releases
   directly to `sosheskaz/homebrew-tap` as `Casks/swys.rb`; prereleases remain
   skipped. No tap pull request is created. Verify the next authorized tap
   commit, then a fresh install and upgrade:

   ```sh
   brew install --cask sosheskaz/tap/swys
   swys --version
   swys --help
   ```

For each release, verify hosted publication, anonymous downloads, and the tap
commit before testing installation or upgrade.
Disable the workflows and clear `RELEASE_ENABLED` to stop automation; restoring
`skip_upload: true` also stops GoReleaser tap writes.
