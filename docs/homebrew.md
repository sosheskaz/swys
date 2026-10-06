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
is not Developer ID signing or notarization. GoReleaser 2.18.2 renders this hook
as Homebrew's deprecated `postflight` stanza, which Homebrew 7 flags with
`Cask/InstallSteps`. Native style checks also flag completion stanza ordering and
a missing frozen-string-literal header in the generated cask. Installation and
completion linking passed on macOS arm64 despite these style findings. Recheck
native validation when GoReleaser supports the declarative replacement. Its
current `custom_block` appears before `version` and fails Homebrew stanza ordering.

## Validate without publishing

```sh
mise exec -- goreleaser check
mise exec -- goreleaser release --snapshot --clean --parallelism=2
mise run test:release
brew tap-new --no-git local/swys-validation
mkdir -p "$(brew --repository local/swys-validation)/Casks"
cp dist/homebrew/Casks/swys.rb "$(brew --repository local/swys-validation)/Casks/swys.rb"
brew info --cask local/swys-validation/swys
brew style "$(brew --repository local/swys-validation)/Casks/swys.rb"
brew audit --cask local/swys-validation/swys
brew untap local/swys-validation
```

Snapshot URLs describe unpublished artifacts. The checks above include the
known generated-style findings; they do not replace an actual install check.
Installing from the public URL requires a published release.
Do not install a missing release or change the tap to test a snapshot. A local
installation probe must use local archive URLs and an isolated Homebrew prefix.

## Release publishing configuration

The initial activation is complete. The steps below document the gating and
credential setup for recovery or a future repository migration. The 0.1.0 cask
was published after anonymous archive verification; the first automatic update
with `BREW_PAT`, and Linux installation, still require live validation.

1. Keep the Release and Release Please workflows disabled until release
   publishing is authorized. Leave `homebrew_casks[].skip_upload: true` in
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
