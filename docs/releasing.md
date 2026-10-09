# Releasing SwYS

Release-please owns version proposals and changelogs. After a release pull
request merges, it creates the tag and GitHub Release; GoReleaser then builds
archives and publishes OCI images. These are separate checkpoints: passing a
snapshot build does not establish that any artifact has been published.

[**0.1.0**](https://github.com/sosheskaz/swys/releases/tag/v0.1.0) is published.
Release Please and Release are enabled; follow the later-release process below
for subsequent versions.

## Validate a candidate without publishing

```sh
mise run check
mise run test:race -- -shuffle=on
mise run scan:vuln
mise exec -- goreleaser check
mise exec -- goreleaser release --snapshot --clean --parallelism=2
mise run test:release
```

Review hosted checks for the same commit. Inspect all platform archives,
checksums, license notices, completion files, and the packaged command. Validate
OCI images separately: snapshot mode disables image publication. Keep local
validation and actual hosted publication evidence distinct.

## First release

The 0.1.0 launch completed this one-time sequence. Preserve it as the record of
the initial publication checkpoints; do not repeat the manual note curation for
later releases.

1. Finish source and documentation review, including the complete preserved Git
   history. Repository visibility and real publication require an explicit
   launch decision; do not enable a publishing workflow just to preview notes.
2. Keep the coupled Release Please workflow disabled. Run the standalone
   `release-please release-pr` operation to prepare the initial 0.1.0 release
   pull request. Keep the empty manifest until the normal generated proposal
   updates it. Do not seed a fake previous tag or discard the historical changes
   with a bootstrap boundary.
3. Review the historical notes as a coherent description of the current CLI.
   Remove obsolete behavior and stale issue or pull-request links. For this
   first release only, put the same reviewed entry in `CHANGELOG.md` and the
   release PR's generated notes block. Preserve release-please's title, branch,
   version heading, and pending lifecycle label.
4. Keep proposal regeneration stopped between that one-time curation and
   publication: release-please can overwrite manual notes even when no source
   commit has changed. For later releases, correct generator inputs instead of
   editing generated notes by hand.
5. Review and merge the release proposal only when publication is authorized.
   With the coupled workflow still disabled, run standalone
   `release-please github-release`, then verify the tag commit and GitHub
   Release body. Enable and dispatch the separate Release artifact workflow
   for that reviewed tag. The normal coupled workflow publishes both stages
   without a human pause, so it must not be used for this first checkpoint.
   Do not treat an updated changelog alone as the source of the published body.
6. Verify archive downloads, checksums, executable metadata, packaged notices,
   OCI image platforms and digests, and an actual install. Update installation
   and security documentation to reflect the services now available. Resume
   the coupled Release Please workflow after the initial release and its
   artifacts have been verified.

## Public-launch settings

Before opening the repository, review its source and history for information
that is not intended for publication. Keep any private audit evidence outside
this repository.

At launch, protect `main` with pull requests and required checks after verifying
the check names against current CI. Keep squash merging, PR title and description
as commit details, automatic branch-deletion, and the update-branch suggestion.
Require approval for workflows from outside contributors and verify that a real
fork pull request cannot publish artifacts or access privileged credentials.

Enable private vulnerability reporting and the available secret-scanning
protections. Verify the reporting link in [SECURITY.md](../SECURITY.md). Preserve
read-only workflow defaults and immutable action pins; grant writes only to
jobs that require them. GitHub Actions' combined create/approve-PR setting is
needed for the configured release-PR automation.

Release activation and Homebrew credential provisioning are described in
[Homebrew distribution](homebrew.md). Production dependency updates have their
own [Renovate activation](renovate.md#production-provisioning) and must not be
enabled merely because CI validation is green.

## Later releases and recovery

Release-please updates the README's marked installation examples and the skill
discovery entry alongside the release version. Keep current-version examples
inside `x-release-please-start-version` / `x-release-please-end` blocks in files
listed under `extra-files` in `release-please-config.json`. Leave historical
release references and minimum supported versions outside those blocks.

Review each generated release PR's version, notes, and tests. With squash merges,
Conventional Commit titles determine the release calculation. The Go strategy
uses the existing pre-1.0 bump rules in `release-please-config.json`.

The agent skill shares the CLI's tags and version lifecycle. Release-please
updates `skills/swys/SKILL.md`'s version in the same proposal as the manifest.
The discovery entry loads instructions from `swys skill`; the binary embeds
those instructions and prints its actual build provenance. Snapshots deliberately
have a different runtime version from the source release label.

Run `mise run lint:skills` with GitHub CLI authentication to validate both the
discovery and rendered packages using `gh skill publish --dry-run`. This check
stages outside the repository and does not publish or query repository settings.
It remains separate from offline `mise run check`. Do not run actual
`gh skill publish`: it creates a competing release lifecycle.

After each release, verify pinned `gh skill install` into a temporary directory
using that tag, and confirm the tag, discovery version, packaged binary version,
and rendered build identity.
Add the `agent-skills` repository topic when publishing the first skill release
to make search discovery available; direct repository installation does not
require that topic. Existing older tags do not gain skill support retroactively.

If publication fails, inspect which stage completed before retrying. A tag,
GitHub Release, release asset, OCI tag, and tap commit can have different states.
Preserve verified artifacts; do not delete or move a published tag to rerun a
job. Use the release workflow's explicit tag input to retry the intended
artifact build only after checking the existing release and permissions.

Before replaying an older tag after a newer cask is published, confirm its
configuration skips tap upload. An older stable release with `skip_upload: auto`
can replace the newer cask. The job reads configuration from the release tag;
changing `main` does not change an old tag's publishing settings.

Stop release automation by disabling its workflows and clearing
`RELEASE_ENABLED`. Setting GoReleaser's cask `skip_upload` back to `true` also
stops future tap writes. These actions do not retract artifacts already
published or copies already downloaded.
