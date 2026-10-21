# Renovate

Renovate runs from the official Docker Hub version-and-digest-pinned image in
`.github/renovate.Dockerfile`, with repository policy in `.github/renovate.json`.
GitHub-hosted PR validation checks the proposed
checkout with a read-only token. It validates repository config, proves native
config discovery and nonempty dependency extraction, and looks up public
releases. It does not run artifact updates or publish dependency PRs.

## Local validation

Docker is required only for Renovate-specific validation:

```sh
mise run lint:renovate
```

This checks the exact runtime and native RE2, runs the strict repository-config
validator, and extracts dependencies from a read-only mount of the current
worktree. Linked worktrees need no additional Git-directory mount. Ordinary
`mise run check` does not require Docker.

Authenticated lookup runs in CI with its read-only `GITHUB_TOKEN`. The optional
local `--lookup` flag requires an explicitly supplied read-only
`GITHUB_COM_TOKEN`; the task does not find credentials. Logs expose only stage
metadata and dependency counts. A missing config, empty expected manager,
incomplete lookup, or process failure fails validation. Warnings fail validation
except the expected missing-token warning during anonymous extraction.
Recommended policy leaves indirect Go modules disabled; they must still be
extracted, while lookup proof uses enabled dependencies.

## Image release age

Docker Hub supplies the native Docker datasource's release timestamps. The
runtime image retains the configured seven-day minor/patch wait, fourteen-day
major wait, required timestamps, and manual review. Renovate updates its full
version and OCI digest together; GitHub release commits are not image digests.

Local validation and production set `dockerMaxPages` to `10`. The current
image's anonymous Docker Hub lookup hit the service's pagination cap on the
eleventh page. Its default twenty-page fetch fell back to tags without dates;
ten pages retained dated recent releases without Docker Hub credentials.

This setting applies to all Docker lookups and can reduce historical tag
visibility for future dependencies. Required timestamps hold undated updates;
lookup validation also requires a date for the runtime image, including when
it needs no update. Review the available age window if eligible updates stop.

## Production provisioning

Production stays disabled until provisioning and activation are authorized.
Its source guard additionally requires repository variable `RENOVATE_ENABLED`
to equal `true`. Install a GitHub App only on this repository and configure:

- Repository variable `RENOVATE_APP_CLIENT_ID`: the App client ID.
- Repository secret `RENOVATE_APP_PRIVATE_KEY`: provision the private key
  directly through GitHub's secret interface.

The workflow requests contents, issues, pull requests, workflows, and commit
statuses write access; checks and vulnerability alerts read access. GitHub also
provides metadata read access. These cover dependency branches, the dashboard,
PRs, workflow updates, status checks, and alert lookup. Confirm the installation
can grant these permissions before activation. Renovate discovers the App's bot
identity from its installation token; no author identity is hardcoded.

The production workflow checks out main, serializes runs without cancellation,
mints a token scoped to the current repository, and mounts only Renovate's
cache directory into the container. It uses native repository-config discovery
and permits no custom post-upgrade commands. The token is revoked by the token
Action after the job. No credentials are shared with PR checks.

Production persists only Renovate's package cache between runs, so release and
tag history is fetched incrementally rather than in full on every run. The
cache holds lookup data for public packages and repositories. It lives in
main's Actions cache scope: PR workflows, including those
from forks, can restore it, and any workflow on main can write it. A tampered
entry could steer proposed versions and digests, including automerged Actions
updates. Tool downloads are not persisted, because Renovate would execute them
with the write token. The repository cache stays disabled, because it would
store Dependabot alerts.

Automerge policy remains in the config. Repository automerge availability,
required checks, and enforcement must be established before activating those
merges; source policy and validation do not prove operational automerge. No
production writes have been validated by this migration.

## Distribution verification

The pinned image's signature was verified against Renovate's release workflow:

```sh
image=$(awk '$1 == "FROM" { print $2 }' .github/renovate.Dockerfile)
cosign verify \
  --certificate-identity=https://github.com/renovatebot/renovate/.github/workflows/build.yml@refs/heads/main \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  "$image"
```

This authenticates the Renovate distribution. It does not independently attest
every bundled dependency. Review and verify the replacement distribution when
updating the image pin; a valid image signature does not settle missing
provenance for individual packages.

Image update PRs omit release notes. Renovate's tag history is large enough
that fetching notes dominated each run's duration. Review the release notes
through the PR's source and compare links.
