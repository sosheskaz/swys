# Chainguard container-base notices and sources

These files describe the OCI container base, not the standalone SwYS binary.
The release archives include them so container users can retrieve the base's
package and source information without registry access. The application image
contains the same files under `/var/run/ko/licenses/oci/`.

## Reviewed base

GoReleaser pins
`cgr.dev/chainguard/static@sha256:fe55470f22d3259488d9d3739168d8f04da67755f0b69382bc26eda4a7d3d327`.
Its platform manifests are:

| Platform    | Manifest digest                                                           | Upstream SPDX SBOM                             |
| ----------- | ------------------------------------------------------------------------- | ---------------------------------------------- |
| linux/amd64 | `sha256:a40219f3b0c2719e4e4220310e80a2230a4b95881644292c130e3a8e8287fc6c` | [linux-amd64.spdx.json](linux-amd64.spdx.json) |
| linux/arm64 | `sha256:daed076c904e5dc26f5ff87d77aa4cea8b7ca76e906b561915dafe5b086377dc` | [linux-arm64.spdx.json](linux-arm64.spdx.json) |

The SPDX documents are the predicates extracted from Chainguard's signed
attestations, with JSON formatting only. Their signatures and image subjects
were verified with Cosign 3.1.3 on 2026-10-06 using Chainguard's documented
public signing identity. The extracted documents are not themselves signed
attestations.

## Packages and notices

| Runtime package        | Version      | Upstream declaration | Notice/source handling                                                                                                                                                   |
| ---------------------- | ------------ | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| wolfi-baselayout       | 20230201-r30 | MIT                  | Preserve the supplied files and metadata; attribution clarification is pending below.                                                                                    |
| ca-certificates-bundle | 20260909-r2  | MPL-2.0 AND MIT      | The certificate-data notice, MPL text, and corresponding source links are reproduced in `THIRD_PARTY_NOTICES.txt`.                                                       |
| tzdata                 | 2026e-r0     | CC-PDDC              | Retain the base's timezone files and embedded notices, including `/usr/share/zoneinfo/leap-seconds.list`; source is [tz 2026e](https://github.com/eggert/tz/tree/2026e). |

The SBOMs preserve upstream license declarations and source references. A
package declaration does not establish that every license applies to every
file; build recipes and build-only tools can have separate terms. Adding SwYS
with ko retains the base layers and their existing notices.

For `wolfi-baselayout`, upstream declares MIT but records
`copyrightText: "NOASSERTION"`. We have not located a complete package-specific
copyright and permission notice. [Wolfi issue #78756](https://github.com/wolfi-dev/os/issues/78756)
asks for the canonical notice to preserve. This records an attribution
uncertainty; it does not substitute a guessed copyright holder, relicense the
package, or claim that its redistribution is prohibited.

## Refreshing the base

Update the GoReleaser pin, both platform SBOMs, this inventory, and the
base-derived section of `THIRD_PARTY_NOTICES.txt` together. Review the files
actually shipped by the new base and retain their notices. Do not assume a new
base has the same package set or certificate source.

Resolve the platform manifests from the pinned index with `crane manifest`.
For each manifest, verify its SPDX attestation before extracting the predicate:

```sh
set -eu
image=cgr.dev/chainguard/static@sha256:a40219f3b0c2719e4e4220310e80a2230a4b95881644292c130e3a8e8287fc6c
cosign verify-attestation \
  --type https://spdx.dev/Document \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity=https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main \
  "$image" > verified-attestation.json
jq -r '.payload | @base64d' verified-attestation.json > statement.json
jq --arg digest "${image##*@sha256:}" -e \
  '.subject | any(.digest.sha256 == $digest)' statement.json
jq '.predicate' statement.json > linux-amd64.spdx.json
```

Repeat for arm64 using its manifest digest and output filename. The verified
statement must name the matching platform manifest. Keep upstream SPDX values
unchanged; formatting is allowed. Run the release packaging checks and inspect
both application images before publishing.

See Chainguard's [SBOM/source-reference guidance](https://edu.chainguard.dev/chainguard/containers/security-and-compliance/retrieve-image-sboms/#license-information-and-source-code-references)
and [signature-verification instructions](https://edu.chainguard.dev/chainguard/containers/security-and-compliance/verifying-chainguard-images-and-metadata-signatures-with-cosign/).
