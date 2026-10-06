# Licensing

Copyright Eric Miller.

Except for third-party material identified by its existing notices, the
project-owned source code, documentation, and configuration in this repository
are licensed under the [Apache License, Version 2.0](LICENSE), to the extent Eric
Miller owns the applicable rights or is authorized to grant that license.

This grant also applies to project-owned material in the preserved Git history
of this repository, including historical revisions that do not contain a
`LICENSE` file. The imported history includes every commit reachable from
`4a6d0bbd2bbc76f2169ab69ebd8dd6f45e6a4008`.

Third-party material retains its original license terms. This grant does not
relicense that material. When redistributing an older revision, preserve the
third-party notices and license terms applicable to that revision.

[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt) contains the upstream license,
attribution, and patent notices for the current binary distribution, including
the Go runtime. Its dependency versions do not describe every historical
revision. The bundle also preserves certificate-source notices for the
explicitly identified reviewed OCI base. [Container-base metadata](licenses/oci/README.md)
includes verified upstream SPDX inventories, source references, and the open
Wolfi attribution question. Other container base components remain subject to
their own terms; this does not claim complete base notice coverage.

When changing the Go toolchain or runtime dependencies, review and update the
notice bundle from their corresponding source versions. Preserve upstream
notice text verbatim. Check the base-derived section against the actual
resolved container base for each release.

Release archives include `LICENSE`, `LICENSING.md`, and
`THIRD_PARTY_NOTICES.txt` alongside the README and changelog, when present.
The release build stages copies of these canonical files in `kodata/licenses/`;
ko places them at `/var/run/ko/licenses/` in the application image. Container-base
metadata is also included in every archive under `licenses/oci/` and in images
under `/var/run/ko/licenses/oci/`. The generated staging tree is
not a second source of license text.
