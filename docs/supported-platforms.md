# Supported release platforms

Carapace release archives contain the `carapaced` daemon and the `carapace` control
client. The release matrix must build all targets before publication.

| Operating system | Architecture | Rust target | Package |
| --- | --- | --- | --- |
| Linux | x86-64 | `x86_64-unknown-linux-gnu` | `.tar.gz` |
| Linux | ARM64 | `aarch64-unknown-linux-gnu` | `.tar.gz` |
| macOS | x86-64 | `x86_64-apple-darwin` | `.tar.gz` |
| macOS | ARM64 | `aarch64-apple-darwin` | `.tar.gz` |

The Linux archives use dynamic glibc linkage. They do not support musl systems. Each
archive records the highest required `GLIBC_*` symbol version for both executables as
`carapaced_glibc_minimum` and `carapace_glibc_minimum` in `BUILD-METADATA.txt`. Packaging
fails if it cannot measure either value. Read both fields
before deployment because the value depends on the tagged release build environment.

The archives are portable command-line packages. They are not native installers. macOS
artifacts are not an application bundle and are not notarized. Platform signing and
installers need the required project accounts and certificates before they can become
release gates.

The current native macOS binary reports a minimum macOS version of 11.0. The release
workflow sets and checks this value for both executables and records
`carapaced_macos_minimum=11.0` and `carapace_macos_minimum=11.0` in each macOS archive.
This is a measured command-line binary minimum, not a notarization claim.

Windows is build-only. CI compiles and tests the workspace on Windows, but the production
daemon and both control API modes fail closed because Carapace does not yet enforce
owner-only ACLs on state and token files. The release workflow does not publish Windows
archives. Windows can enter the supported release matrix only after native ACL tests pass
for normal startup, claimant recovery, token creation, state persistence, and migration.

Each release includes `SHA256SUMS` and `SHA256SUMS.asc`. Each target archive contains a
CycloneDX JSON SBOM. GitHub records artifact provenance for each archive. Publication
fails closed unless the repository has an approved signing key and exact fingerprint in
the `RELEASE_SIGNING_KEY` and `RELEASE_SIGNING_FINGERPRINT` secrets. The workflow does
not create a key.
