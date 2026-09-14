# Release dependencies

Carapace uses Chela through local path dependencies. CI and release builds check out the
exact Chela commit in `chela-revision.txt`. Both workflows verify the checked-out commit
before they compile Carapace. Each release archive also contains the commit in
`BUILD-METADATA.txt`.

## Update the Chela revision

1. Review and test the proposed Chela commit.
2. Replace the full 40-character commit in `chela-revision.txt`.
3. Run the locked Carapace workspace tests against that Chela checkout.
4. Run the release build for each supported target.
5. Review the workflow result before you merge the change.

Do not use a branch name or a moving tag as the revision.

## Roll back the Chela revision

Restore the last reviewed commit in `chela-revision.txt`. Then run the same locked tests
and release builds. This rollback changes no Carapace state or user data.

## Release publication

Each target job builds and packages both `carapaced` and `carapace`. Target jobs cannot
write a GitHub release. The publication job starts only after all target jobs succeed. It
downloads the complete artifact set and uploads that set to the tagged release.
The release also contains `SHA256SUMS` for all target archives. CI rebuilds the embedded
GUI and fails if the committed static files do not match the GUI source.

Each target archive contains a CycloneDX JSON software bill of materials at
`SBOM.cdx.json`. The publication job creates a GitHub artifact attestation for every
archive. The attestation binds the archive digest to the GitHub workflow identity and tag.
It uses GitHub's short-lived OpenID Connect identity. It does not use a stored project key.

Verify a downloaded archive with the GitHub CLI:

```sh
gh attestation verify carapace-<target>.<tar.gz-or-zip> --repo SecretSplitKit/Carapace
sha256sum --check SHA256SUMS
gpg --batch --verify SHA256SUMS.asc SHA256SUMS
```

`sha256sum` is normally available on Linux. On another operating system, use a SHA-256
tool that can read the same checksum file.

## Detached project signatures

The tag workflow fails closed unless maintainers configure an approved armored private
key in `RELEASE_SIGNING_KEY` and its exact full fingerprint in
`RELEASE_SIGNING_FINGERPRINT`. The workflow imports that key only into the temporary job
keyring, checks the fingerprint, and signs `SHA256SUMS`. It does not generate a key.

Before publication is enabled, maintainers must publish the matching public key and
fingerprint through an authenticated project channel and define custody, rotation, and
revocation. Import that published public key, compare its full fingerprint with the
published fingerprint, then run the verification command above. A successful GitHub
workflow alone does not establish that an unknown signing key is approved.
