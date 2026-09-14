#!/usr/bin/env bash
set -euo pipefail

release_workflow=".github/workflows/release.yml"
ci_workflow=".github/workflows/ci.yml"
chela_revision_file="chela-revision.txt"

chela_revision="$(tr -d '\r\n' < "$chela_revision_file")"
[[ "$chela_revision" =~ ^[0-9a-f]{40}$ ]]

required_build='cargo build --release --locked --target ${{ matrix.target }} -p carapace-api --bin carapaced -p carapace --bin carapace'
grep -Fqx "        run: $required_build" "$release_workflow"
grep -Fq 'test -s "target/${{ matrix.target }}/release/carapaced"' "$release_workflow"
grep -Fq '$daemon = Get-Item "target/${{ matrix.target }}/release/carapaced.exe"' "$release_workflow"

for workflow in "$release_workflow" "$ci_workflow"; do
  grep -Fq 'toolchain: 1.95.0' "$workflow"
done

grep -Fq 'run: cargo test --workspace --locked' "$ci_workflow"

if grep -Fq 'continue-on-error:' "$release_workflow"; then
  echo "Release targets must not permit failure." >&2
  exit 1
fi

test "$(grep -Fc 'uses: softprops/action-gh-release@' "$release_workflow")" -eq 1
grep -Fq 'needs: [quality, native-tests, build]' "$release_workflow"
grep -Fq 'merge-multiple: true' "$release_workflow"
grep -Fq 'run: sha256sum carapace-* > SHA256SUMS' "$release_workflow"
grep -Fq 'anchore/sbom-action@57aae528053a48a3f6235f2d9461b05fbcb7366d # v0.23.1' "$release_workflow"
grep -Fq 'cp "sbom-${{ matrix.target }}.cdx.json" "$staging/SBOM.cdx.json"' "$release_workflow"
grep -Fq 'Copy-Item "sbom-${{ matrix.target }}.cdx.json" "$staging/SBOM.cdx.json"' "$release_workflow"
grep -Fq 'actions/attest-build-provenance@96278af6caaf10aea03fd8d33a09a777ca52d62f # v3.2.0' "$release_workflow"
grep -Fq 'subject-path: release-assets/carapace-*' "$release_workflow"
grep -Fq 'attestations: write' "$release_workflow"
grep -Fq 'id-token: write' "$release_workflow"

for gate in \
  'scripts/check-tracked-secrets.sh' \
  'scripts/check-supply-chain-config.sh' \
  'cargo fmt --all -- --check' \
  'cargo clippy --workspace --all-targets -- -D warnings' \
  'cargo test --workspace --locked' \
  'python cbor_vectors.py --check' \
  'npm run check' \
  'npm test' \
  'npm run test:browser' \
  'git diff --exit-code -- crates/carapace-api/static'; do
  grep -Fq "$gate" "$release_workflow"
done
grep -Fq 'EmbarkStudios/cargo-deny-action@' "$release_workflow"
grep -Fq 'needs: [quality, native-tests]' "$release_workflow"
for workflow in "$release_workflow" "$ci_workflow"; do
  grep -Fq 'os: [ubuntu-24.04, ubuntu-24.04-arm, macos-15-intel, macos-15, windows-2025, windows-11-arm]' "$workflow"
done
test "$(grep -Fc 'cargo test --workspace --locked' "$release_workflow")" -ge 2
grep -Fq 'scripts/check-operational-logs.sh' "$release_workflow"
grep -Fq 'scripts/state-fixtures.sh check' "$release_workflow"
grep -Fq 'scripts/check-fuzz-targets.sh --smoke' "$release_workflow"
grep -Fq 'cargo-fuzz --version 0.13.1 --locked' "$release_workflow"
grep -Fq 'RELEASE_SIGNING_KEY: ${{ secrets.RELEASE_SIGNING_KEY }}' "$release_workflow"
grep -Fq 'RELEASE_SIGNING_FINGERPRINT: ${{ secrets.RELEASE_SIGNING_FINGERPRINT }}' "$release_workflow"
grep -Fq 'gpg --batch --local-user "$RELEASE_SIGNING_FINGERPRINT" --detach-sign --armor --output SHA256SUMS.asc SHA256SUMS' "$release_workflow"
grep -Fq 'carapaced_glibc_minimum=${carapaced_glibc_minimum}' "$release_workflow"
grep -Fq 'carapace_glibc_minimum=${carapace_glibc_minimum}' "$release_workflow"
grep -Fq 'target/${{ matrix.target }}/release/carapaced" | grep -F '\''minos 11.0' "$release_workflow"
grep -Fq 'target/${{ matrix.target }}/release/carapace" | grep -F '\''minos 11.0' "$release_workflow"
grep -Fq 'carapaced_macos_minimum=11.0' "$release_workflow"
grep -Fq 'carapace_macos_minimum=11.0' "$release_workflow"
grep -Fq 'MACOSX_DEPLOYMENT_TARGET: "11.0"' "$release_workflow"

grep -Fq 'run: npm ci' "$ci_workflow"
grep -Fq 'run: npm run check' "$ci_workflow"
grep -Fq 'run: npm run build' "$ci_workflow"
grep -Fq 'run: git diff --exit-code -- crates/carapace-api/static' "$ci_workflow"

for workflow in "$release_workflow" "$ci_workflow"; do
  grep -Fq 'ref: ${{ steps.chela-pin.outputs.revision }}' "$workflow"
  grep -Fq 'test "$actual_revision" = "$CHELA_REV"' "$workflow"
done

echo "Release workflow checks passed."
