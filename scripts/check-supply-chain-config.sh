#!/usr/bin/env bash
set -euo pipefail

ci_workflow=".github/workflows/ci.yml"

grep -Fq 'actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e # v6.4.0' "$ci_workflow"
grep -Fq 'node-version: 24.18.0' "$ci_workflow"
grep -Fq 'npm install --global npm@11.16.0' "$ci_workflow"
grep -Fq 'EmbarkStudios/cargo-deny-action@d755fbddac377c2d538f556dd0f9c7728c7f73e4 # v2.0.14' "$ci_workflow"
grep -Fq 'arguments: --all-features' "$ci_workflow"
grep -Fq 'command-arguments: --config /github/workspace/Carapace/deny.toml' "$ci_workflow"
grep -Fq 'rustsec/audit-check@69366f33c96575abad1ee0dba8212993eecbe998 # v2.0.0' "$ci_workflow"
grep -Fq 'unknown-registry = "deny"' deny.toml
grep -Fq 'unknown-git = "deny"' deny.toml
grep -Fq 'yanked = "deny"' deny.toml
grep -Fq 'wildcards = "warn"' deny.toml
grep -Fq 'allow-wildcard-paths = true' deny.toml
grep -Fq '"Unlicense"' deny.toml

node -e '
const manifest = require("./gui/package.json");
if (manifest.packageManager !== "npm@11.16.0") process.exit(1);
if (manifest.engines?.node !== "24.18.0") process.exit(1);
if (manifest.engines?.npm !== "11.16.0") process.exit(1);
'

test "$(tr -d '\r\n' < .nvmrc)" = "24.18.0"
scripts/check-tracked-secrets.sh

echo "Supply-chain configuration checks passed."
