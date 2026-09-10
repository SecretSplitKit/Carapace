#!/usr/bin/env bash
set -euo pipefail

secret_pattern='-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,}|sk_live_[A-Za-z0-9]{20,}'

if git grep -I -n -E -e "$secret_pattern" -- . \
    ':(exclude)scripts/check-tracked-secrets.sh'; then
    echo "A tracked file contains a value that looks like a secret." >&2
    exit 1
fi

tracked_env_files="$(git ls-files | grep -E '(^|/)\.env($|\.)' | grep -Ev '\.env\.(example|test)$' || true)"
if [[ -n "$tracked_env_files" ]]; then
    echo "Tracked environment files are not permitted:" >&2
    echo "$tracked_env_files" >&2
    exit 1
fi

echo "Tracked-secret checks passed."
