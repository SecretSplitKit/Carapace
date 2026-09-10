#!/usr/bin/env bash
set -euo pipefail

command -v grep >/dev/null 2>&1

if grep -R -n -E 'fn safe_join|write_file_with_meta|fs::write\(&?dest|File::create\(&?dest' \
  --include='*.rs' \
  crates/carapace-vault crates/carapace-disclose; then
  echo "restore output logic exists outside carapace-restore" >&2
  exit 1
fi

test -f crates/carapace-restore/src/lib.rs
echo "restore source layout is valid"
