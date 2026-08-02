#!/usr/bin/env bash
set -euo pipefail

if rg -n 'fn safe_join|write_file_with_meta|fs::write\(&?dest|File::create\(&?dest' \
  crates/carapace-vault crates/carapace-disclose; then
  echo "restore output logic exists outside carapace-restore" >&2
  exit 1
fi

test -f crates/carapace-restore/src/lib.rs
echo "restore source layout is valid"
