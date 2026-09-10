#!/usr/bin/env bash
set -euo pipefail

status=0
command -v grep >/dev/null 2>&1

while IFS= read -r match; do
  [[ -z "$match" ]] && continue
  echo "Free-form daemon or API log call is not allowed: $match" >&2
  status=1
done < <(
  grep -R -n -E '(eprintln!|println!|dbg!|tracing::|log::)' \
    --include='*.rs' \
    --exclude='ops.rs' \
    --exclude-dir='bin' \
    crates/carapaced/src crates/carapace-api/src || true
)

if (( status != 0 )); then
  echo "Use the structured ops::log function with a fixed event identifier." >&2
  exit "$status"
fi

echo "Operational log source gate passed."
