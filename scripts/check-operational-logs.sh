#!/usr/bin/env bash
set -euo pipefail

status=0

while IFS= read -r match; do
  [[ -z "$match" ]] && continue
  echo "Free-form daemon or API log call is not allowed: $match" >&2
  status=1
done < <(
  rg -n '(eprintln!|println!|dbg!|tracing::|log::)' \
    crates/carapaced/src crates/carapace-api/src \
    --glob '*.rs' \
    --glob '!ops.rs' \
    --glob '!**/bin/**' || true
)

if (( status != 0 )); then
  echo "Use the structured ops::log function with a fixed event identifier." >&2
  exit "$status"
fi

echo "Operational log source gate passed."
