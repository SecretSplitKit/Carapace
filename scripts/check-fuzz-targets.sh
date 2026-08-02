#!/usr/bin/env bash
set -euo pipefail

expected="$(printf '%s\n' manifests_grants recovery_messages restore_paths state_database wire)"
actual="$(
  cargo metadata --manifest-path fuzz/Cargo.toml --no-deps --format-version 1 |
    jq -r '.packages[0].targets[] | select(.kind == ["bin"]) | .name' |
    tr -d '\r' |
    sort
)"

[[ "$actual" == "$expected" ]] || {
  echo "Fuzz target set differs from the required target set." >&2
  diff -u <(echo "$expected") <(echo "$actual") >&2 || true
  exit 1
}

for target in $expected; do
  file="fuzz/fuzz_targets/$target.rs"
  [[ -f "$file" ]] || {
    echo "Missing fuzz target source: $file" >&2
    exit 1
  }
  grep -Fq 'fuzz_target!' "$file" || {
    echo "Fuzz target does not call fuzz_target!: $file" >&2
    exit 1
  }
  corpus="fuzz/corpus/$target"
  [[ -d "$corpus" && -n "$(find "$corpus" -type f -print -quit)" ]] || {
    echo "Fuzz target has no regression corpus: $target" >&2
    exit 1
  }
done

if [[ "${1:-}" == "--smoke" ]]; then
  runs="${CARAPACE_FUZZ_SMOKE_RUNS:-1000}"
  [[ "$runs" =~ ^[1-9][0-9]*$ ]]
  smoke_root="$(mktemp -d)"
  trap 'rm -rf "$smoke_root"' EXIT
  for target in $expected; do
    cp -R "fuzz/corpus/$target" "$smoke_root/$target"
    cargo +nightly-2026-06-01 fuzz run "$target" "$smoke_root/$target" -- \
      -runs="$runs" -seed=424242
  done
elif [[ -n "${1:-}" ]]; then
  echo "usage: scripts/check-fuzz-targets.sh [--smoke]" >&2
  exit 2
fi

echo "Fuzz target checks passed."
