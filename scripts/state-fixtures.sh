#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
output="${2:-}"
required=(
  empty-schema-2.redb
  rich-schema-2.redb
  legacy-schema-1.redb
  legacy-unversioned.redb
  active-ceremony-rates-tombstones.redb
  split-held-shares.redb
  replica-gc-state.redb
  corrupt.redb
  truncated.redb
)

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    command -v shasum >/dev/null 2>&1
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

generate() {
  local destination="$1"
  mkdir -p "$destination"
  CARAPACE_FIXTURE_OUTPUT_DIR="$destination" \
    cargo test --locked -p carapaced --lib persist_load_roundtrips_all_categories
  {
    printf 'file\tsha256\tclassification\n'
    for file in "${required[@]}"; do
      test -s "$destination/$file"
      printf '%s\t%s\tsynthetic-test-state-no-production-secrets\n' \
        "$file" "$(hash_file "$destination/$file")"
    done
  } > "$destination/MANIFEST.tsv"
}

case "$mode" in
  generate)
    test -n "$output"
    generate "$output"
    ;;
  check)
    frozen="crates/carapaced/tests/fixtures/legacy-rich-v1.redb.gz.b64"
    manifest="crates/carapaced/tests/fixtures/MANIFEST.tsv"
    expected="$(awk -F '\t' '$1 == "legacy-rich-v1.redb.gz.b64" { print $2 }' "$manifest")"
    test -n "$expected"
    test "$(hash_file "$frozen")" = "$expected"
    case "$(uname -s)" in
      MINGW*|MSYS*|CYGWIN*)
        cargo test --locked -p carapaced --lib persist_load_roundtrips_all_categories
        echo "State fixture $mode completed."
        exit 0
        ;;
    esac
    temporary="$(mktemp -d)"
    trap 'rm -rf "$temporary"' EXIT
    generate "$temporary"
    test "$(wc -l < "$temporary/MANIFEST.tsv" | tr -d ' ')" = "10"
    ;;
  *)
    echo "usage: scripts/state-fixtures.sh <generate OUTPUT_DIR|check>" >&2
    exit 2
    ;;
esac

echo "State fixture $mode completed."
