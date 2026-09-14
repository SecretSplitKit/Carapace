#!/usr/bin/env bash
set -euo pipefail

inventory="docs/test-inventory.md"
checked=0
gaps=0

duplicate_ids="$(
  awk -F'|' '/^\| PR-/{gsub(/[[:space:]]/, "", $2); print $2}' "$inventory" \
    | sort \
    | uniq -d
)"
if [[ -n "$duplicate_ids" ]]; then
  echo "The inventory has duplicate requirement ids:" >&2
  echo "$duplicate_ids" >&2
  exit 1
fi

while IFS='|' read -r _ id status requirement file function _; do
  id="$(echo "$id" | xargs)"
  [[ "$id" == PR-* ]] || continue
  status="$(echo "$status" | xargs)"
  file="$(echo "$file" | xargs)"
  function="$(echo "$function" | xargs)"

  case "$status" in
    Pass|Partial)
      [[ -f "$file" ]] || {
        echo "$id points to missing file: $file" >&2
        exit 1
      }
      if [[ "$file" == *.sh && "$function" == "main" ]]; then
        [[ -x "$file" ]] || {
          echo "$id points to a script that is not executable: $file" >&2
          exit 1
        }
      elif [[ "$file" == *.py ]]; then
        grep -Eq "^def[[:space:]]+$function[[:space:]]*\(" "$file" || {
          echo "$id points to missing Python function $function in $file" >&2
          exit 1
        }
	  elif [[ "$file" == *.ts || "$file" == *.mjs ]]; then
		grep -Fq "test('$function'" "$file" || grep -Fq "it('$function'" "$file" || {
		  echo "$id points to missing JavaScript test $function in $file" >&2
		  exit 1
		}
      else
        grep -Eq "(^|[[:space:]])fn[[:space:]]+$function[[:space:]]*\\(" "$file" || {
          echo "$id points to missing function $function in $file" >&2
          exit 1
        }
      fi
      checked=$((checked + 1))
      ;;
    Gap)
      [[ "$file" == "-" && "$function" == "-" ]] || {
        echo "$id gap must use '-' for its file and function" >&2
        exit 1
      }
      gaps=$((gaps + 1))
      ;;
    *)
      echo "$id has unknown status: $status" >&2
      exit 1
      ;;
  esac
done < "$inventory"

(( checked >= 25 )) || {
  echo "The inventory has too few executable mappings: $checked" >&2
  exit 1
}
(( gaps > 0 )) || {
  echo "The inventory must state known test gaps." >&2
  exit 1
}

echo "Test inventory checks passed: $checked mappings, $gaps explicit gaps."
scripts/check-fuzz-targets.sh
