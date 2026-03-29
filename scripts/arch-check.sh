#!/usr/bin/env bash
# Architecture enforcement checks for octarine.
#
# Usage:
#   scripts/arch-check.sh                     # All checks, all files
#   scripts/arch-check.sh --staged-only       # Only git-staged .rs files
#   scripts/arch-check.sh layer-boundary      # Run one check
#   scripts/arch-check.sh --staged-only naming-prefix test-lint
#
# Exit code: non-zero if any ERROR-level finding.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${REPO_ROOT}/crates/octarine/src"

ERRORS_FILE=$(mktemp)
WARNINGS_FILE=$(mktemp)
echo 0 > "$ERRORS_FILE"
echo 0 > "$WARNINGS_FILE"
trap 'rm -f "$ERRORS_FILE" "$WARNINGS_FILE"' EXIT

staged_only=false
checks=()

# ── Parse args ──────────────────────────────────────────────────────────────

for arg in "$@"; do
  case "$arg" in
    --staged-only) staged_only=true ;;
    *) checks+=("$arg") ;;
  esac
done

# ── Helpers ─────────────────────────────────────────────────────────────────

add_error() {
  echo "$1"
  echo $(( $(cat "$ERRORS_FILE") + 1 )) > "$ERRORS_FILE"
}

add_warning() {
  echo "$1"
  echo $(( $(cat "$WARNINGS_FILE") + 1 )) > "$WARNINGS_FILE"
}

# Returns .rs files to check under a subdirectory, one per line.
files_to_check() {
  local subdir="${1:-}"
  local base="${SRC}"
  if [[ -n "$subdir" ]]; then
    base="${SRC}/${subdir}"
  fi
  if [[ ! -d "$base" ]]; then
    return
  fi

  if $staged_only; then
    git -C "$REPO_ROOT" diff --cached --name-only --diff-filter=ACMR \
      | grep '\.rs$' \
      | while IFS= read -r f; do
          local full="${REPO_ROOT}/${f}"
          if [[ "$full" == "${base}"/* ]]; then
            echo "$full"
          fi
        done
  else
    find "$base" -name '*.rs' -type f 2>/dev/null
  fi
}

rel() { echo "${1#"${REPO_ROOT}"/}"; }

should_run() {
  [[ ${#checks[@]} -eq 0 ]] || printf '%s\n' "${checks[@]}" | grep -qx "$1"
}

# ── Check 1: Layer 1 must not import observe ────────────────────────────────

if should_run "layer-boundary"; then
  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    while IFS=: read -r line _rest; do
      add_error "[ERROR] layer-boundary: $(rel "$file"):${line} -- observe imported in Layer 1 (primitives)"
    done < <(grep -n 'use crate::observe' "$file" 2>/dev/null || true)
  done < <(files_to_check "primitives")
fi

# ── Check 2: L3 must not re-export primitives functions ─────────────────────

if should_run "unwrapped-fn"; then
  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    [[ "$file" == *"/primitives/"* ]] && continue
    while IFS=: read -r line content; do
      if echo "$content" | grep -qE '[{,]\s*[a-z][a-z0-9_]*'; then
        add_warning "[WARN]  unwrapped-fn: $(rel "$file"):${line} -- possible bare function re-export from primitives"
      fi
    done < <(grep -n 'pub use crate::primitives::' "$file" 2>/dev/null || true)
  done < <(files_to_check)
fi

# ── Check 3: Prohibited naming prefixes in identifiers ──────────────────────

if should_run "naming-prefix"; then
  for subdir in "primitives/identifiers" "identifiers"; do
    while IFS= read -r file; do
      [[ -z "$file" ]] && continue
      while IFS=: read -r line content; do
        fn_name=$(echo "$content" | grep -oE '(has_|contains_|check_|verify_|ensure_|remove_)[a-z_]*' | head -1)
        add_error "[ERROR] naming-prefix: $(rel "$file"):${line} -- prohibited prefix in '${fn_name}'"
      done < <(grep -nE 'pub fn (has_|contains_|check_|verify_|ensure_|remove_)' "$file" 2>/dev/null || true)
    done < <(files_to_check "$subdir")
  done
fi

# ── Check 4: Return type vs prefix mismatches ──────────────────────────────

if should_run "naming-return-type"; then
  for subdir in "primitives/identifiers" "identifiers"; do
    while IFS= read -r file; do
      [[ -z "$file" ]] && continue
      while IFS=: read -r line _content; do
        add_warning "[WARN]  naming-return-type: $(rel "$file"):${line} -- is_* should return bool"
      done < <(grep -nE 'pub fn is_[a-z_]+\(.*\)\s*->\s*(Option|Result|Vec|String)' "$file" 2>/dev/null || true)
      while IFS=: read -r line _content; do
        add_warning "[WARN]  naming-return-type: $(rel "$file"):${line} -- validate_* should return Result"
      done < <(grep -nE 'pub fn validate_[a-z_]+\(.*\)\s*->\s*bool' "$file" 2>/dev/null || true)
    done < <(files_to_check "$subdir")
  done
fi

# ── Check 5: Tests must not allow indexing_slicing ──────────────────────────

if should_run "test-lint"; then
  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    while IFS=: read -r line _rest; do
      add_error "[ERROR] test-lint: $(rel "$file"):${line} -- indexing_slicing must not be allowed (use .get()/.first()/.last())"
    done < <(grep -n 'allow.*clippy::indexing_slicing' "$file" 2>/dev/null || true)
  done < <(files_to_check)
fi

# ── Summary ─────────────────────────────────────────────────────────────────

final_errors=$(cat "$ERRORS_FILE")
final_warnings=$(cat "$WARNINGS_FILE")

if [[ $final_errors -gt 0 ]] || [[ $final_warnings -gt 0 ]]; then
  echo ""
  echo "arch-check: ${final_errors} error(s), ${final_warnings} warning(s)"
fi

if [[ $final_errors -gt 0 ]]; then
  exit 1
fi
