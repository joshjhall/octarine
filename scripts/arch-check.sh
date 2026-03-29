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

# ── Check 6: Types re-exported by L3 must be pub use in primitives ─────
#
# If L3 does `pub use crate::primitives::X::Y` for a type, then Y must be
# `pub use` (not `pub(crate) use`) in the primitives module — otherwise
# rustc rejects it with E0365.  This catches the mismatch before compile.

if should_run "type-visibility"; then
  declare -A pubcrate_types=()

  # Phase 1: collect PascalCase names that are pub(crate) use in primitives mod.rs files.
  # Collapse multi-line use statements (pub(crate) use X::{\n  A,\n  B\n};) into
  # single lines so we capture all imported names.
  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    # Collapse multi-line use statements: join lines between { and }
    collapsed=$(perl -0777 -pe 's/pub\(crate\)\s+use\s+[^;]+/($& =~ s!\n! !gr)/ge' "$file" 2>/dev/null)
    while IFS= read -r use_line; do
      [[ -z "$use_line" ]] && continue
      # Extract PascalCase names, skip Builder names
      for name in $(echo "$use_line" | grep -oE '\b[A-Z][a-zA-Z0-9]+\b' | grep -vE 'Builder$' || true); do
        pubcrate_types["$name"]="$(rel "$file")"
      done
    done < <(echo "$collapsed" | grep 'pub(crate) use' || true)
  done < <(find "$SRC/primitives" -name 'mod.rs' -type f 2>/dev/null)

  # Phase 2: collect PascalCase names that L3 tries to pub use from primitives
  declare -A l3_pub_types=()
  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    [[ "$file" == *"/primitives/"* ]] && continue
    collapsed=$(perl -0777 -pe 's/pub\s+use\s+crate::primitives::[^;]+/($& =~ s!\n! !gr)/ge' "$file" 2>/dev/null)
    while IFS= read -r use_line; do
      [[ -z "$use_line" ]] && continue
      for name in $(echo "$use_line" | grep -oE '\b[A-Z][a-zA-Z0-9]+\b' | grep -vE 'Builder$' || true); do
        l3_pub_types["$name"]="$(rel "$file")"
      done
    done < <(echo "$collapsed" | grep 'pub use crate::primitives::' || true)
  done < <(files_to_check)

  # Phase 3: cross-reference — error when L3 tries to publicly expose a pub(crate) type
  for name in "${!pubcrate_types[@]}"; do
    if [[ -n "${l3_pub_types[$name]:-}" ]]; then
      add_error "[ERROR] type-visibility: ${pubcrate_types[$name]} -- '${name}' is pub(crate) in primitives but L3 tries pub use at ${l3_pub_types[$name]}"
    fi
  done
fi

# ── Check 7: Builders/functions in primitives must be pub(crate) use ───
#
# Business logic (builders, functions) in primitives aggregator mod.rs
# files should use pub(crate) use so users go through L3 observe wrappers.
# Types are allowed as pub use since they carry no logic.

if should_run "builder-visibility"; then
  for modfile in "$SRC/primitives/mod.rs" "$SRC"/primitives/*/mod.rs; do
    [[ -f "$modfile" ]] || continue
    while IFS=: read -r line content; do
      # Skip comment lines
      echo "$content" | grep -qE '^\s*//' && continue
      # Skip pub(crate) use — those are already correct
      echo "$content" | grep -q 'pub(crate)' && continue

      # Flag Builder names
      for name in $(echo "$content" | grep -oE '\b[A-Z][a-zA-Z0-9]*Builder\b' || true); do
        add_warning "[WARN]  builder-visibility: $(rel "$modfile"):${line} -- '${name}' should use pub(crate) use in primitives (business logic must go through L3 wrappers)"
      done

      # Flag snake_case function names inside braces (the actual imported items)
      if echo "$content" | grep -q '{'; then
        local_items=$(echo "$content" | sed 's/.*{//' | sed 's/}.*//')
        for fn_name in $(echo "$local_items" | grep -oE '\b[a-z][a-z0-9_]+\b' | grep -vE '^(self|super|crate|as|use|pub|mod)$' || true); do
          add_warning "[WARN]  builder-visibility: $(rel "$modfile"):${line} -- '${fn_name}' (function) should use pub(crate) use in primitives"
        done
      fi
    done < <(grep -n 'pub use' "$modfile" 2>/dev/null | grep -v 'pub(crate)' || true)
  done
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
