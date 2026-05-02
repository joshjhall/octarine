# Octarine development commands
# Run `just --list` to see all available recipes

set dotenv-load := false

# Default: run check, clippy, and tests
default: check clippy test

# ─── Build & Check ───────────────────────────────────────────────────────────

# Type-check the workspace
check:
    cargo check --workspace

# Build the workspace
build:
    cargo build --workspace

# ─── Lint ────────────────────────────────────────────────────────────────────

# Run clippy with all targets and features, deny warnings
clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings


# Run cargo fmt (check only)
fmt-check:
    cargo fmt --all -- --check

# Run cargo fmt (apply fixes)
fmt:
    cargo fmt --all

# Run all formatters and file fixers via pre-commit on every file in the repo
fmt-all: pre-commit

# ─── SemVer ──────────────────────────────────────────────────────────────────

# Check for breaking public-API changes vs. the main branch baseline.
# Requires origin/main to be fetched (CI uses fetch-depth: 0).
semver-check:
    cargo semver-checks check-release --workspace --baseline-rev origin/main

# ─── Test ────────────────────────────────────────────────────────────────────

# Run all workspace tests (all features — matches `just clippy`)
test:
    cargo test --workspace --all-features -j4

# Run tests with output visible
test-verbose:
    cargo test --workspace --all-features -j4 -- --nocapture

# Run tests for the octarine crate only
test-octarine:
    cargo test -p octarine --all-features -j4

# Run performance/timing tests (ignored by default, run before releases)
test-perf:
    cargo test -p octarine --all-features -j4 test_perf_ -- --ignored
    cargo test -p octarine --all-features -j4 test_adversarial_ -- --ignored
    cargo test -p octarine --all-features -j4 test_batch_processor_time_flush -- --ignored

# Run tests with the testing feature enabled (kept for explicit minimal-feature runs)
test-with-fixtures:
    cargo test -p octarine -j4 --features testing

# Run a specific test by name pattern
test-filter PATTERN:
    cargo test --workspace --all-features -j4 -- {{PATTERN}}

# Run lib unit tests in octarine by module path, optionally enabling features.
# Examples:
#   just test-mod correlation::proximity
#   just test-mod observe::writers::database sqlite,postgres
test-mod PATTERN FEATURES='':
    cargo test -p octarine --lib -j4 --features "{{FEATURES}}" -- {{PATTERN}}

# ─── Architecture ────────────────────────────────────────────────────────────

# Run architecture enforcement checks (layer boundaries, naming, lint rules)
arch-check *ARGS:
    python3 -m scripts.arch_check {{ARGS}}

# Run the pytest suite for arch_check
arch-check-test:
    python3 -m pytest tests/arch_check/ -q

# Lint shell scripts with shellcheck (no-op when no .sh files present)
shellcheck:
    #!/usr/bin/env bash
    set -euo pipefail
    shopt -s nullglob
    files=(scripts/*.sh)
    if [ ${#files[@]} -eq 0 ]; then
        echo "shellcheck: no shell scripts to lint"
    else
        shellcheck "${files[@]}"
    fi

# ─── Pre-flight (run before push / PR) ──────────────────────────────────────

# Full pre-push validation: fmt, clippy, shellcheck, arch-check, tests
preflight: fmt-check clippy shellcheck arch-check test

# Everything including perf tests (run before releases)
preflight-full: preflight test-perf

# ─── Dependencies ────────────────────────────────────────────────────────

# Update Cargo.lock to latest semver-compatible versions
deps-update:
    cargo update
    @echo "Run 'just deps-audit' to check for remaining vulnerabilities"

# Show outdated dependencies
deps-outdated:
    cargo outdated --workspace --depth 1

# Check for known security vulnerabilities
deps-audit:
    cargo audit --ignore RUSTSEC-2023-0071

# Run cargo-deny checks (advisories, licenses, sources)
deps-deny:
    cargo deny check

# Full dependency health check: audit + deny + outdated
deps-check: deps-audit deps-deny deps-outdated

# ─── Utilities ───────────────────────────────────────────────────────────────

# Remove build artifacts
clean:
    cargo clean

# Run all pre-commit hooks on every file (via lefthook)
pre-commit:
    lefthook run pre-commit --all-files

# Count tests (listed, not executed)
test-count:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Counting tests..."
    count=$(cargo test --workspace -j4 -- --list 2>&1 | grep -c ': test$')
    echo "$count tests found"

# ─── Release ────────────────────────────────────────────────────────────────

# Create a release. Accepts either a literal version or a bump keyword:
#   just release 0.3.0              # literal version
#   just release 0.3.0-beta.1       # literal prerelease
#   just release patch              # 0.3.0-beta.3 → 0.3.0 (finalize)
#   just release minor              # 0.3.0-beta.3 → 0.3.0 (finalize)
#   just release major              # 0.3.0-beta.3 → 1.0.0
#   just release beta               # 0.3.0-beta.3 → 0.3.0-beta.4
#   just release rc                 # 0.3.0-beta.3 → 0.3.0-rc.1
#
# Keyword bumps shell out to `python3 -m scripts.release` which owns the
# semver state machine (alpha → beta → rc → stable). See
# docs/releases/versioning.md for the full bump policy.
release ARG:
    #!/usr/bin/env bash
    set -euo pipefail
    ARG="{{ARG}}"

    # Read the current workspace version from Cargo.toml.
    CURRENT=$(/usr/bin/awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)
    if [ -z "$CURRENT" ]; then
        echo "ERROR: could not read current version from Cargo.toml" >&2
        exit 1
    fi

    # Distinguish bump keyword from literal version. Literal versions always
    # contain a dot; keywords never do.
    if [[ "$ARG" == *.* ]]; then
        VERSION="$ARG"
        # Validate the literal via the same parser the helper uses.
        if ! python3 -m scripts.release parse "$VERSION" >/dev/null; then
            exit 1
        fi
    else
        case "$ARG" in
            major|minor|patch|beta|rc) ;;
            *)
                echo "ERROR: '$ARG' is neither a version (X.Y.Z[-pre.N]) nor a bump keyword" >&2
                echo "       Keywords: major | minor | patch | beta | rc" >&2
                exit 1
                ;;
        esac
        VERSION=$(python3 -m scripts.release bump "$ARG" --current "$CURRENT")
    fi

    # Workspace member sync: octarine must inherit the workspace version OR
    # already match it literally. octarine-derive is intentionally untouched
    # (independent versioning policy).
    OCTARINE_LINE=$(/usr/bin/awk '/^version/{print; exit}' crates/octarine/Cargo.toml)
    if [[ "$OCTARINE_LINE" != *"workspace = true"* ]] \
       && [[ "$OCTARINE_LINE" != "version = \"$CURRENT\""* ]]; then
        echo "ERROR: crates/octarine/Cargo.toml version is out of sync with workspace" >&2
        echo "       workspace: $CURRENT" >&2
        echo "       crate:     $OCTARINE_LINE" >&2
        exit 1
    fi

    # Ensure clean working tree
    if [ -n "$(git status --porcelain)" ]; then
        echo "ERROR: Working tree is not clean. Commit or stash changes first." >&2
        exit 1
    fi

    echo "═══ Releasing v$VERSION (from v$CURRENT) ═══"
    echo ""

    # Run full pre-flight validation
    echo "── Running preflight-full ──"
    just preflight-full
    echo ""

    # Get previous tag for changelog generation
    PREV_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")

    # Update version in workspace and crate Cargo.toml
    echo "── Updating versions ──"
    sed -i "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml
    if [[ "$OCTARINE_LINE" != *"workspace = true"* ]]; then
        sed -i "s/^version = \".*\"/version = \"$VERSION\"/" crates/octarine/Cargo.toml
        echo "  crates/octarine/Cargo.toml → $VERSION"
    fi
    echo "  Cargo.toml → $VERSION"

    # Sweep version references in human-readable docs. The list is
    # intentionally explicit and limited to live "current version" callouts —
    # historical references (e.g. "Complete as of vX.Y.Z" in
    # docs/architecture/refactor-plan.md) must not be auto-rewritten.
    # Doctest examples in src/**/*.rs reference major.minor only
    # (e.g. version = "0.2") and are out of scope here.
    echo "── Updating doc version references ──"
    DOC_FILES=(
        README.md
        CONTRIBUTING.md
    )
    for f in "${DOC_FILES[@]}"; do
        if [ -f "$f" ] && grep -q "v$CURRENT" "$f"; then
            sed -i "s|v$CURRENT|v$VERSION|g" "$f"
            echo "  $f"
        fi
    done

    # Regenerate lockfile
    cargo check --workspace --quiet 2>/dev/null

    # Generate changelog entry
    echo "── Generating changelog ──"
    DATE=$(date +%Y-%m-%d)
    ENTRY="## [$VERSION] - $DATE"$'\n'$'\n'"<!-- TODO: review and curate before push -->"$'\n'

    if [ -n "$PREV_TAG" ]; then
        # Conventional-commit prefix → CHANGELOG section. Multiple prefixes can
        # share a section (refactor + chore both → "Changed"); we collect
        # commits per section, then emit each section once with all of them.
        SECTION_ORDER="Added Fixed Changed Documentation Testing Performance CI Build"
        declare -A SECTION_COMMITS
        # Map: prefix → section label
        declare -A PREFIX_SECTION=(
            [feat]=Added
            [fix]=Fixed
            [refactor]=Changed
            [chore]=Changed
            [docs]=Documentation
            [test]=Testing
            [perf]=Performance
            [ci]=CI
            [build]=Build
        )

        for PREFIX in "${!PREFIX_SECTION[@]}"; do
            LABEL="${PREFIX_SECTION[$PREFIX]}"
            COMMITS=$(git log "$PREV_TAG"..HEAD --oneline --grep="^$PREFIX" 2>/dev/null | sed 's/^[a-f0-9]* /- /' || true)
            if [ -n "$COMMITS" ]; then
                if [ -n "${SECTION_COMMITS[$LABEL]:-}" ]; then
                    SECTION_COMMITS[$LABEL]+=$'\n'"$COMMITS"
                else
                    SECTION_COMMITS[$LABEL]="$COMMITS"
                fi
            fi
        done

        for LABEL in $SECTION_ORDER; do
            if [ -n "${SECTION_COMMITS[$LABEL]:-}" ]; then
                ENTRY+=$'\n'"### $LABEL"$'\n'$'\n'"${SECTION_COMMITS[$LABEL]}"$'\n'
            fi
        done

        # Catch any commits that don't match conventional prefixes
        OTHER=$(git log "$PREV_TAG"..HEAD --oneline --invert-grep \
            --grep="^feat" --grep="^fix" --grep="^refactor" --grep="^docs" \
            --grep="^test" --grep="^perf" --grep="^ci" --grep="^build" \
            --grep="^release" --grep="^chore" 2>/dev/null | sed 's/^[a-f0-9]* /- /' || true)
        if [ -n "$OTHER" ]; then
            ENTRY+=$'\n'"### Other"$'\n'$'\n'"$OTHER"$'\n'
        fi
    else
        ENTRY+=$'\n'"Initial release."$'\n'
    fi

    # Prepend to CHANGELOG.md (preserve existing content)
    if [ -f CHANGELOG.md ]; then
        # Insert after the header lines (first 4 lines: title, blank, description, blank)
        HEAD_LINES=$(head -4 CHANGELOG.md)
        TAIL_LINES=$(tail -n +5 CHANGELOG.md)
        printf '%s\n\n%s\n%s\n' "$HEAD_LINES" "$ENTRY" "$TAIL_LINES" > CHANGELOG.md
    else
        printf '# Changelog\n\nAll notable changes to octarine will be documented in this file.\n\n%s\n' "$ENTRY" > CHANGELOG.md
    fi
    echo "  CHANGELOG.md updated"

    # Commit and tag
    # Lefthook hooks may fix formatting (e.g., trailing newlines). If the first
    # commit fails because hooks modified files, re-stage and retry once.
    echo "── Committing ──"
    git add Cargo.toml crates/octarine/Cargo.toml Cargo.lock CHANGELOG.md
    for f in "${DOC_FILES[@]}"; do
        if [ -f "$f" ]; then git add "$f"; fi
    done
    if ! git commit -m "release: v$VERSION"; then
        echo "  Lefthook hooks modified files, retrying..."
        git add Cargo.toml crates/octarine/Cargo.toml Cargo.lock CHANGELOG.md
        for f in "${DOC_FILES[@]}"; do
            if [ -f "$f" ]; then git add "$f"; fi
        done
        git commit -m "release: v$VERSION"
    fi
    git tag -a "v$VERSION" -m "Release v$VERSION"
    echo "  Tagged v$VERSION"

    # Determine if pre-release
    PRERELEASE_FLAG=""
    if [[ "$VERSION" == *-* ]]; then
        PRERELEASE_FLAG=" --prerelease"
    fi

    echo ""
    echo "═══ Release v$VERSION ready ═══"
    echo ""
    echo "Review the new CHANGELOG entry (look for the 'TODO: review' marker)"
    echo "and amend the commit if needed before pushing."
    echo ""
    echo "Next steps:"
    echo "  git push && git push --tags"
    echo "  gh release create v$VERSION$PRERELEASE_FLAG --generate-notes"

# Preview a release without touching disk. Prints the proposed version, the
# doc files that would be rewritten, and a snapshot of commits since the last
# tag. Use this to smoke-test bump keywords before running the real release.
release-preview ARG:
    #!/usr/bin/env bash
    set -euo pipefail
    ARG="{{ARG}}"

    CURRENT=$(/usr/bin/awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)
    if [[ "$ARG" == *.* ]]; then
        VERSION="$ARG"
        if ! python3 -m scripts.release parse "$VERSION" >/dev/null; then
            exit 1
        fi
    else
        case "$ARG" in
            major|minor|patch|beta|rc) ;;
            *)
                echo "ERROR: '$ARG' is neither a version nor a bump keyword" >&2
                exit 1
                ;;
        esac
        VERSION=$(python3 -m scripts.release bump "$ARG" --current "$CURRENT")
    fi

    PREV_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")

    echo "Current: v$CURRENT"
    echo "New:     v$VERSION"
    echo ""
    echo "Doc files that would be rewritten (v$CURRENT → v$VERSION):"
    DOC_FILES=(
        README.md
        CONTRIBUTING.md
    )
    for f in "${DOC_FILES[@]}"; do
        if [ -f "$f" ] && grep -q "v$CURRENT" "$f"; then
            count=$(grep -c "v$CURRENT" "$f")
            echo "  $f  ($count occurrence(s))"
        fi
    done
    echo ""
    if [ -n "$PREV_TAG" ]; then
        echo "Commits since $PREV_TAG:"
        git log "$PREV_TAG"..HEAD --oneline | head -20
    else
        echo "No prior tag — this would be the initial release."
    fi

# Run the pytest suite for the release helper.
release-test:
    python3 -m pytest tests/release/ -q
