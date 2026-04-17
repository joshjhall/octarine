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

# ─── Test ────────────────────────────────────────────────────────────────────

# Run all workspace tests
test:
    cargo test --workspace -j4

# Run tests with output visible
test-verbose:
    cargo test --workspace -j4 -- --nocapture

# Run tests for the octarine crate only
test-octarine:
    cargo test -p octarine -j4

# Run performance/timing tests (ignored by default, run before releases)
test-perf:
    cargo test -p octarine -j4 test_perf_ -- --ignored
    cargo test -p octarine -j4 test_adversarial_ -- --ignored
    cargo test -p octarine -j4 test_batch_processor_time_flush -- --ignored

# Run tests with the testing feature enabled
test-with-fixtures:
    cargo test -p octarine -j4 --features testing

# Run a specific test by name pattern
test-filter PATTERN:
    cargo test --workspace -j4 -- {{PATTERN}}

# Run lib unit tests in octarine by module path, optionally enabling features.
# Examples:
#   just test-mod correlation::proximity
#   just test-mod observe::writers::database sqlite,postgres
test-mod PATTERN FEATURES='':
    cargo test -p octarine --lib -j4 --features "{{FEATURES}}" -- {{PATTERN}}

# ─── Architecture ────────────────────────────────────────────────────────────

# Run architecture enforcement checks (layer boundaries, naming, lint rules)
arch-check:
    bash scripts/arch-check.sh

# Lint shell scripts with shellcheck
shellcheck:
    shellcheck scripts/*.sh

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

# Run pre-commit hooks on all files
pre-commit:
    pre-commit run --all-files

# Count tests (listed, not executed)
test-count:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Counting tests..."
    count=$(cargo test --workspace -j4 -- --list 2>&1 | grep -c ': test$')
    echo "$count tests found"

# ─── Release ────────────────────────────────────────────────────────────────

# Create a release: just release 0.3.0 or just release 0.3.0-beta.1
release VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="{{VERSION}}"

    # Validate semver format (X.Y.Z or X.Y.Z-prerelease.N)
    if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-z]+\.[0-9]+)?$ ]]; then
        echo "ERROR: Invalid version '$VERSION'"
        echo "Expected: X.Y.Z or X.Y.Z-{alpha,beta,rc}.N"
        exit 1
    fi

    # Ensure clean working tree
    if [ -n "$(git status --porcelain)" ]; then
        echo "ERROR: Working tree is not clean. Commit or stash changes first."
        exit 1
    fi

    echo "═══ Releasing v$VERSION ═══"
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
    sed -i "s/^version = \".*\"/version = \"$VERSION\"/" crates/octarine/Cargo.toml
    echo "  Cargo.toml → $VERSION"
    echo "  crates/octarine/Cargo.toml → $VERSION"

    # Regenerate lockfile
    cargo check --workspace --quiet 2>/dev/null

    # Generate changelog entry
    echo "── Generating changelog ──"
    DATE=$(date +%Y-%m-%d)
    ENTRY="## [$VERSION] - $DATE"$'\n'

    if [ -n "$PREV_TAG" ]; then
        # Group commits by conventional commit type
        for TYPE_LABEL in "feat:Added" "fix:Fixed" "refactor:Changed" "docs:Documentation" "test:Testing" "perf:Performance" "ci:CI" "build:Build"; do
            PREFIX="${TYPE_LABEL%%:*}"
            LABEL="${TYPE_LABEL##*:}"
            COMMITS=$(git log "$PREV_TAG"..HEAD --oneline --grep="^$PREFIX" 2>/dev/null | sed 's/^[a-f0-9]* /- /' || true)
            if [ -n "$COMMITS" ]; then
                ENTRY+=$'\n'"### $LABEL"$'\n'$'\n'"$COMMITS"$'\n'
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
    # Pre-commit hooks may fix formatting (e.g., trailing newlines). If the first
    # commit fails because hooks modified files, re-stage and retry once.
    echo "── Committing ──"
    git add Cargo.toml crates/octarine/Cargo.toml Cargo.lock CHANGELOG.md
    if ! git commit -m "release: v$VERSION"; then
        echo "  Pre-commit hooks modified files, retrying..."
        git add Cargo.toml crates/octarine/Cargo.toml Cargo.lock CHANGELOG.md
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
    echo "Next steps:"
    echo "  git push && git push --tags"
    echo "  gh release create v$VERSION$PRERELEASE_FLAG --generate-notes"
