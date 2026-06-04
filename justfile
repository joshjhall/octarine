# Octarine development commands
# Run `just --list` to see all available recipes

set dotenv-load := false

# Default: run check, clippy, and tests
default: check clippy test

# ─── Build & Check ───────────────────────────────────────────────────────────

# Type-check the workspace (matches CI flag set — see check-windows / check-macos)
check:
    cargo check --workspace --all-features

# Build the workspace
build:
    cargo build --workspace

# Generate rustdoc with warnings denied (matches CI doc job)
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

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

# Check YAML/JSON formatting via dprint (no fixes)
fmt-data-check:
    dprint check

# Format YAML/JSON via dprint
fmt-data:
    dprint fmt

# Check TOML formatting via taplo (no fixes; config: .taplo.toml)
fmt-toml-check:
    taplo format --check

# Format TOML via taplo (writes; config: .taplo.toml)
fmt-toml:
    taplo format

# Lint TOML schema correctness via taplo (config: .taplo.toml)
lint-toml:
    taplo lint

# Run all formatters and file fixers via pre-commit on every file in the repo
fmt-all: pre-commit

# ─── Spell check ─────────────────────────────────────────────────────────────

# Spell-check the repo with typos (read-only; non-zero exit on findings)
spell:
    typos

# Apply typos fixes (prompts before writing changes)
spell-fix:
    typos --write-changes

# ─── SemVer ──────────────────────────────────────────────────────────────────

# Check for breaking public-API changes vs. the main branch baseline.
# Requires origin/main to be fetched (CI uses fetch-depth: 0).
semver-check:
    cargo semver-checks check-release --workspace --baseline-rev origin/main

# ─── Test ────────────────────────────────────────────────────────────────────

# Run all workspace tests + doctests (all features — matches `just clippy`).
# Tests run under cargo-nextest; doctests run via `cargo test --doc` because
# nextest cannot drive doctests.
test: test-nextest test-docs

# Run nextest-managed tests (everything except doctests)
test-nextest:
    cargo nextest run --workspace --all-features --build-jobs 4

# Run doctests via cargo (nextest cannot run doctests)
test-docs:
    cargo test --workspace --all-features --doc -j4

# Run tests with output visible
test-verbose:
    cargo nextest run --workspace --all-features --build-jobs 4 --no-capture

# Run tests for the octarine crate only
test-octarine:
    cargo nextest run -p octarine --all-features --build-jobs 4

# Run performance/timing tests (ignored by default, run before releases).
# Filterset unions three regex patterns matched against the prior cargo
# substring filters, in a single nextest invocation.
test-perf:
    cargo nextest run -p octarine --all-features --build-jobs 4 --run-ignored ignored-only \
        -E 'test(/^test_perf_/) + test(/^test_adversarial_/) + test(test_batch_processor_time_flush)'

# Run tests with the testing feature enabled (kept for explicit minimal-feature runs)
test-with-fixtures:
    cargo nextest run -p octarine --build-jobs 4 --features testing

# Run a specific test by name pattern
test-filter PATTERN:
    cargo nextest run --workspace --all-features --build-jobs 4 -E 'test(/{{PATTERN}}/)'

# Run lib unit tests in octarine by module path, optionally enabling features.
# Examples:
#   just test-mod correlation::proximity
#   just test-mod observe::writers::database sqlite,postgres
test-mod PATTERN FEATURES='':
    cargo nextest run -p octarine --lib --build-jobs 4 --features "{{FEATURES}}" -E 'test(/{{PATTERN}}/)'

# ─── Coverage ────────────────────────────────────────────────────────────────

# Generate LCOV coverage report (target/coverage/lcov.info).
# Matches the CI coverage job flag set.
coverage:
    mkdir -p target/coverage
    cargo llvm-cov --workspace --all-features -j4 \
        --lcov --output-path target/coverage/lcov.info

# Generate an HTML coverage report (target/llvm-cov/html/index.html).
coverage-html:
    cargo llvm-cov --workspace --all-features -j4 --html
    @echo ""
    @echo "Open: target/llvm-cov/html/index.html"

# Print a short coverage summary to the console.
coverage-summary:
    cargo llvm-cov --workspace --all-features -j4 --summary-only

# ─── Inner-loop ──────────────────────────────────────────────────────────────

# Launch bacon for continuous background checks (config: .bacon.toml).
# Default job is `check`; press `c` for clippy, `t` for test, `d` for rustdoc,
# `?` for shortcuts. Pass extra args, e.g. `just bacon clippy`,
# `just bacon test-filter -- some::module`, `just bacon --headless`.
bacon *ARGS:
    bacon {{ARGS}}

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

# Format shell scripts with shfmt (no-op when no .sh files present; submodule excluded)
fmt-sh:
    #!/usr/bin/env bash
    set -euo pipefail
    files=$(git ls-files | /usr/bin/grep -E '\.sh$' || true)
    if [ -z "$files" ]; then
        echo "shfmt: no shell scripts to format"
    else
        echo "$files" | xargs shfmt -w -i 2 -ci -bn
    fi

# Check shell script formatting with shfmt (no-op when no .sh files present; submodule excluded)
fmt-sh-check:
    #!/usr/bin/env bash
    set -euo pipefail
    files=$(git ls-files | /usr/bin/grep -E '\.sh$' || true)
    if [ -z "$files" ]; then
        echo "shfmt: no shell scripts to check"
    else
        echo "$files" | xargs shfmt -d -i 2 -ci -bn
    fi

# Lint Dockerfiles with hadolint (no-op when no repo-local Dockerfiles present; submodule excluded)
lint-docker:
    #!/usr/bin/env bash
    set -euo pipefail
    files=$(git ls-files | /usr/bin/grep -E '(^|/)Dockerfile([.-].+)?$' || true)
    if [ -z "$files" ]; then
        echo "hadolint: no Dockerfiles to lint"
    else
        echo "$files" | xargs hadolint
    fi

# Lint Markdown with rumdl (config: .rumdl.toml; submodule excluded there)
lint-md:
    rumdl check .

# Format Markdown with rumdl (writes; review diff before committing)
fmt-md:
    rumdl fmt .

# Lint GitHub Actions workflows with actionlint (embedded shellcheck at warning severity)
lint-workflows:
    actionlint -shellcheck "shellcheck --severity=warning"

# Lint a commit message against the conform policy (default: HEAD's message)
commit-lint FILE='.git/COMMIT_EDITMSG':
    conform enforce --commit-msg-file {{FILE}}

# Lint every commit on this branch against origin/main
commit-lint-branch:
    conform enforce --base-branch origin/main

# ─── Pre-flight (run before push / PR) ──────────────────────────────────────

# Full pre-push validation: fmt, clippy, shellcheck, lint-docker, lint-md, lint-workflows, lint-toml, lint-deps, spell, arch-check, tests
preflight: fmt-check fmt-data-check fmt-toml-check fmt-sh-check clippy shellcheck lint-docker lint-md lint-workflows lint-toml lint-deps spell arch-check test

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
    cargo audit --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2023-0089

# Run cargo-deny checks (advisories, licenses, sources)
deps-deny:
    cargo deny check

# Check workspace lockfile against OSV.dev (RustSec + GHSA + cross-ecosystem)
deps-osv:
    osv-scanner scan source --lockfile=Cargo.lock

# Full dependency health check: audit + deny + osv + outdated
deps-check: deps-audit deps-deny deps-osv deps-outdated

# Detect unused workspace dependencies. Scopes to our crates only so the
# containers submodule's Cargo.toml files (and any future workspace
# additions) don't surface false positives. Exit 0 = clean; exit 1 =
# unused deps found.
lint-deps:
    cargo machete --skip-target-dir crates/octarine crates/octarine-derive crates/octarine-problem

# Surface past-due "re-evaluate YYYY-MM-DD" markers on advisory ignores in
# deny.toml. Exit 0 = nothing due; exit 1 = at least one past-due marker.
# Used by `just quarterly` and safe to wire into preflight later.
deps-expiry-check:
    #!/usr/bin/env bash
    set -euo pipefail
    today=$(date +%Y-%m-%d)
    overdue=0
    while IFS= read -r line; do
        match=$(echo "$line" | /usr/bin/grep -oE 're-evaluate [0-9]{4}-[0-9]{2}-[0-9]{2}' || true)
        [ -z "$match" ] && continue
        marker_date=${match#re-evaluate }
        if [[ "$marker_date" < "$today" ]]; then
            echo "PAST DUE ($marker_date): $line"
            overdue=$((overdue + 1))
        fi
    done < <(/usr/bin/grep -E 're-evaluate [0-9]{4}-[0-9]{2}-[0-9]{2}' deny.toml || true)
    if [ "$overdue" -eq 0 ]; then
        echo "deps-expiry-check: no past-due re-evaluate markers"
    else
        echo "deps-expiry-check: $overdue past-due marker(s) — review deny.toml" >&2
        exit 1
    fi

# ─── Quarterly (long-cycle review) ───────────────────────────────────────────

# Composite deep-scan recipe for the quarterly review checklist. Runs each
# tool independently (non-halting) so one tool's exit code does not mask
# another's; emits a per-section header and a final pass/fail summary.
#
# Differs from `deps-check` in that:
#   - cargo audit runs WITHOUT --ignore so RUSTSEC-2023-0071 surfaces for
#     human re-evaluation (its re-evaluate date is in deny.toml).
#   - Adds cargo tree --duplicates, license inventory, advisory-expiry
#     check, and optional cargo-geiger.
#
# See CONTRIBUTING.md "Maintenance Cadence" for the quarterly workflow.
quarterly:
    #!/usr/bin/env bash
    set -uo pipefail
    sections=()
    statuses=()
    run() {
        local label=$1
        shift
        echo ""
        echo "══ $label ═══════════════════════════════════════════════════════════"
        if "$@"; then
            sections+=("$label")
            statuses+=("PASS")
        else
            sections+=("$label")
            statuses+=("FAIL")
        fi
    }
    echo "Quarterly review — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    run "cargo audit (no --ignore)"       cargo audit
    run "cargo deny check"                cargo deny check
    run "osv-scanner"                     osv-scanner scan source --lockfile=Cargo.lock
    run "cargo outdated"                  cargo outdated --workspace --depth 1
    run "cargo tree --duplicates"         cargo tree --duplicates --workspace
    run "cargo deny list (licenses)"      cargo deny list
    if command -v cargo-geiger >/dev/null 2>&1; then
        run "cargo geiger (unsafe scan)"  cargo geiger --workspace
    else
        echo ""
        echo "── cargo geiger: not installed, skipping ──"
    fi
    run "deps-expiry-check"               just deps-expiry-check
    echo ""
    echo "══ Summary ══════════════════════════════════════════════════════════"
    fail_count=0
    for i in "${!sections[@]}"; do
        printf '  %-35s %s\n' "${sections[$i]}" "${statuses[$i]}"
        [ "${statuses[$i]}" = "FAIL" ] && fail_count=$((fail_count + 1))
    done
    echo ""
    if [ "$fail_count" -eq 0 ]; then
        echo "All sections passed. Continue with the human-judgment checklist in the quarterly reminder issue."
    else
        echo "$fail_count section(s) reported findings — review output above and triage into issues."
    fi

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
    count=$(cargo nextest list --workspace --all-features 2>&1 | /usr/bin/grep -cE '^\s+[A-Za-z]' || true)
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

    # Workspace member sync: octarine and octarine-problem must inherit the
    # workspace version OR already match it literally. octarine-derive is
    # intentionally untouched (independent versioning policy) but its
    # workspace-deps spec in root Cargo.toml must match its crate manifest
    # — drift there would break `cargo publish`.
    OCTARINE_LINE=$(/usr/bin/awk '/^version/{print; exit}' crates/octarine/Cargo.toml)
    if [[ "$OCTARINE_LINE" != *"workspace = true"* ]] \
       && [[ "$OCTARINE_LINE" != "version = \"$CURRENT\""* ]]; then
        echo "ERROR: crates/octarine/Cargo.toml version is out of sync with workspace" >&2
        echo "       workspace: $CURRENT" >&2
        echo "       crate:     $OCTARINE_LINE" >&2
        exit 1
    fi

    PROBLEM_LINE=$(/usr/bin/awk '/^version/{print; exit}' crates/octarine-problem/Cargo.toml)
    if [[ "$PROBLEM_LINE" != *"workspace = true"* ]] \
       && [[ "$PROBLEM_LINE" != "version = \"$CURRENT\""* ]]; then
        echo "ERROR: crates/octarine-problem/Cargo.toml version is out of sync with workspace" >&2
        echo "       workspace: $CURRENT" >&2
        echo "       crate:     $PROBLEM_LINE" >&2
        exit 1
    fi

    DERIVE_CRATE_VERSION=$(/usr/bin/awk '/^version/{gsub(/^version = "|"$/, "", $0); print; exit}' crates/octarine-derive/Cargo.toml)
    DERIVE_WS_VERSION=$(/usr/bin/awk '/^octarine-derive = /{match($0, /version = "[^"]+"/); print substr($0, RSTART+11, RLENGTH-12); exit}' Cargo.toml)
    if [ "$DERIVE_CRATE_VERSION" != "$DERIVE_WS_VERSION" ]; then
        echo "ERROR: octarine-derive version drift between manifest and workspace deps" >&2
        echo "       crates/octarine-derive/Cargo.toml: $DERIVE_CRATE_VERSION" >&2
        echo "       Cargo.toml [workspace.dependencies]: $DERIVE_WS_VERSION" >&2
        echo "       Fix by editing Cargo.toml so workspace dep matches the crate manifest." >&2
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
    if [[ "$PROBLEM_LINE" != *"workspace = true"* ]]; then
        sed -i "s/^version = \".*\"/version = \"$VERSION\"/" crates/octarine-problem/Cargo.toml
        echo "  crates/octarine-problem/Cargo.toml → $VERSION"
    fi
    # Workspace dep specs in root Cargo.toml carry literal versions alongside
    # `path = ...` so `cargo publish` accepts the workspace. Keep them in
    # lockstep with the crate manifests they point to. octarine-derive is
    # independently versioned and never touched here.
    sed -i "s|^octarine = { path = \"crates/octarine\", version = \"[^\"]*\" }|octarine = { path = \"crates/octarine\", version = \"$VERSION\" }|" Cargo.toml
    sed -i "s|^octarine-problem = { path = \"crates/octarine-problem\", version = \"[^\"]*\" }|octarine-problem = { path = \"crates/octarine-problem\", version = \"$VERSION\" }|" Cargo.toml
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
    git add Cargo.toml crates/octarine/Cargo.toml crates/octarine-problem/Cargo.toml Cargo.lock CHANGELOG.md
    for f in "${DOC_FILES[@]}"; do
        if [ -f "$f" ]; then git add "$f"; fi
    done
    if ! git commit -m "release: v$VERSION"; then
        echo "  Lefthook hooks modified files, retrying..."
        git add Cargo.toml crates/octarine/Cargo.toml crates/octarine-problem/Cargo.toml Cargo.lock CHANGELOG.md
        for f in "${DOC_FILES[@]}"; do
            if [ -f "$f" ]; then git add "$f"; fi
        done
        git commit -m "release: v$VERSION"
    fi
    git tag -a "v$VERSION" -m "Release v$VERSION"
    echo "  Tagged v$VERSION"

    # Determine if pre-release
    echo ""
    echo "═══ Release v$VERSION ready ═══"
    echo ""
    echo "Review the new CHANGELOG entry (look for the 'TODO: review' marker)"
    echo "and amend the commit if needed before pushing."
    echo ""
    echo "Next steps:"
    echo "  git push && git push --tags"
    echo ""
    echo "The release workflow takes over from there — it publishes all three"
    echo "crates to crates.io and creates a GitHub Release. Monitor it at:"
    echo "  https://github.com/joshjhall/octarine/actions/workflows/release.yml"

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
