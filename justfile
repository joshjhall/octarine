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

# ─── Pre-flight (run before push / PR) ──────────────────────────────────────

# Full pre-push validation: fmt, clippy, tests
preflight: fmt-check clippy test

# Everything including perf tests (run before releases)
preflight-full: preflight test-perf

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
