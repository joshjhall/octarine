#!/usr/bin/env bash
# post-create.sh — Runs once when the devcontainer is first created.
# Install development tools and warm caches so subsequent starts are fast.

set -euo pipefail

echo "==> Installing pre-commit..."
pipx install pre-commit

echo "==> Warming cargo cache..."
cargo fetch --manifest-path /workspace/octarine/Cargo.toml

echo "==> Post-create setup complete."
