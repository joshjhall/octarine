#!/usr/bin/env bash
# post-create.sh — Runs once when the devcontainer is first created.
# Install development tools and warm caches so subsequent starts are fast.

set -euo pipefail

echo "==> Verifying lefthook..."
# lefthook is preinstalled in the devcontainer via the containers submodule.
command -v lefthook >/dev/null || { echo "ERROR: lefthook not on PATH"; exit 1; }

echo "==> Warming cargo cache..."
cargo fetch --manifest-path /workspace/octarine/Cargo.toml

echo "==> Post-create setup complete."
