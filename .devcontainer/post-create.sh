#!/usr/bin/env bash
# post-create.sh — Runs once when the devcontainer is first created.
# Install development tools and warm caches so subsequent starts are fast.

set -euo pipefail

echo "==> Verifying lefthook..."
# lefthook is preinstalled in the devcontainer via the containers submodule.
command -v lefthook >/dev/null || {
  echo "ERROR: lefthook not on PATH"
  exit 1
}

# .cargo/config.toml sets linker = "clang" + -fuse-ld=mold for Linux. mold
# ships with the containers submodule's rust-dev feature; clang does not
# (only libclang-dev for bindgen), so install it explicitly. Without this,
# `cargo test` and rustdoc fail to link.
if ! command -v clang >/dev/null; then
  echo "==> Installing clang (needed by .cargo/config.toml linker setting)..."
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends clang
fi

echo "==> Warming cargo cache..."
cargo fetch --manifest-path /workspace/octarine/Cargo.toml

# Build the CodeGraph code-intelligence index so the MCP server has a graph to
# query on first use. .codegraph/ is gitignored, so a freshly created container
# has no index until this runs.
if command -v codegraph >/dev/null; then
  if [ -f /workspace/octarine/.codegraph/codegraph.db ]; then
    echo "==> CodeGraph index already present; syncing..."
    codegraph sync /workspace/octarine || echo "WARN: codegraph sync failed (non-fatal)"
  else
    echo "==> Initializing CodeGraph index..."
    codegraph init /workspace/octarine || echo "WARN: codegraph init failed (non-fatal)"
  fi
else
  echo "WARN: codegraph not on PATH; skipping index build."
fi

echo "==> Post-create setup complete."
