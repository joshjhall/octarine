#!/usr/bin/env bash
# post-start.sh — Runs every time the devcontainer starts.
# Configures git identity, CLI auth, and installs git hooks.

set -euo pipefail

# --- Git & CLI setup (from containers submodule) ---
echo "==> Configuring git..."
setup-git

echo "==> Configuring glab..."
setup-glab

# --- Git hooks via lefthook ---
if command -v lefthook &>/dev/null; then
    echo "==> Installing lefthook hooks..."
    # lefthook refuses to install when core.hooksPath is set
    git config --unset-all core.hooksPath 2>/dev/null || true
    lefthook install
else
    echo "WARN: lefthook not found. Check that the containers submodule is present."
fi

echo "==> Post-start setup complete."
