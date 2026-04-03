#!/usr/bin/env bash
# post-start.sh — Runs every time the devcontainer starts.
# Configures git identity, CLI auth, and installs git hooks.

set -euo pipefail

# --- Git & CLI setup (from containers submodule) ---
echo "==> Configuring git..."
setup-git

echo "==> Configuring glab..."
setup-glab

# --- Git hooks via pre-commit ---
if command -v pre-commit &>/dev/null; then
    echo "==> Installing pre-commit hooks..."
    # pre-commit refuses to install when core.hooksPath is set
    git config --unset-all core.hooksPath 2>/dev/null || true
    pre-commit install --install-hooks
    pre-commit install --hook-type pre-push
else
    echo "WARN: pre-commit not found. Run post-create.sh first or: pipx install pre-commit"
fi

echo "==> Post-start setup complete."
