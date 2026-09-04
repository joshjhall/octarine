#!/usr/bin/env bash
# post-start.sh — Runs every time the devcontainer starts.
# Configures git identity, CLI auth, and installs git hooks.

set -euo pipefail

# --- postCreateCommand recovery (Zed) ---
# Zed's native devcontainer implementation runs postStartCommand but not
# postCreateCommand, so one-time setup (notably the clang install that
# .cargo/config.toml's linker setting depends on) never happens and every
# cargo link step fails. VS Code runs postCreateCommand before this script,
# so the marker already exists and this is a no-op. post-create.sh is
# idempotent, making the replay safe in either editor.
# See containers/docs/troubleshooting/zed-devcontainer.md.
if [ ! -f "$HOME/.post-create-complete" ]; then
  echo "==> post-create marker missing (likely Zed); running post-create.sh..."
  bash /workspace/octarine/.devcontainer/post-create.sh
fi

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
