---
name: project_worktree_submodule_hooks
description: Commits in a fresh worktree fail lefthook 127 until the containers submodule is force-checked-out
metadata:
  node_type: memory
  type: project
  originSessionId: b69a3d43-768e-47d7-b552-7eead8b1865c
---

The `containers` submodule is configured `update = none` in `.gitmodules`, so a
freshly-created git worktree does NOT populate it. The lefthook `pre-commit`
auto-fixers `trailing-whitespace` and `end-of-file-fixer` call
`containers/bin/fix-trailing-whitespace.sh` / `fix-end-of-file.sh`; when the
submodule is absent both exit 127 and block every commit.

**Fix:** `git submodule update --init --force --checkout containers` in the
worktree (plain `--init` is skipped because of `update = none`; `--force` is
required). The submodule checks out at its pinned SHA, so it shows no diff and
needs no commit. Content hooks (rumdl, typos, gitleaks, conform) are unaffected
and pass independently.

**Why:** worktrees don't inherit submodule working trees; only `.git/modules`
is shared.

**How to apply:** when a worktree commit dies with `containers/bin/*.sh: not
found` / `exit status 127`, run the force-checkout above and retry — it is
infra, not a problem with the diff.
