---
name: project_worktree_submodule_hooks
description: Commits in a fresh worktree fail lefthook 127 until the containers submodule is force-checked-out
metadata:
  node_type: memory
  type: project
  originSessionId: b69a3d43-768e-47d7-b552-7eead8b1865c
  modified: 2026-09-05T21:05:00.503Z
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

**Teardown cost of the fix:** once `containers` is populated, `worktree-rm.sh`
fails at the end of the run — `git worktree remove` refuses with *"working
trees containing submodules cannot be moved or removed"*, and `--force` then
hits *"Directory not empty"*. `git submodule deinit` does not help (it reports
`fatal: not a git repository` against the worktree). Just `rm -rf
<worktree>/containers` first, then re-run `worktree-rm.sh`; it removes the
worktree and the local branch normally.

Two follow-ons on this teardown path, both harmless but worth expecting:
`worktree-rm.sh` may leave `target/` behind ("N entries could not be removed"
on the bindfs/FUSE overlay) — nothing git-tracked survives, and `git worktree
list` is the authority on whether cleanup actually succeeded. And `git push
origin --delete <branch>` can hang past a 2-minute timeout here; `gh api -X
DELETE repos/<owner>/<repo>/git/refs/heads/<branch>` returns immediately.
Verify either way with `git ls-remote --heads origin <branch> | wc -l` → 0.
