---
name: project_worktree_rm_submodule_target
description: worktree-rm.sh fails when the containers submodule is initialized; recovery leaves an undeletable target/ remnant
metadata:
  node_type: memory
  type: project
  originSessionId: 5d2337d9-008e-449d-b373-9b64ecb12fe8
  modified: 2026-09-06T05:28:21.462Z
---

`worktree-rm.sh N` fails on a clean worktree with:

```text
fatal: working trees containing submodules cannot be moved or removed
then, with --force: error: failed to delete '...': Directory not empty
```

This fires whenever `git submodule update --init containers` was run in the
worktree — which [[project_worktree_submodule_hooks]] says to do, since lefthook
exits 127 without it. So the two rules collide: initializing the submodule to
make commits work is what later blocks teardown.

Worse, the failed `--force` attempt **partially deletes** the worktree and
deregisters it, leaving a directory git no longer tracks. `cd` into it then
fails with `fatal: not a git repository: (null)`, so `git -C <path> submodule
deinit` cannot be used to recover — the deinit window has already closed.

**Why:** the leftover `target/` (~240M) also resists `rm -rf` with `Bad file
descriptor` on `incremental/**/*.o` — the container's filesystem mount holds
descriptors open from the build. Not corruption; the files unlink once the
descriptors are released.

**How to apply:** run `git submodule deinit -f containers` **inside** the
worktree BEFORE `worktree-rm.sh`, while it is still a valid git repo. If
teardown already failed, verify the merged commit is on `origin/main` first
(`git log origin/main --oneline`), then clean up by hand: `rm -rf` the tree,
`rm -rf .git/worktrees/<name>`, `git worktree prune`, and `git branch -D` the
branch (`-d` refuses after a squash merge — the commits are not ancestors of
main, so `-D` is correct once the content is confirmed on origin). A surviving
`target/` remnant is safe to leave for a later sweep.
