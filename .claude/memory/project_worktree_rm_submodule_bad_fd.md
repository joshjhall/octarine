---
name: project_worktree_rm_submodule_bad_fd
description: "worktree-rm can leave an undeletable target/ remnant when submodule deinit races the mount; deregister is what matters, the .o files are inert"
metadata:
  node_type: memory
  type: project
  originSessionId: 342ee2b9-ddb2-45f7-a72c-39c97a089806
  modified: 2026-09-06T21:05:04.227Z
---

`worktree-rm.sh N` can fail even on a verified-clean tree, in two stacked steps:

1. `fatal: working trees containing submodules cannot be moved or removed` —
   deinit `containers` INSIDE the worktree first (see
   [[project_worktree_rm_submodule_target]] and
   [[project_worktree_rm_hook_and_deinit]]). Deinit + `rmdir containers`
   clears the *directory* but git still refuses until the retry.
1. The script's own `--force` retry then dies with
   `error: failed to delete '<path>': Bad file descriptor`.

**The second failure is cosmetic — check before chasing it.** The `--force`
attempt DOES deregister the worktree: `git worktree list` no longer shows it and
`git worktree prune` finds nothing. What survives is an orphaned directory
holding a couple of `target/debug/incremental/**/*.o` files that `rm -rf`
cannot unlink (`Bad file descriptor`), the same devcontainer mount flakiness
behind [[project_devcontainer_clang_disk]]. `du -sh` reports 0.

**How to finish:** confirm `git worktree list` is clean, `git branch -D
feature/issue-N` by hand (the script never got there), and leave the remnant —
the wedged handles clear on container restart. Do not retry `rm -rf` more than
once, and do not treat the remnant as a failed teardown.

**To free the `issue-N` path itself** (when a later run wants the name back, or
the directory's presence is confusing): `rm -rf` the contents first — that
reclaims the real disk (19G → 0 in #735) even though it leaves empty husks —
then `mv .worktrees/issue-N .worktrees/.trash-issue-N`. A rename only touches
the *parent's* directory entry, so it succeeds where unlink fails. The husk is
0 bytes and inert; it disappears on container restart.

**Registry-gone is NOT directory-gone.** `git worktree list` omitting the tree
proves only that the admin entry was removed — the directory can still be
sitting there at 19G. After any `worktree-rm` error, check the filesystem
(`ls -d`, `du -sh`) before reporting the teardown complete; do not infer removal
from the registry, and never override the script's explicit failure message with
a weaker signal.

**Why:** the teardown looks like it failed loudly while having actually
succeeded at everything load-bearing, so the reflex is to keep fighting the
mount instead of just deleting the branch.

**How to apply:** after a `worktree-rm` error, verify deregistration first
(`git worktree list`), then delete the branch manually, then stop.
