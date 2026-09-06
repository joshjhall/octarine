---
name: project-worktree-rm-hook-and-deinit
description: "Golem teardown gotchas — submodule deinit leaves an empty dir that still blocks worktree removal, and the pre-push hook runs the full suite on a branch DELETE"
metadata:
  node_type: memory
  type: project
  originSessionId: 68b9fac4-9d2a-45aa-b9c7-d8cee0601b33
  modified: 2026-09-06T15:20:04.993Z
---

Two teardown failures hit on the #486 golem run (2026-09-06), both after a
successful merge:

**1. `submodule deinit` is not enough.** Per [[project_worktree_rm_submodule_target]]
you must deinit `containers` inside the worktree before teardown — but deinit
clears the *contents* and leaves an **empty `containers/` directory**, which
still makes git refuse:

```text
fatal: working trees containing submodules cannot be moved or removed
then, with --force: error: failed to delete '...': Bad file descriptor
```

Fix: `rmdir <worktree>/containers` after the deinit, then re-run
`worktree-rm.sh N`. The "Bad file descriptor" is the FUSE/bindfs overlay, not
corruption.

**2. The pre-push hook runs clippy + tests on a branch DELETION.**
`git push origin --delete feature/issue-N` triggers lefthook's `cargo-clippy` +
`cargo-test` and then fails the push. There is nothing to verify when deleting a
ref, so use `--no-verify`:

```bash
git push origin --delete "feature/issue-N" --no-verify
```

**Expected residue:** `worktree-rm.sh` reports `N entries could not be removed`
and leaves `.worktrees/issue-N/` holding only a stale `.git` pointer file and an
empty `target/`. That is the overlay refusing to release build output — git's
worktree registry (`git worktree list`, `.git/worktrees/`) no longer lists it and
nothing tracked is at risk. Don't chase it.

Related: [[feedback_just_recipes]], [[project_devcontainer_clang_disk]]
