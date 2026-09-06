---
name: project_case_insensitive_mount_phantoms
description: "Capitalized \"duplicate\" src dirs (src/Data/, src/Security/…) are the SAME files via a case-insensitive mount — never delete them"
metadata:
  node_type: memory
  type: project
  originSessionId: f141c8c8-fed5-4fca-bbfe-91d036525d95
  modified: 2026-09-06T04:02:30.049Z
---

`git status` in this repo shows untracked capitalized directories that look
like stale duplicates of tracked lowercase modules:

```text
?? crates/octarine/src/Data/
?? crates/octarine/src/Identifiers/
?? crates/octarine/src/Security/
?? crates/octarine/src/observe/Problem/
```

**They are not duplicates. They are the same files.** `/workspace/octarine`
is a case-**insensitive** virtiofs bind mount (macOS host), while git is
case-**sensitive**. So `src/Data/mod.rs` and `src/data/mod.rs` resolve to one
inode, and git reports the capitalized spelling as an untracked path that
does not exist in the index.

**Deleting them deletes the real source tree.** `rm -rf crates/octarine/src/Data/`
removes `crates/octarine/src/data/` — 66 tracked files — and git cannot
recover what was never a separate object.

**Why the usual "stale artifact" tells all mislead here:** the files are not
referenced by `lib.rs` under the capitalized name, their mtimes are months
old, `git check-ignore` says they are not ignored, and diffing a capitalized
file against its lowercase twin reports no differences (of course — same
file). Every one of those reads as "dead copies". They are not.

**How to check, in one command** — compare inodes, don't diff contents:

```bash
stat -c '%i %n' crates/octarine/src/Data/mod.rs crates/octarine/src/data/mod.rs
# same inode => one file under two spellings => DO NOT DELETE
```

Confirm the mount itself with the repo's own detector, which exists precisely
for this: `containers/bin/detect-case-sensitivity.sh /workspace/octarine`
(exit 0 = case-sensitive, 1 = case-insensitive; it prints the remediation
list). A bare `touch lower.txt && ls LOWER.txt` in `/tmp` proves nothing —
`/tmp` is case-sensitive here while the workspace mount is not, so always
test the workspace path.

**How to apply:** treat these four paths as invisible. Do not delete them, do
not add them to `.gitignore` (a case-sensitive `.gitignore` entry cannot
express "the same file under another case"), and do not file them as tech
debt. If a task genuinely needs them gone, it is a host/mount change, not a
repo change. See [[project_devcontainer_clang_disk]] for the other
environment-not-repo trap on this box.
