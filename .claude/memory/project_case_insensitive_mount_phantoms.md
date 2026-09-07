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

**`mv` is as destructive as `rm` here — and it can wedge the path
permanently.** On 2026-09-06 a `git checkout -- observe/problem/` failed
because the index showed the 7 files as deleted, so the uppercase `Problem/`
twin was moved aside (`mv .../Problem /tmp/...`) to "let git recreate the
lowercase path". That left the mount with a **stale dentry**: the path is
listed by `ls` as `d?????????` but is simultaneously unusable in both
directions —

```text
mkdir problem  -> File exists
ls / stat / rm -> No such file or directory
git checkout   -> fatal: cannot create directory at '...': File exists
```

Nothing recreates it, and moving the twin back fails the same way. The crate
then will not compile (`error[E0583]: file not found for module 'problem'`),
which also fails every pre-push hook, so `git push --no-verify` is the only
way to land work until the volume is remounted (devcontainer restart), after
which `git checkout -- <path>` restores it.

So: when git reports these files as deleted, that is the *index* disagreeing
with the mount — **not** a signal to rearrange the filesystem. Verify the
content is safe first (`git show HEAD:<path> | diff - <Uppercase path>`;
it will be IDENTICAL), then leave the paths alone and treat it as an
environment problem.

**How to apply:** treat these four paths as invisible. Do not delete them, do
not **move or rename** them, do not add them to `.gitignore` (a
case-sensitive `.gitignore` entry cannot express "the same file under another
case"), and do not file them as tech debt. If a task genuinely needs them
gone, it is a host/mount change, not a repo change. See [[project_devcontainer_clang_disk]] for the other
environment-not-repo trap on this box.
