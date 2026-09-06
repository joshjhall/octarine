---
name: project_devcontainer_clang_disk
description: Two recurring local-only build blockers in this devcontainer — missing clang linker and a 40G+ target/ dir; neither is a repo bug
metadata:
  node_type: memory
  type: project
  originSessionId: 42763651-c837-4231-b783-b4e9deeefb38
  modified: 2026-09-05T23:09:41.205Z
---

`just clippy`/`just test` can fail locally for two environment reasons that
look like repo breakage but are not:

1. **`error: linker 'clang' not found`** — `.cargo/config.toml` sets
   `linker = "clang"` + `-fuse-ld=mold` for Linux targets. mold ships in the
   image but clang does not (the rust-dev feature ships only `libclang-dev`),
   so `.devcontainer/post-create.sh` installs it.
2. **`mold: failed to write to an output file. Disk full?`** or
   `LLVM error: section header table goes past the end of the file` — a
   truncated/corrupt object, usually from a bloated `target/` (seen at 40G).
   Fix: `cargo clean`. For a single corrupt artifact, deleting just that
   crate's files from `target/debug/deps/` is enough.

**Why:** For (1), **Zed does not run `postCreateCommand`** — it runs
`postStartCommand` but skips `postCreateCommand` entirely, so clang is never
installed. This is a *separate* gap from the ENTRYPOINT replacement that
`recover-entrypoint` handles ([[project_zed_entrypoint_recover]]);
`recover-entrypoint` does not run lifecycle hooks. Fixed 2026-09-04:
`post-start.sh` replays `post-create.sh` when `~/.post-create-complete` is
absent.

For (2), `df -h /` reports the container overlay (looked like 153G free)
while `target/` lives on the virtiofs `/workspace/octarine` mount — check
`df -h /workspace/octarine` for the number that actually matters.

**"Disk full?" is often a lie about MEMORY, not disk.** Seen 2026-09-05
(golem worktree, issue #467): `mold: failed to write to an output file.
Disk full?`, `clang: unable to execute command: Bus error`, and
`rustc ... (signal: 7, SIGBUS)` — with **152G free on every mount**. The
real limit was RAM: `free -h` showed ~300Mi free of 23Gi with swap pinned
at 3.9G/4G. mold mmaps its output, so memory exhaustion surfaces as a
write/disk error. Check `free -h` **and** `swapon --show` before reaching
for `cargo clean`.

Proof it is environmental, not a code defect: rebuild the single artifact
that failed, in isolation (`cargo build --example <name> --all-features
--jobs 1`). It links at exit 0 while the full `--all-features` build of the
same tree dies. `cargo check -p octarine-core --no-default-features` is a
cheap local signal that fits in memory when the full build does not.

Do not burn a session retrying the full build — a wide `--all-features`
build may be unrunnable on this box regardless of `--jobs`. **Push instead
and let CI arbitrate**; the lefthook pre-push hook (`cargo clippy
--all-targets --all-features` + `cargo test --workspace`, `lefthook.yml`)
and CI both have real memory. On #467 every local attempt failed while CI
passed 29/29 including a 14m46s full test suite.

**Also: `just preflight` can exit 0 while a sub-recipe FAILED.** Its
`test-nextest` step failed with `exited with code 101` and the wrapper
still reported success. Grep the log body for `^error` / `SIGBUS` rather
than trusting the exit status.

**How to apply:** Hit either error, fix the environment and re-run; don't
start debugging the dependency graph or the toolchain migration. When adding
one-time devcontainer setup, put it in `post-create.sh` and make it
idempotent — the Zed replay re-runs it. See [[feedback_just_recipes]].
