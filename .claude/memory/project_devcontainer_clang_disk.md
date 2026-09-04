---
name: project_devcontainer_clang_disk
description: Two recurring local-only build blockers in this devcontainer — missing clang linker and a 40G+ target/ dir; neither is a repo bug
metadata:
  node_type: memory
  type: project
  originSessionId: 42763651-c837-4231-b783-b4e9deeefb38
  modified: 2026-09-04T19:28:00.414Z
---

`just clippy`/`just test` can fail locally for two environment reasons that
look like repo breakage but are not:

1. **`error: linker 'clang' not found`** — `.cargo/config.toml` sets
   `linker = "clang"` + `-fuse-ld=mold` for Linux targets. mold ships in the
   image but clang sometimes does not. Fix: `sudo apt-get install -y clang`.
2. **`mold: failed to write to an output file. Disk full?`** or
   `LLVM error: section header table goes past the end of the file` — a
   truncated/corrupt object, usually from a bloated `target/` (seen at 40G).
   Fix: `cargo clean`. For a single corrupt artifact, deleting just that
   crate's files from `target/debug/deps/` is enough.

**Why:** `df -h /` reports the container overlay (looked like 153G free)
while `target/` lives on the virtiofs `/workspace/octarine` mount — check
`df -h /workspace/octarine` for the number that actually matters.

**How to apply:** Hit either error, fix the environment and re-run; don't
start debugging the dependency graph or the toolchain migration. See
[[feedback_just_recipes]].
