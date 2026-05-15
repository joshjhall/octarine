---
name: ci-macos-cache-poisoning
description: macOS CI uses cache-bin=false to prevent .cargo/bin poisoning and bumps shared-key when toolchain bins get corrupted
metadata:
  node_type: memory
  type: project
  originSessionId: bfac780c-0dc5-4dfa-8e30-660c0215a5ac
---

The `Check (macOS)` job in `.github/workflows/ci.yml` uses:

- explicit `echo "$CARGO_HOME/bin" >> $GITHUB_PATH` before
  `dtolnay/rust-toolchain` (handles dtolnay's short-circuit when the
  runner has system rustup at `/opt/homebrew/bin/rustup`)
- `cache-bin: false` on `Swatinem/rust-cache@v2` (prevents poisoning)
- a versioned `shared-key` (`macos-v2`) (lets us invalidate the cache
  when poisoning happens)

**Why:** A single runner-image flake stored a stub `rustup-init` as
`~/.cargo/bin/cargo`. `Swatinem/rust-cache@v2` caches `~/.cargo/bin`
by default, so every subsequent macOS run pulled the bad cache AFTER
the toolchain install, replacing the working shims and reproducing the
`error: unexpected argument 'check' found / Usage: rustup-init[EXE]`
error indefinitely. One broken run → permanent CI breakage until the
cache key changed.

**How to apply:**

- Do NOT remove `cache-bin: false` on the macOS job. We don't
  `cargo install` anything there, so caching `~/.cargo/bin` provides
  no benefit and creates this poisoning risk.
- If macOS Check breaks again with a similar rustup-init or "command
  not found" signature, bump `shared-key: macos-v2` → `macos-v3`. Don't
  spend time debugging; the cache is poisoned.
- The "Verify cargo resolves to toolchain" step is the canary. If it
  fails, the PATH-prepend is the issue. If it passes but `cargo check`
  fails, the cache is poisoned.
- Linux and Windows jobs do not need any of this — their runner images
  do not pre-install rustup the same way, and they have not exhibited
  the poisoning pattern.

History: original flake on #331's post-merge run; misdiagnosed as
rustup-init shim in #332 (rm -rf approach was wrong); finally fixed
in #333 by combining the PATH prepend with `cache-bin: false` + a
fresh `shared-key`.
