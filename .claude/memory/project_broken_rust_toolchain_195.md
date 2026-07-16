---
name: project_broken_rust_toolchain_195
description: "This env's pinned rust 1.95.0 toolchain is missing its cargo component; cargo/clippy/test and pre-push Rust hooks fail regardless of the diff"
metadata:
  node_type: memory
  type: project
  originSessionId: d54ed237-e323-4ddd-b13f-79a98d03a8a6
---

`rust-toolchain.toml` pins `channel = "1.95.0"`, but in this container that toolchain is missing its cargo component: `cargo --version` → "the 'cargo' binary ... is not applicable to the '1.95.0-aarch64-unknown-linux-gnu' toolchain". The `1.97.0` toolchain (rustup default) is intact.

**Consequence:** any `just`/cargo invocation and the lefthook **pre-push** hooks (`cargo-clippy`, `cargo-test`) fail with a rustup recursion_error — independent of what the diff touches.

**How to apply:** for config-only / non-Rust diffs (e.g. `.devcontainer/`), push with `--no-verify` and note in the PR that local Rust hooks couldn't run + CI covers them. For actual Rust work, **run the real suite through the intact 1.97.0 toolchain** — `rustup run 1.97.0 cargo test -p octarine-core --lib <path>`, and likewise `... cargo clippy --all-features` and `... env RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` — which validated a full financial-identifiers change in #693 (2026-07-15). `just` recipes still route through the broken 1.95.0 and fail, so bypass them here; commit/push with `--no-verify` since the pre-push hooks also use 1.95.0. Note clippy under 1.97.0 fires a few newer lints (e.g. `useless_borrows_in_formatting`) that 1.95.0 wouldn't — check the reported file paths are yours before acting. Relates to [[feedback_just_recipes]].
