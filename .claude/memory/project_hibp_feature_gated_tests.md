---
name: project_hibp_feature_gated_tests
description: "auth/password/hibp.rs is behind the auth-hibp feature; a bare `cargo test -- hibp` silently matches 0 tests"
metadata:
  node_type: memory
  type: project
  originSessionId: 26e2bbe8-8788-4a05-a1a0-c933b7b46e79
  modified: 2026-09-06T19:58:19.207Z
---

`crates/octarine/src/auth/password/mod.rs` gates `mod hibp;` behind
`#[cfg(feature = "auth-hibp")]`. A bare `cargo test -p octarine-core --lib
-- hibp` therefore compiles nothing and reports **`0 passed`** — which
looks like success, not like a skipped module.

**Why:** hit during #724, where hibp tests were edited and "verified" by a
run that never compiled them. The `0 passed` line is easy to read past.

**How to apply:** this is exactly what CLAUDE.md's "always use `just`
recipes" rule protects against — `just test` passes `--all-features`. When
a targeted `cargo test` is genuinely warranted, pass `--features auth-hibp`
and **check the test count is non-zero**, not just that the run exited 0.
The same trap applies to any other feature-gated module.

Related: [[feedback_just_recipes]].
