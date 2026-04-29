---
name: Use just recipes, not raw commands
description: All verification, testing, linting, AND ad-hoc dev commands must use just recipes — never raw cargo/bash commands, even for one-off iteration
type: feedback
originSessionId: 0641e80c-85a8-41f7-9026-371e1fa16da1
---
Always use `just` recipes — in plans, verification sections, documentation, AND for ad-hoc commands during development iteration. Never invoke `cargo test`, `cargo clippy`, `cargo build`, `cargo fmt`, or `bash scripts/*` directly, even when tempted to "just check this one thing quickly."

**Why:** `just` recipes are the single source of truth for how to run things. Agents, hooks, CI, and humans should all use the same recipes. Raw commands are implementation details that can drift, miss feature flags, or use wrong job counts. Reinforced 2026-04-29: agent reached for `cargo build` and `cargo test` mid-implementation when `just test-octarine` / `just test-mod` would have done the same job; user pushed back firmly.

**How to apply:** In plan verification sections AND during execution: write `just test-octarine` not `cargo test -p octarine --lib`. Write `just test-mod "data::paths::builder"` not `cargo test --lib data::paths::builder`. Write `just arch-check` not `bash scripts/arch-check.sh`. Write `just clippy` not `cargo clippy --workspace -- -D warnings`. If a recipe doesn't exist for the exact thing you want, prefer the closest existing recipe over a raw cargo invocation.
