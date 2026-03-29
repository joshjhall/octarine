---
name: Use just recipes, not raw commands
description: All verification, testing, and linting should reference just recipes — never raw cargo/bash commands in plans or docs
type: feedback
---

Always reference `just` recipes in plans, verification sections, and documentation — never raw `cargo test`, `cargo clippy`, or `bash scripts/` commands.

**Why:** `just` recipes are the single source of truth for how to run things. Agents, hooks, CI, and humans should all use the same recipes. Raw commands are implementation details that can drift.

**How to apply:** In plan verification sections, write `just test-octarine` not `cargo test -p octarine --lib`. Write `just arch-check` not `bash scripts/arch-check.sh`. Write `just clippy` not `cargo clippy --workspace -- -D warnings`.
