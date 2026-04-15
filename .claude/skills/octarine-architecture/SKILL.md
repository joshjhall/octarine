---
description: Octarine three-layer architecture, cascading visibility, and builder hierarchy rules. Use when adding modules, imports, dependencies, builders, shortcuts, re-exports, or modifying visibility modifiers in the octarine crate.
---

# Octarine Architecture

**Detailed reference**: See `decision-trees.md` in this skill directory for module
placement decisions, visibility lookup tables, import validation matrix, the
Layer 3 wrapping template, and naming conventions. Load it when deciding where
code goes, diagnosing a visibility issue, or reviewing naming.

## Three-Layer Architecture

| Layer | Path | Visibility | Can Import | CANNOT Import |
|-------|------|-----------|------------|---------------|
| **L1** | `primitives/` | `pub(crate)` | External crates, `Problem` type only | `observe::*`, any L3 module |
| **L1b** | `testing/` | `pub` + `#[cfg(feature)]` | Everything | — |
| **L2** | `observe/` | `pub` | `primitives/` | Any L3 module, `testing/` |
| **L3** | `identifiers/`, `data/`, `runtime/`, `crypto/`, `security/` | `pub` | `primitives/` + `observe/` | `testing/` (except `#[cfg(test)]`) |

Primitives must NEVER call `observe::info/warn/debug/fail`, `increment_by()`, or `record()`.

## Visibility Chain

The chain for any feature follows this exact progression:

```text
primitives/{domain}/detection.rs     pub(crate) fn is_*()     # Pure logic
        |
primitives/{domain}/builder/core.rs  pub(crate) struct XBuilder  # Orchestration
        |
{module}/builder/{domain}.rs         pub struct XBuilder { inner }  # Wraps + observe
        |
{module}/shortcuts.rs                pub fn is_*()  # Builder::new().method()
        |
{module}/mod.rs                      pub use shortcuts::*  # Re-export
```

**Critical rules**:
- Primitives modules: `pub(crate) mod` — never `pub mod`
- Sub-level feature modules: `pub(super) mod` or `pub(crate) mod` — never `pub mod`
- Re-exports at ALL levels: `pub use` — NEVER `pub(super) use`
- Structs at ALL levels: `pub struct` — needed for re-export cascade
- Module visibility and item visibility are INDEPENDENT

## Builder Hierarchy

| File | Role | Business Logic? |
|------|------|-----------------|
| `builder/mod.rs` | Facade struct, configuration methods | NO |
| `builder/{domain}.rs` | Extension methods delegating to implementation | NO — delegation only |
| `builder/{domain}_shortcuts.rs` | `pub fn x() { Builder::new().x() }` | NO |
| `{domain}/detection.rs` | Pattern matching, classification | YES — this is where logic lives |
| `{domain}/validation.rs` | Policy enforcement (calls detection) | YES |
| `{domain}/sanitization.rs` | Input transformation | YES |

## Doc Tests by Layer

| Layer | Doc tests? | Annotation | Why |
|-------|-----------|------------|-----|
| **L1** (primitives) | NEVER | `/// ``` ignore` or `/// ``` no_run` or omit | `pub(crate)` items can't appear in public rustdoc |
| **L2** (observe) | ALWAYS | `/// ``` ` (runnable) | Public API, must verify examples compile and run |
| **L3** (public API) | ALWAYS | `/// ``` ` (runnable) | Public API, must verify examples compile and run |

Primitives are `pub(crate)` so rustdoc cannot run their examples — use `ignore`/`no_run` or omit.

## Common Mistakes

```rust
// WRONG: pub(super) for re-exports — breaks sibling access
pub(super) use builder::MyBuilder;
// CORRECT:
pub use builder::MyBuilder;

// WRONG: pub mod on sub-level module — exposes internals
pub mod detection;
// CORRECT:
pub(crate) mod detection;  // in primitives
pub(super) mod detection;  // in feature modules

// WRONG: Business logic in builder extension file
impl PersonalBuilder {
    pub fn is_email(&self, value: &str) -> bool {
        EMAIL_REGEX.is_match(value)  // NO — this belongs in detection.rs
    }
}
// CORRECT: Builder delegates to implementation
impl PersonalBuilder {
    pub fn is_email(&self, value: &str) -> bool {
        self.inner.is_email(value)  // Delegates to primitives builder
    }
}

// WRONG: Shortcut bypasses builder
pub fn is_email(value: &str) -> bool {
    crate::primitives::identifiers::personal::detection::is_email(value)
}
// CORRECT: Shortcut uses public builder
pub fn is_email(value: &str) -> bool {
    PersonalBuilder::new().is_email(value)
}
```

## Verification
- `just arch-check` — verify layer boundary compliance
- `just clippy` — catch visibility modifier errors

## When to Use

- Adding modules, files, or `use crate::` imports to the octarine crate
- Creating or modifying builder structs, shortcuts, or re-exports
- Writing `pub`/`pub(crate)`/`pub(super)` visibility declarations

## When NOT to Use

- Working exclusively in the `testing/` module (it has its own visibility rules as L1b)
- Working on code outside `crates/octarine/src/`
- Pure documentation changes
