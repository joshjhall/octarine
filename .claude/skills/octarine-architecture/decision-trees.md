# Octarine Architecture — Decision Trees & Reference Tables

Companion to `SKILL.md`. Load when deciding module placement, diagnosing
visibility issues, reviewing naming conventions, or writing Layer 3 wrappers.

## Module Placement Decision Tree

```text
Where does this code go?
  |
  +-- Pure utility, no octarine internal deps?
  |     YES -> primitives/{concern}/{domain}/
  |             concern = data (FORMAT), security (THREATS), identifiers (CLASSIFICATION)
  |
  +-- Observability infrastructure (events, metrics, PII redaction)?
  |     YES -> observe/
  |
  +-- Wraps primitives with observe instrumentation?
  |     YES -> Layer 3 module (identifiers/, data/, security/, runtime/, crypto/)
  |
  +-- Test infrastructure for reuse across tests?
        YES -> testing/ (feature-gated)
```

## Visibility Modifier Lookup

| Context | Correct | Wrong | Why |
|---------|---------|-------|-----|
| Module decl in `primitives/mod.rs` | `pub(crate) mod x` | `pub mod x` | Prevents external bypass of observe layer |
| Module decl in `primitives/x/mod.rs` | `pub(crate) mod y` | `pub mod y` | Same — internal structure |
| Item (fn/struct) in primitives | `pub fn` / `pub struct` | `pub(crate) fn` | Items need `pub` for crate-internal re-export |
| Sub-level feature module | `pub(super) mod` | `pub mod` | Hides internal structure |
| Root-level feature module (e.g. `identifiers/mod.rs`) | `pub mod builder` | `pub(crate) mod` | Public API surface |
| Re-export at ANY level | `pub use x::Y` | `pub(super) use x::Y` | Must cascade up — `pub(super)` blocks siblings |
| Builder struct at ANY level | `pub struct` | `pub(crate) struct` | Needed for re-export cascade |
| Shortcut fn in `shortcuts.rs` | `pub fn` | `pub(crate) fn` | User-facing convenience API |

## Import Validation Matrix

| Source Layer | `primitives::*` | `observe::*` | L3 modules | `testing::*` |
|-------------|-----------------|--------------|------------|-------------|
| `primitives/` | SELF only | `Problem` ONLY | DENY | DENY |
| `observe/` | ALLOW | SELF only | DENY | DENY |
| L3 modules | ALLOW | ALLOW | ALLOW (same layer) | DENY |
| `testing/` | ALLOW | ALLOW | ALLOW | SELF |
| `#[cfg(test)]` blocks | ALLOW | ALLOW | ALLOW | ALLOW |

**Allowed `observe` import in primitives** (the ONLY exception):
```rust
use crate::observe::Problem;  // OK — error type only
```

## Layer 3 Wrapping Pattern

Template based on `crates/octarine/src/identifiers/builder/personal.rs`:

```rust
//! {Domain} builder with observability
use std::time::Instant;
use crate::observe;
use crate::observe::Problem;
use crate::observe::metrics::{MetricName, increment_by, record};
use crate::primitives::identifiers::{
    {DomainType}Builder as Primitive{Domain}Builder,
    // ... strategy/policy types
};
use super::super::types::{IdentifierMatch, IdentifierType};

#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;
    pub fn detect_ms() -> MetricName {
        MetricName::new("data.identifiers.{domain}.detect_ms").expect("valid metric name")
    }
    pub fn detected() -> MetricName {
        MetricName::new("data.identifiers.{domain}.detected").expect("valid metric name")
    }
    // validate_ms, redact_ms, pii_found as needed
}

#[derive(Debug, Clone, Copy, Default)]
pub struct {Domain}Builder {
    inner: Primitive{Domain}Builder,
    emit_events: bool,
}

impl {Domain}Builder {
    #[must_use]
    pub fn new() -> Self {
        Self { inner: Primitive{Domain}Builder::new(), emit_events: true }
    }
    #[must_use]
    pub fn silent() -> Self {
        Self { inner: Primitive{Domain}Builder::new(), emit_events: false }
    }
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // Detection method pattern:
    pub fn is_{type}(&self, value: &str) -> bool {
        self.inner.is_{type}(value)  // Delegate — no added observe for bool
    }

    // Find method pattern (with observe):
    pub fn find_{type}s_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.detect_{type}s_in_text(text);
        if self.emit_events {
            record(metric_names::detect_ms(), start.elapsed().as_micros() as f64 / 1000.0);
            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
            }
        }
        matches.into_iter().map(Into::into).collect()
    }

    // Validation method pattern:
    pub fn validate_{type}(&self, value: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_{type}(value);
        if self.emit_events {
            record(metric_names::validate_ms(), start.elapsed().as_micros() as f64 / 1000.0);
            if result.is_err() {
                observe::debug("identifiers", format!("{type} validation failed for input"));
            }
        }
        result
    }
}
```

## Naming Convention Quick Reference

| Return Type | Prefix | Example |
|-------------|--------|---------|
| `bool` | `is_*` | `is_email()`, `is_pii_present()` |
| `Result<T>` | `validate_*` | `validate_email()` |
| `Vec<T>` | `detect_*` | `detect_threats()` |
| `Option<T>` | `find_*` | `find_email()` |
| `String` (clean) | `sanitize_*` | `sanitize_path()` |
| `String` (hide) | `redact_*` | `redact_email()` |
| `String` (remove) | `strip_*` | `strip_null_bytes()` |
| `String` (standardize) | `normalize_*` | `normalize_url()` |
| `String` (convert) | `to_*` | `to_unix()` |

**Prohibited**: `has_*` (use `is_*_present`), `contains_*`, `check_*`,
`verify_*`, `ensure_*`, `remove_*` (use `strip_*`)

## Three Orthogonal Concerns

Each domain (paths, network, text) can have operations in all three areas:

| Concern | Module | Question |
|---------|--------|----------|
| FORMAT | `primitives/data/` | "How should this be structured?" |
| THREATS | `primitives/security/` | "Is this dangerous?" |
| CLASSIFICATION | `primitives/identifiers/` | "What is it? Is it PII?" |
