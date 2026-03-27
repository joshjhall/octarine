# Octarine Observe Integration — Patterns & Registry

Companion to `SKILL.md`. Load when adding a new module, adding metrics,
or checking existing metric coverage.

## define_metrics! Macro

Defined in `crates/octarine/src/observe/metrics/mod.rs` (line 133).
Generates a `metric_names` module with pre-validated `MetricName` functions.

```rust
// Usage in builder mod.rs:
crate::define_metrics! {
    detect_ms => "data.paths.detect_ms",
    validate_ms => "data.paths.validate_ms",
    validated => "data.paths.validated",
}

// Expands to:
mod metric_names {
    use crate::observe::metrics::MetricName;
    pub fn detect_ms() -> MetricName {
        MetricName::new("data.paths.detect_ms").expect("valid metric name")
    }
    pub fn validate_ms() -> MetricName {
        MetricName::new("data.paths.validate_ms").expect("valid metric name")
    }
    pub fn validated() -> MetricName {
        MetricName::new("data.paths.validated").expect("valid metric name")
    }
}
```

## Existing Metric Registry

### data.paths.*
- `data.paths.context.sanitized` — context sanitization count
- `data.paths.filename.threats_detected` — filename threat count
- `data.paths.filename.sanitize_ms` — filename sanitization timing
- `data.paths.filename.validated` — filename validation count
- `data.paths.boundary.validate_ms` — boundary validation timing
- `data.paths.boundary.constrain_ms` — path constraint timing
- `data.paths.construction.paths_built` — path construction count
- `data.paths.characteristic.path_type_detected` — path type detection count
- `data.paths.characteristic.platform_detected` — platform detection count
- `data.paths.format.format_detected` — format detection count
- `data.paths.format.converted` — format conversion count

### data.network.*
- `data.network.normalize_ms` — URL normalization timing
- `data.network.normalize_count` — URL normalization count

### data.identifiers.{domain}.*
- `data.identifiers.personal.detect_ms` — personal detection timing
- `data.identifiers.personal.validate_ms` — personal validation timing
- `data.identifiers.personal.redact_ms` — personal redaction timing
- `data.identifiers.personal.detected` — personal detection count
- `data.identifiers.personal.pii_found` — personal PII found count
- (Similar pattern for financial, government, network, token, etc.)

### security.*
- `security.commands.threats_detected` — command injection threats
- `security.commands.validate_ms` — command validation timing
- `security.commands.escape_ms` — command escaping timing
- `security.paths.threats_detected` — path security threats
- `security.paths.validate_ms` — path security validation timing
- `security.paths.sanitize_ms` — path security sanitization timing

### crypto.*
- `crypto.validation.certificate_ms` — certificate validation timing
- `crypto.validation.ssh_key_ms` — SSH key validation timing
- `crypto.validation.audit_ms` — crypto audit timing
- `crypto.validation.validated` — crypto validation count
- `crypto.validation.threats_blocked` — crypto threats blocked
- `crypto.validation.warnings` — crypto warnings count

### secrets.*
- `secrets.storage.created` — encrypted storage created
- `secrets.insert_count` — secret insertions
- `secrets.access_count` — secret accesses
- `secrets.expired_count` — secret expirations

### http.*
- `http.request.latency_ms` — HTTP request latency

### Modules MISSING Metrics (need attention)
- `security/formats/builder.rs` — XXE, JSON depth, YAML bombs (logging only)
- `security/network/builder.rs` — SSRF, dangerous schemes (logging only)
- `security/queries/builder.rs` — SQL/NoSQL/LDAP injection (logging only)

## Complete Module Template

For a new Layer 3 module `{module}/{concern}/`:

```text
{module}/{concern}/
├── mod.rs              # Public API surface
├── builder/
│   ├── mod.rs          # Builder struct + metrics + new/silent
│   ├── detection.rs    # Detection delegation methods
│   ├── validation.rs   # Validation delegation methods
│   └── shortcuts.rs    # Convenience functions
└── types.rs            # Public types (optional)
```

### mod.rs template:

```rust
//! {Concern} operations with observability
//!
//! Wraps `primitives::{concern}` with observe instrumentation.

pub(crate) mod builder;

// Re-export builder and types
pub use builder::{Concern}Builder;
pub use builder::shortcuts::*;
```

### builder/mod.rs template:

```rust
use std::time::Instant;
use crate::observe;
use crate::observe::Problem;
use crate::observe::metrics::{increment_by, record};
use crate::primitives::{concern}::{
    {Concern}Builder as Primitive{Concern}Builder,
};

pub(crate) mod detection;
pub(crate) mod validation;
pub mod shortcuts;

crate::define_metrics! {
    detect_ms => "{module}.{concern}.detect_ms",
    validate_ms => "{module}.{concern}.validate_ms",
    threats_detected => "{module}.{concern}.threats_detected",
}

#[derive(Debug, Clone, Default)]
pub struct {Concern}Builder {
    inner: Primitive{Concern}Builder,
    emit_events: bool,
}

impl {Concern}Builder {
    #[must_use]
    pub fn new() -> Self {
        Self { inner: Primitive{Concern}Builder::new(), emit_events: true }
    }

    #[must_use]
    pub fn silent() -> Self {
        Self { inner: Primitive{Concern}Builder::new(), emit_events: false }
    }

    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }
}
```

### builder/shortcuts.rs template:

```rust
use super::{Concern}Builder;
use crate::observe::Problem;

/// Lenient: returns safe default on failure
#[must_use]
pub fn sanitize_{concern}(input: &str) -> String {
    sanitize_{concern}_strict(input)
        .unwrap_or_else(|_| String::new())
}

/// Strict: returns Result
pub fn sanitize_{concern}_strict(input: &str) -> Result<String, Problem> {
    {Concern}Builder::new().sanitize(input)
}
```

## Event Dispatch Policy

The `Problem` type has an intentional dispatch policy:

| Problem Kind | Auto-Logged? | Level | Rationale |
|-------------|-------------|-------|-----------|
| Validation failure | YES | WARNING | Security-relevant, must audit |
| Permission denied | YES | ERROR | Access control, must audit |
| Security threat | YES | CRITICAL | Active threat, must alert |
| Config error | NO | — | Logged at call site with context |
| Network error | NO | — | Logged at call site with context |
| Database error | NO | — | Logged at call site with context |

Use `observe::fail_validation()`, `observe::fail_security()`,
`observe::fail_permission()` for auto-logged errors. Use
`Problem::OperationFailed()` only when you'll log at the call site.
