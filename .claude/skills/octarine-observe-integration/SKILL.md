---
description: Observe integration patterns for octarine Layer 3 builders — metrics, events, and instrumentation. Use when adding or modifying Layer 3 builders, adding metrics to modules, or wrapping primitives with observe.
---

# Octarine Observe Integration

Every Layer 3 builder wrapping primitives MUST include observe instrumentation.
This skill covers metrics, event emission, and the two-layer/three-layer API
pattern for consistent module structure.

**Detailed reference**: See `patterns.md` in this skill directory for the
`define_metrics!` macro usage, metric naming registry, and complete module
structure template. Load it when adding a new module or metrics.

## Builder Instrumentation Checklist

Every Layer 3 builder must have:

1. **Metric names module** — pre-validated `MetricName` constants
2. **Timing metrics** — `record()` for operation duration (`*_ms`)
3. **Count metrics** — `increment_by()` for occurrences
4. **Event emission** — `observe::warn/debug/info` for significant events
5. **Silent mode** — `emit_events: bool` flag with `.silent()` constructor

## Metric Name Module Pattern

Use the `define_metrics!` macro (preferred) or manual `MetricName::new()`:

```rust
// Preferred: define_metrics! macro
crate::define_metrics! {
    detect_ms => "security.formats.detect_ms",
    validate_ms => "security.formats.validate_ms",
    threats_detected => "security.formats.threats_detected",
}

// Alternative: manual (when macro isn't suitable)
#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;
    pub fn detect_ms() -> MetricName {
        MetricName::new("module.submodule.detect_ms").expect("valid metric name")
    }
}
```

## Metric Naming Convention

Pattern: `{layer}.{module}.{operation}_{unit}`

| Component | Convention | Examples |
|-----------|-----------|----------|
| Layer | `data`, `security`, `crypto`, `http` | — |
| Module | Singular domain name | `paths`, `network`, `commands` |
| Operation | Verb describing what's measured | `detect`, `validate`, `sanitize` |
| Unit suffix | `_ms` for timing, `_count` for quantity | `detect_ms`, `threats_detected` |

Examples: `data.paths.validate_ms`, `security.commands.threats_detected`,
`crypto.validation.certificate_ms`, `data.identifiers.personal.detected`

## Method Instrumentation Pattern

```rust
pub fn validate(&self, input: &str) -> Result<(), Problem> {
    let start = Instant::now();
    let result = self.inner.validate(input);

    if self.emit_events {
        record(metric_names::validate_ms(),
            start.elapsed().as_micros() as f64 / 1000.0);
        if result.is_err() {
            observe::debug("module_name", "Validation failed");
        }
    }

    result
}
```

## Event API Selection

| Context | API | Example |
|---------|-----|---------|
| Layer 3 builders | Shortcuts API (2-arg) | `observe::warn("operation", "message")` |
| Security events | Shortcuts API | `observe::warn("path_validation", "Traversal detected")` |
| Error creation | Error helpers | `observe::fail_validation("field", "reason")` |
| Library internals | Event API (1-arg) | `event::debug("Starting retry")` |

**Never use** `event::warn()` in Layer 3 builders — use `observe::warn()` for
consistent operation context capture.

## Module Structure

See `octarine-architecture` skill's `decision-trees.md` for the full module
structure template. Key points: every public module needs `mod.rs` (re-exports),
`builder/` (struct + metrics + delegation), and shortcuts. Provide both lenient
(`fn x() -> String`) and strict (`fn x_strict() -> Result`) versions.

## When to Use

- Creating a new Layer 3 module wrapping primitives
- Adding metrics to an existing builder
- Reviewing a builder for missing instrumentation
- Adding observe event calls to any module

## When NOT to Use

- Working in primitives layer (NO observe allowed except Problem)
- Working in observe layer itself (internal infrastructure)
- Writing tests
