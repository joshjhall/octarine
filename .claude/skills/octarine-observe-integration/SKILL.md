---
description: Observe integration patterns for octarine Layer 3 builders — metrics, events, silent mode, and instrumentation. Use when adding define_metrics, modifying Layer 3 builders, wrapping primitives with observe, or running observe compliance audits.
---

# Octarine Observe Integration

Every Layer 3 builder wrapping primitives MUST include observe instrumentation.

**Detailed reference**: See `patterns.md` in this skill directory for the
`define_metrics!` macro usage, metric naming registry, and module structure
templates. Load it when adding a new module or metrics.

## Builder Instrumentation Checklist

Every Layer 3 builder must have:

1. **Metric names module** — pre-validated `MetricName` constants
2. **Timing metrics** — `record()` for operation duration (`*_ms`)
3. **Count metrics** — `increment_by()` for occurrences
4. **Event emission** — `observe::warn/debug/info` for significant events
5. **Silent mode** — `emit_events: bool` flag with `.silent()` constructor

## Metric Name Module Pattern

Use the `define_metrics!` macro (preferred):

```rust
crate::define_metrics! {
    detect_ms => "security.formats.detect_ms",
    validate_ms => "security.formats.validate_ms",
    threats_detected => "security.formats.threats_detected",
}
```

Manual `MetricName::new()` is acceptable when the macro isn't suitable.

## Metric Naming Convention

Pattern: `{layer}.{module}.{operation}_{unit}`

| Component | Convention | Examples |
|-----------|-----------|----------|
| Layer | `data`, `security`, `crypto`, `http` | — |
| Module | Singular domain name | `paths`, `network`, `commands` |
| Operation | Verb describing what's measured | `detect`, `validate`, `sanitize` |
| Unit suffix | `_ms` for timing, `_count` for quantity | `detect_ms`, `threats_detected` |

Examples: `data.paths.validate_ms`, `security.commands.threats_detected`

## Method Instrumentation Pattern

```rust
pub fn validate(&self, input: &str) -> Result<(), Problem> {
    let start = Instant::now();
    let result = self.inner.validate(input);

    if self.emit_events {
        // as_micros / 1000 preserves sub-ms precision; as_millis() truncates to 0 for fast ops
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
| Error creation | Error helpers | `observe::fail_validation("field", "reason")` |

**Never use** `event::warn()` in new Layer 3 builders — use `observe::warn()`
for consistent operation context capture in audit trails.

**Migration note**: Several existing builders still use `event::warn()`:
`crypto/validation/builder.rs`, `data/text/builder.rs`,
`identifiers/builder/{government,biometric}.rs`,
`security/{queries,network}/builder.rs`. When modifying one of these builders,
migrate existing `event::` calls to `observe::` at the same time.

## When to Use

- Creating a new Layer 3 module wrapping primitives
- Adding metrics to an existing builder
- Reviewing a builder for missing instrumentation
- Adding observe event calls to any module
- Running observe compliance audits

## When NOT to Use

- Working in primitives layer — use `octarine-architecture` skill instead
- Working in observe layer itself — refer to `observe/` internal docs
- Writing tests — use `octarine-test-resilience` skill instead

## Verification

After instrumentation:

1. `just clippy` passes with no new warnings
2. `just test-mod "module::path"` shows no regressions
3. Grep confirms metric in both `define_metrics!` and `record()`/`increment_by()`
