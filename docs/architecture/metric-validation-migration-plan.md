# Metric Validation Migration Plan

## Current State

- Metric validation currently in `observe/metrics/validation.rs`
- Should be in `security/data/validation/identifiers/metrics.rs`

## Migration Strategy

### Phase 1: Create Security Module Structure

```rust
// security/data/validation/identifiers/mod.rs
pub mod metrics;
pub mod variables;
pub mod database;

// Re-export common functions
pub use metrics::{validate_metric_name, sanitize_metric_name};
```

### Phase 2: Move Core Validation

```rust
// security/data/validation/identifiers/metrics.rs
use crate::security::SecurityError;

/// Validates metric names according to monitoring system standards
///
/// Security considerations:
/// - Prevents injection attacks via metric names
/// - Ensures compatibility with Prometheus/StatsD/OpenMetrics
/// - Prevents cardinality explosion attacks
pub fn validate_metric_name(name: &str) -> Result<(), SecurityError> {
    // Same validation logic, but returns SecurityError
    // Can be more strict than observe module needs
}

/// Validates metric labels for security
pub fn validate_metric_label(key: &str, value: &str) -> Result<(), SecurityError> {
    // Prevent injection via labels
    // Check for suspicious patterns
    // Enforce cardinality limits
}
```

### Phase 3: Observe Module Adapter

```rust
// observe/metrics/validation.rs
use crate::security::data::validation::identifiers::metrics as security_validation;

/// Wrapper that adapts security validation for metrics use
pub(crate) fn validate_metric_name(name: &str) -> bool {
    security_validation::validate_metric_name(name).is_ok()
}

/// Auto-sanitize if validation fails
pub(crate) fn ensure_valid_metric_name(name: &str) -> String {
    match security_validation::validate_metric_name(name) {
        Ok(_) => name.to_string(),
        Err(_) => security_validation::sanitize_metric_name(name),
    }
}
```

## Benefits of This Approach

1. **Separation of Concerns**:

   - Security module: Strict validation, security focus
   - Observe module: Usability, auto-correction

1. **Different Error Types**:

   - Security returns `SecurityError` with audit events
   - Observe can choose to auto-fix or warn

1. **Reusability**:

   - Other modules can use the same validation
   - Config keys, environment variables use similar rules

1. **Security First**:

   - Security module can be more paranoid
   - Can check for injection patterns specific to monitoring systems

## Example Implementation

```rust
// In security module (strict)
pub fn validate_metric_name(name: &str) -> Result<(), SecurityError> {
    // Check for injection attempts
    if name.contains("${") || name.contains("{{") {
        return Err(SecurityError::PotentialInjection {
            input_type: "metric_name",
            pattern: "template_injection",
        });
    }

    // Check length limits (security perspective)
    if name.len() > 200 {
        return Err(SecurityError::InputTooLong {
            max: 200,
            actual: name.len(),
        });
    }

    // Check character set
    for ch in name.chars() {
        if !is_safe_metric_char(ch) {
            return Err(SecurityError::InvalidCharacter {
                context: "metric_name",
                character: ch,
            });
        }
    }

    Ok(())
}

// In observe module (lenient)
pub(crate) fn get_metric_name(raw: &str) -> String {
    // Try strict validation first
    if security::validate_metric_name(raw).is_ok() {
        return raw.to_string();
    }

    // Auto-sanitize for usability
    // Log warning for observability
    warn!("Sanitizing invalid metric name: {}", raw);
    security::sanitize_metric_name(raw)
}
```

## Implementation Order

1. **Keep current implementation** in observe module for now
1. **Build security module** validation with more comprehensive rules
1. **Gradually migrate** observe to use security validation
1. **Add security-specific checks** (injection, cardinality attacks)

## Security Considerations

The security module should check for:

1. **Template Injection**: `${}`, `{{}}`, `$()`
1. **Path Traversal**: `../`, `..\\`
1. **SQL Injection**: `'; DROP TABLE`, `OR 1=1`
1. **Label Bombing**: Too many unique label combinations
1. **Reserved Names**: System metrics that shouldn't be overwritten
1. **Encoding Attacks**: Unicode homoglyphs, null bytes

## Conclusion

Moving validation to the security module is the right architectural decision. It should be done gradually, maintaining backward compatibility while adding security depth.
