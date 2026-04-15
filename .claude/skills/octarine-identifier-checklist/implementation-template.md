# Octarine Identifier Implementation Templates

Companion to `SKILL.md`. Load when implementing a new type (Steps 1-11) or
creating a new domain.

## New Type in Existing Domain

For adding `{type}` to domain `{domain}` (e.g., adding `passport` to `government`):

### Step 1: Detection

File: `crates/octarine/src/primitives/identifiers/{domain}/detection/{type}.rs`

```rust
use crate::primitives::identifiers::common::{IdentifierMatch, IdentifierType};

/// Check if value is a {type}
pub fn is_{type}(value: &str) -> bool {
    // Pattern matching logic here
    false
}

/// Find all {type} matches in text
pub fn detect_{type}s_in_text(text: &str) -> Vec<IdentifierMatch> {
    // Text scanning logic here
    vec![]
}
```

Register in `detection/mod.rs`:
```rust
pub(crate) mod {type};
pub use {type}::*;
```

Add to domain's `detect_{domain}_identifier()`:
```rust
if is_{type}(value) {
    return Some(IdentifierType::{Type});
}
```

### Step 2: Patterns (if using regex)

File: `crates/octarine/src/primitives/identifiers/common/patterns/{domain}.rs`

```rust
use once_cell::sync::Lazy;
use regex::Regex;

pub static {TYPE}_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"...").expect("valid {type} regex")
});
```

### Step 3: Validation

File: `crates/octarine/src/primitives/identifiers/{domain}/validation/{type}.rs`

```rust
use crate::primitives::Problem;
use super::super::detection;

/// Validate that value is a valid {type}
pub fn validate_{type}(value: &str) -> Result<(), Problem> {
    if !detection::is_{type}(value) {  // MUST call detection first
        return Err(Problem::Validation("Invalid {type} format".into()));
    }
    // Additional validation rules...
    Ok(())
}
```

### Step 4: Sanitization

File: `crates/octarine/src/primitives/identifiers/{domain}/sanitization/{type}.rs`

```rust
use crate::primitives::Problem;

pub fn sanitize_{type}(value: &str) -> Result<String, Problem> {
    // Sanitization logic
    Ok(value.to_string())
}
```

### Step 5: Redaction

```rust
#[derive(Debug, Clone, Copy)]
pub enum {Type}RedactionStrategy {
    Complete,   // "[{TYPE}]"
    Partial,    // Show some characters
}

pub fn redact_{type}(value: &str, strategy: {Type}RedactionStrategy) -> String {
    match strategy {
        {Type}RedactionStrategy::Complete => "[{TYPE}]".to_string(),
        {Type}RedactionStrategy::Partial => {
            // Partial redaction logic
            format!("{}***", &value[..2])
        }
    }
}
```

### Steps 6-8: Primitives Builder Methods

In `primitives/identifiers/{domain}/builder/detection_methods.rs`:
```rust
impl {Domain}IdentifierBuilder {
    pub fn is_{type}(&self, value: &str) -> bool {
        detection::is_{type}(value)
    }
    pub fn detect_{type}s_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_{type}s_in_text(text)
    }
}
```

In `builder/validation_methods.rs`:
```rust
impl {Domain}IdentifierBuilder {
    pub fn validate_{type}(&self, value: &str) -> Result<(), Problem> {
        validation::validate_{type}(value)
    }
}
```

In `builder/sanitization_methods.rs`:
```rust
impl {Domain}IdentifierBuilder {
    pub fn redact_{type}(&self, value: &str, strategy: {Type}RedactionStrategy) -> String {
        sanitization::redact_{type}(value, strategy)
    }
}
```

### Step 9: Public Builder (Layer 3)

In `crates/octarine/src/identifiers/builder/{domain}.rs`, add methods:

```rust
impl {Domain}Builder {
    pub fn is_{type}(&self, value: &str) -> bool {
        self.inner.is_{type}(value)
    }

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

    pub fn validate_{type}(&self, value: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_{type}(value);
        if self.emit_events {
            record(metric_names::validate_ms(), start.elapsed().as_micros() as f64 / 1000.0);
        }
        result
    }

    pub fn redact_{type}(&self, value: &str) -> String {
        self.inner.redact_{type}(value, {Type}RedactionStrategy::Complete)
    }
}
```

### Step 10: Shortcuts

In `crates/octarine/src/identifiers/shortcuts.rs`:

```rust
pub fn is_{type}(value: &str) -> bool {
    {Domain}Builder::new().is_{type}(value)
}

pub fn validate_{type}(value: &str) -> Result<(), Problem> {
    {Domain}Builder::new().validate_{type}(value)
}

pub fn redact_{type}(value: &str) -> String {
    {Domain}Builder::new().redact_{type}(value)
}
```

### Step 11: PII Registration (if PII)

In `crates/octarine/src/identifiers/types/core.rs`, add variant:
```rust
pub enum IdentifierType {
    // ... existing variants
    {Type},
}
```

In PII scanner, add detection mapping.

### Step 12: Tests

Each layer gets its own test:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_{type}_valid() { assert!(is_{type}("valid_input")); }

    #[test]
    fn test_is_{type}_invalid() { assert!(!is_{type}("invalid")); }

    #[test]
    fn test_validate_{type}() { assert!(validate_{type}("valid").is_ok()); }
}
```

## New Identifier Domain

Directory structure to create:

```text
crates/octarine/src/primitives/identifiers/{domain}/
├── mod.rs                    # pub(crate) mod declarations + pub use re-exports
├── detection/
│   ├── mod.rs                # pub(crate) mod {type}; pub use {type}::*;
│   └── {type}.rs             # is_{type}(), detect_{type}s_in_text()
├── validation/
│   ├── mod.rs
│   └── {type}.rs             # validate_{type}()
├── sanitization/
│   ├── mod.rs
│   └── {type}.rs             # sanitize_{type}(), redact_{type}()
├── conversion.rs             # normalize_{type}() (if needed)
└── builder/
    ├── mod.rs                # pub(crate) struct {Domain}IdentifierBuilder
    ├── core.rs               # new(), common methods
    ├── detection_methods.rs  # is_*, detect_* delegation
    ├── validation_methods.rs # validate_* delegation
    └── sanitization_methods.rs # sanitize_*, redact_* delegation
```

Then wire up in parent `mod.rs` files:
- `primitives/identifiers/mod.rs`: add `pub(crate) mod {domain};`
- `identifiers/builder/mod.rs`: add `pub(crate) mod {domain};` + builder struct
- `identifiers/mod.rs`: add re-exports

## Verification Commands

After implementation, verify completeness:

```bash
# Check all detection functions have corresponding validation
grep -r "pub fn is_" crates/octarine/src/primitives/identifiers/{domain}/detection/
grep -r "pub fn validate_" crates/octarine/src/primitives/identifiers/{domain}/validation/

# Check primitives builder coverage
grep -r "pub fn is_\|pub fn validate_\|pub fn redact_" \
  crates/octarine/src/primitives/identifiers/{domain}/builder/

# Check public builder coverage
grep -r "pub fn is_\|pub fn validate_\|pub fn redact_" \
  crates/octarine/src/identifiers/builder/{domain}.rs

# Check shortcuts coverage
grep -r "pub fn is_\|pub fn validate_\|pub fn redact_" \
  crates/octarine/src/identifiers/shortcuts.rs | grep {type}

# Check for naming violations
grep -rn "pub fn \(has_\|contains_\|check_\|verify_\|ensure_\|remove_\)" \
  crates/octarine/src/

# Check for inheritance arrow violations (detection importing validation)
grep -r "use.*validation\|use.*sanitization" \
  crates/octarine/src/primitives/identifiers/*/detection/

# Run tests
just test-filter {type}
```
