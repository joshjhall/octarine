# API Naming Conventions

This document defines the naming conventions for all public API methods in octarine's `data/` modules. Consistent naming ensures predictability, discoverability, and makes the API easier for both humans and AI agents to use correctly.

## Core Rule: Prefix Indicates Return Type

| Return Type | Prefix | Semantic | Example |
|-------------|--------|----------|---------|
| `bool` | `is_*` | Yes/no question | `is_secure()`, `is_email()`, `is_threat_present()` |
| `Result<T, E>` | `validate_*` | Strict validation with error | `validate_email()`, `validate_secure()` |
| `Vec<T>` | `detect_*` | Find all matches/occurrences | `detect_threats()`, `detect_emails()` |
| `Option<T>` | `find_*` | Find single/first match | `find_extension()`, `find_email()` |
| `&str` (accessor) | no prefix | Simple property access | `stem()`, `filename()`, `extension()` |
| `String` (convert) | `to_*` | Lossless format conversion | `to_unix()`, `to_windows()`, `to_safe_filename()` |
| `String` (clean) | `sanitize_*` | Security cleaning/threat removal | `sanitize()`, `sanitize_strict()` |
| `String` (hide) | `redact_*` | Hide sensitive data for display | `redact_email()`, `redact_ssn()` |
| `String` (remove) | `strip_*` | Remove specific pattern | `strip_null_bytes()`, `strip_extension()` |
| `String` (standardize) | `normalize_*` | Standardize format (non-security) | `normalize_separators()`, `normalize_case()` |
| `String` (ensure) | `with_*` | Add if missing, return as-is if present | `with_trailing_separator()`, `with_extension()` |
| Numeric/derived | `calculate_*` | Compute/derive value from input | `calculate_age()`, `calculate_checksum()` |

## Rationale

1. **Predictability**: Knowing the return type from the method name helps developers guess correctly
1. **Discoverability**: Users can type `is_` and find all boolean checks, `validate_` for all strict validations, etc.
1. **Consistency**: Same patterns across paths, identifiers, and future modules
1. **AI-friendly**: Strict rules are easier for AI agents to learn and apply correctly

## Detailed Guidelines

### Boolean Checks: `is_*`

All methods returning `bool` must start with `is_`:

```rust
// ✅ CORRECT
fn is_secure(path: &str) -> bool;
fn is_email(text: &str) -> bool;
fn is_threat_present(path: &str) -> bool;
fn is_traversal_present(path: &str) -> bool;

// ❌ WRONG - these patterns are prohibited
fn has_threat(path: &str) -> bool;       // use is_threat_present
fn contains_pii(text: &str) -> bool;     // use is_pii_present
fn validate_secure(path: &str) -> bool;  // validate_* must return Result
```

For presence checks, use the pattern `is_*_present`:

```rust
fn is_null_bytes_present(path: &str) -> bool;
fn is_shell_metacharacters_present(path: &str) -> bool;
fn is_pii_present(text: &str) -> bool;
```

### Strict Validation: `validate_*`

All methods returning `Result<T, E>` for validation must start with `validate_`:

```rust
// ✅ CORRECT
fn validate_secure(path: &str) -> Result<(), Problem>;
fn validate_email(text: &str) -> Result<(), Problem>;
fn validate_no_traversal(path: &str) -> Result<(), Problem>;

// ❌ WRONG
fn check_secure(path: &str) -> Result<(), Problem>;  // use validate_*
fn ensure_safe(path: &str) -> Result<(), Problem>;   // use validate_*
fn verify_email(text: &str) -> Result<(), Problem>;  // use validate_*
```

### Detection (Find All): `detect_*`

Methods that find all occurrences and return a collection use `detect_*`:

```rust
// ✅ CORRECT
fn detect_threats(path: &str) -> Vec<Threat>;
fn detect_emails(text: &str) -> Vec<EmailMatch>;
fn detect_pii(text: &str) -> Vec<PiiMatch>;

// ❌ WRONG
fn find_all_threats(path: &str) -> Vec<Threat>;  // use detect_*
fn get_threats(path: &str) -> Vec<Threat>;       // use detect_*
```

### Find Single: `find_*`

Methods that find a single or first match and return `Option<T>` use `find_*`:

```rust
// ✅ CORRECT
fn find_extension(path: &str) -> Option<&str>;
fn find_first_threat(path: &str) -> Option<Threat>;

// ❌ WRONG
fn get_extension(path: &str) -> Option<&str>;  // use find_* — get_* is prohibited
fn detect_extension(path: &str) -> Option<&str>;  // detect_* returns Vec
```

### Accessors: No Prefix

Simple property access uses no prefix. The `get_*` prefix is prohibited — drop it and name the accessor after the property:

```rust
// ✅ CORRECT
fn stem(path: &str) -> &str;
fn filename(path: &str) -> &str;
fn extension(path: &str) -> &str;
fn parent(path: &str) -> Option<&str>;
```

### Conversion: `to_*`

Lossless format conversion uses `to_*`:

```rust
// ✅ CORRECT
fn to_unix(path: &str) -> String;
fn to_windows(path: &str) -> String;
fn to_safe_filename(name: &str) -> String;
fn to_lowercase(text: &str) -> String;
```

### Security Cleaning: `sanitize_*`

Security-focused cleaning that removes threats uses `sanitize_*`:

```rust
// ✅ CORRECT
fn sanitize(path: &str) -> Result<String, Problem>;
fn sanitize_strict(path: &str) -> Result<String, Problem>;
fn sanitize_filename(name: &str) -> Result<String, Problem>;
```

### Redaction: `redact_*`

Hiding sensitive data for display uses `redact_*`:

```rust
// ✅ CORRECT
fn redact_email(text: &str) -> String;     // "user@example.com" -> "u***@e***.com"
fn redact_ssn(text: &str) -> String;       // "123-45-6789" -> "***-**-6789"
fn redact_credit_card(text: &str) -> String;
```

### Pattern Removal: `strip_*`

Removing specific patterns (non-security) uses `strip_*`:

```rust
// ✅ CORRECT
fn strip_null_bytes(path: &str) -> String;
fn strip_control_characters(text: &str) -> String;
fn strip_whitespace(text: &str) -> String;

// ❌ WRONG - remove_* implies mutation
fn remove_null_bytes(path: &str) -> String;  // use strip_*
```

### Normalization: `normalize_*`

Standardizing format (non-security) uses `normalize_*`:

```rust
// ✅ CORRECT
fn normalize_separators(path: &str) -> String;
fn normalize_case(text: &str) -> String;
fn normalize_unicode(text: &str) -> String;
```

### Ensure Presence: `with_*`

Adding something if missing (idempotent transforms) uses `with_*`:

```rust
// ✅ CORRECT
fn with_trailing_separator(path: &str) -> String;  // adds `/` if missing
fn with_extension(path: &str, ext: &str) -> String;  // adds extension if missing

// ❌ WRONG
fn ensure_trailing_separator(path: &str) -> String;  // use with_*
fn add_extension_if_missing(path: &str) -> String;   // use with_*
```

Note: `with_*` is idempotent - calling it multiple times has the same effect as calling once.

### Computation: `calculate_*`

Deriving new values through computation uses `calculate_*`:

```rust
// ✅ CORRECT
fn calculate_age(birthdate: &str) -> Result<u32, Problem>;
fn calculate_checksum(data: &[u8]) -> u32;
fn calculate_time_ago(timestamp: DateTime) -> String;  // "3 days ago"
fn calculate_time_until(timestamp: DateTime) -> String;  // "next week"

// ❌ WRONG
fn get_age(birthdate: &str) -> Result<u32, Problem>;  // use calculate_*
fn compute_checksum(data: &[u8]) -> u32;              // use calculate_* for consistency
```

Use `calculate_*` for:

- Mathematical computations (checksums, hashes, distances)
- Date/time derivations (age from birthdate, relative time strings)
- Any function that derives a new typed value (not String format conversion)

## Negation Patterns

Use positive framing where possible:

```rust
// ✅ PREFERRED - positive framing
fn is_traversal_free(path: &str) -> bool;
fn is_null_bytes_absent(path: &str) -> bool;

// ⚠️ ACCEPTABLE - but positive is preferred
fn is_no_traversal(path: &str) -> bool;
fn has_no_null_bytes(path: &str) -> bool;

// For validation, negation in name is acceptable
fn validate_no_traversal(path: &str) -> Result<(), Problem>;
```

## Prohibited Patterns

These prefixes are **prohibited** to maintain consistency:

| Prohibited | Use Instead |
|------------|-------------|
| `get_*` | no prefix (accessors) or `find_*` / `calculate_*` (derived values) |
| `has_*` | `is_*_present` |
| `contains_*` | `is_*_present` or `is_*_contained` |
| `check_*` | `is_*` (bool) or `validate_*` (Result) |
| `verify_*` | `is_*` (bool) or `validate_*` (Result) |
| `ensure_*` | `with_*` (add if missing) or `validate_*` (must exist) |
| `remove_*` | `strip_*` |
| `mask_*` | `redact_*` with appropriate strategy |
| `format_*` | `to_*` (conversion) or `normalize_*` (standardization) |
| `compute_*` | `calculate_*` |

## Builder Method Names

Builder methods follow a slightly different pattern since they configure behavior:

```rust
impl PathBuilder {
    // Configuration methods - use descriptive names
    pub fn allow_traversal(self, allow: bool) -> Self;
    pub fn max_length(self, len: usize) -> Self;
    pub fn require_extension(self, ext: &str) -> Self;

    // Terminal methods - follow standard naming
    pub fn is_valid(&self) -> bool;
    pub fn validate(&self) -> Result<(), Problem>;
    pub fn sanitize(&self) -> Result<String, Problem>;
}
```

## Module-Specific Conventions

### paths/

```rust
// Detection
is_absolute(path) -> bool
is_relative(path) -> bool
is_threat_present(path) -> bool
is_traversal_present(path) -> bool

// Validation
validate_secure(path) -> Result<(), Problem>
validate_no_traversal(path) -> Result<(), Problem>

// Sanitization
sanitize(path) -> Result<String, Problem>
sanitize_strict(path) -> Result<String, Problem>

// Accessors
filename(path) -> &str
stem(path) -> &str
extension(path) -> Option<&str>
parent(path) -> Option<&str>

// Conversion
to_unix(path) -> String
to_windows(path) -> String
normalize_separators(path) -> String
```

### identifiers/

```rust
// Detection
is_email(text) -> bool
is_phone(text) -> bool
is_ssn(text) -> bool
is_pii_present(text) -> bool
detect_pii(text) -> Vec<PiiMatch>

// Validation
validate_email(text) -> Result<(), Problem>
validate_phone(text) -> Result<(), Problem>

// Redaction
redact_pii(text) -> String
redact_email(text) -> String
redact_ssn(text) -> String
```

## Edge Cases

If you encounter a case that doesn't fit these patterns:

1. **Do not** skip it or invent a new pattern
1. Document the edge case
1. Discuss with the team
1. Update this document with the decision

This ensures consistency even for unanticipated scenarios.

## Migration Notes

When renaming existing methods:

1. Add new method with correct name
1. Mark old method as `#[deprecated(since = "X.Y.Z", note = "Use new_name() instead")]`
1. Update internal usage to new names
1. Remove deprecated methods in next major version

## References

- Original discussion: rust-core#182
- Security patterns: `docs/security/patterns/detection-validation-sanitization.md`
- Layer architecture: `docs/architecture/layer-architecture.md`
