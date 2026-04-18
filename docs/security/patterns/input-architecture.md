# Input Security Architecture

## Overview

The security input module provides a unified, secure API for all input handling in octarine. It implements defense-in-depth through multiple layers of validation, sanitization, and type safety.

## Core Principles

### 1. Defense in Depth

- Multiple layers: Validation → Sanitization → Conversion
- Each layer operates independently but cohesively
- Failures at any layer prevent unsafe input from proceeding

### 2. Context-Aware Processing

- Automatic detection of input types (paths, URLs, commands, etc.)
- Context-specific validation and sanitization
- Different behavior for different security contexts

### 3. Type Safety

- Type-safe wrappers enforce security by design
- Compile-time guarantees for validated input
- No way to bypass security checks

### 4. No Bypass Routes

- Internal modules use `pub(crate)` or `pub(super)`
- No wildcard exports to prevent accidental exposure
- Single entry point for all input processing

## Module Structure

```text
/src/security/data/
├── mod.rs                 # Public API surface
├── validation/            # Input validation (9 contexts)
│   ├── paths/            # File system paths
│   ├── network/          # URLs, IPs, ports
│   ├── authentication/   # Usernames, passwords, tokens
│   ├── formats/          # JSON, XML, dates
│   ├── text/             # Plain text, unicode
│   ├── commands/         # Shell commands
│   ├── queries/          # SQL, NoSQL, GraphQL
│   ├── crypto/           # Keys, certificates
│   └── identifiers/      # Email, phone, UUIDs
│
├── sanitization/         # Input sanitization
│   └── [same structure as validation]
│
└── conversion/           # Format conversion
    └── [same structure as validation]
```

## The Nine Security Contexts

Based on OWASP input categories, all input falls into one of nine contexts:

1. **paths** - File system paths, directories
1. **network** - URLs, IPs, ports, protocols
1. **authentication** - Usernames, passwords, tokens, API keys
1. **formats** - JSON, XML, CSV, dates, structured data
1. **text** - Plain text, unicode, encoding
1. **commands** - Shell commands, OS execution
1. **queries** - SQL, NoSQL, GraphQL, LDAP
1. **crypto** - Keys, certificates, algorithms
1. **identifiers** - Email, phone, UUIDs, PII data

## Usage Patterns

### Simple Functions (80% of cases)

```rust
use octarine::security::data::paths::sanitize_path;

// Quick sanitization with defaults
let safe_path = sanitize_path(user_input);
```

### Builder Pattern (Complex cases)

```rust
use octarine::security::data::paths::PathSanitizer;

let sanitizer = PathSanitizer::builder()
    .remove_traversal()
    .normalize()
    .strict_mode()
    .build();

let safe_path = sanitizer.sanitize(user_input)?;
```

### Dual Function Pattern

```rust
// Strict version - returns Result
let path = sanitize_path_strict(user_input)?;

// Lenient version - always succeeds with safe default
let path = sanitize_path(user_input);
```

## Security Boundaries

```text
Untrusted Input → [Security Module] → Validated Input → Application
                        ↑
                 Security Boundary
                 (All validation and
                  sanitization here)
```

### Trust Levels

- **Untrusted**: All external input
- **Validated**: Passed validation checks
- **Sanitized**: Safe for use in application
- **Trusted**: Internal application data

## Validation Layers

### Layer 1: Size and Complexity

- Check input size limits
- Verify complexity bounds
- Prevent resource exhaustion

### Layer 2: Format and Structure

- Verify expected format
- Check structural validity
- Ensure encoding correctness

### Layer 3: Content and Patterns

- Check for malicious patterns
- Verify business rules
- Detect injection attempts

### Layer 4: Context-Specific Rules

- Apply domain-specific rules
- Check against allowlists/denylists
- Verify semantic correctness

## Implementation Guidelines

### Fail-Safe Defaults

```rust
pub fn sanitize_path(input: &str) -> String {
    match sanitize_path_strict(input) {
        Ok(path) => path,
        Err(_) => String::from("/safe/default/path")
    }
}
```

### Event Generation

```rust
pub fn validate_strict(input: &str) -> Result<String, Problem> {
    if !is_valid(input) {
        // Automatically generates security event
        return Err(Problem::validation(
            "Invalid input format",
            ProblemSeverity::Warning
        ));
    }
    Ok(input.to_string())
}
```

### Performance Considerations

- Validation is performed in order of cost (cheap → expensive)
- Short-circuit on first critical failure
- Cache frequently validated inputs
- Use lazy evaluation where possible

## Testing Requirements

### Unit Tests

- Each validation function tested independently
- Each sanitization function tested independently
- Edge cases and boundary conditions

### Security Tests

- Known attack patterns (OWASP Top 10)
- Injection prevention verification
- Resource exhaustion prevention
- Bypass attempt detection

### Fuzzing

- Property-based testing with proptest
- AFL fuzzing for complex inputs
- Continuous fuzzing in CI/CD

## Compliance Alignment

The module meets requirements for:

- **OWASP** Input Validation Guidelines
- **NIST** SP 800-53 Input Controls
- **CWE-20** Improper Input Validation

## Related Documentation

- [Detection vs Validation vs Sanitization](./detection-validation-sanitization.md)
- [Security Guidelines](../security-guidelines.md)
- [Security Patterns Overview](./overview.md)
