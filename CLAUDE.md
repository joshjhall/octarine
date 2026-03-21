# Octarine Crate - Claude Code Context

This file provides crate-specific guidance for working with octarine.

## Overview

**Octarine** is the foundation library providing security primitives and observability tools for Rust applications. Named after the eighth color of the Discworld spectrum - the color of magic, visible only to wizards.

## Architecture (CRITICAL)

Three-layer architecture preventing circular dependencies:

```text
Layer 1: primitives/ (pub(crate))  - Pure functions, NO observe dependencies
         testing/ (feature-gated)  - Test infrastructure, can use all layers
            ↓
Layer 2: observe/ (pub)            - Observability, uses primitives only
            ↓
Layer 3: data/, runtime/ (pub)     - Uses primitives + observe
```

**Golden Rules:**

1. `primitives/` has NO internal dependencies (external crates + Problem type only)
1. `observe/` uses primitives ONLY
1. Layer 3 (`data/`, `runtime/`) uses primitives + observe
1. Production code NEVER imports `testing/`

See `docs/architecture/layer-architecture.md` for full details.

## Module Structure

```text
src/
├── primitives/     # Layer 1: Internal foundation (pub(crate))
│   ├── crypto/     # Cryptographic primitives
│   ├── data/       # FORMAT: Normalization, canonicalization
│   │   ├── paths/  # Path normalization
│   │   ├── network/# URL/hostname formatting
│   │   └── text/   # Text normalization, encoding
│   ├── security/   # THREATS: Danger detection
│   │   ├── paths/  # Traversal, injection detection
│   │   ├── network/# SSRF, encoding attacks
│   │   └── text/   # Log injection, control chars
│   ├── identifiers/# CLASSIFICATION: "What is it? Is it PII?"
│   │   ├── network/# IP, MAC, URL, UUID detection
│   │   ├── personal/# SSN, email, phone, names
│   │   ├── financial/# Credit cards, bank accounts
│   │   └── ...     # credentials, medical, government, etc.
│   ├── io/         # File operations
│   ├── runtime/    # Async utilities
│   └── types/      # Common types (Problem, Result)
├── observe/        # Layer 2: Observability (pub)
│   ├── event/      # Event generation
│   ├── context/    # Automatic context capture
│   ├── problem/    # Error handling with audit trails
│   ├── pii/        # PII detection and redaction
│   ├── metrics/    # Metrics collection
│   ├── writers/    # Output destinations
│   └── compliance/ # SOC2, HIPAA, GDPR, PCI-DSS
├── data/           # Layer 3: Data operations with observe (pub)
│   ├── paths/      # Path operations with observability
│   ├── network/    # Network operations with observability
│   ├── text/       # Text operations with observability
│   └── identifiers/# Identifier operations with observability
├── runtime/        # Layer 3: Runtime operations (pub)
├── crypto/         # Layer 3: Crypto operations (pub)
└── testing/        # Test infrastructure (feature-gated)
```

## Three Orthogonal Concerns (CRITICAL)

The primitives layer is organized around three orthogonal concerns that apply across domains:

| Concern | Purpose | Question | Example |
|---------|---------|----------|---------|
| `data/` | FORMAT | "How should this be structured?" | `normalize_url_path()` |
| `security/` | THREATS | "Is this dangerous?" | `is_ssrf_target()` |
| `identifiers/` | CLASSIFICATION | "What is it? Is it PII?" | `is_uuid()`, `is_email()` |

Each domain (paths, network, text) can have operations in all three areas:

```text
paths:       data/paths/     + security/paths/     + identifiers/location/
network:     data/network/   + security/network/   + identifiers/network/
text:        data/text/      + security/text/      + identifiers/personal/
```

This separation ensures:

- **Clear responsibility**: Each module answers ONE question
- **No confusion**: "is this an IP?" (identifiers) vs "is this IP dangerous?" (security)
- **Composability**: Use any combination based on your needs

## Security Model

### Three Security Layers

| Layer | Purpose | Returns | Modifies Input |
|-------|---------|---------|----------------|
| Detection | Find threats | `bool` | No |
| Validation | Enforce policy | `Result<()>` | No |
| Sanitization | Remove threats | `Result<String>` | Yes |

**Key principle:** Validators/sanitizers MUST call detection first (DRY).

### Detection vs Validation vs Sanitization

```rust
// DETECTION - Lenient (pattern matching, may have false positives)
detection::has_traversal(path)  // "file..txt" -> true (sensitive)

// VALIDATION - Strict (precise, no false positives)
validation::validate_no_traversal(path)?;  // Uses Path::components()

// SANITIZATION - Transform dangerous input
sanitization::sanitize_path(path)?;  // Removes threats
```

**When to use which:**

- **Detection**: Scanning, logging, analysis (false positives OK)
- **Validation**: Security gates, enforcement (no false positives)
- **Sanitization**: Cleaning user input, transforming to safe format

See `docs/security/patterns/detection-validation-sanitization.md` for full patterns.

### Zero-Trust Philosophy

- Validate ALL input regardless of source
- Validate ALL function parameters
- Never trust "safe-looking" patterns (`~/path` could be `~/$(whoami)`)
- Security checks BEFORE convenience shortcuts

**Validation order:** Command injection → Shell metacharacters → Path traversal → Null bytes → Control chars → Length

## Observe Module (Compliance-Grade Observability)

### Quick API

```rust
use octarine::observe::{info, warn, fail, fail_validation, Result};

// Logging (auto-captures WHO/WHAT/WHEN/WHERE)
info("operation", "message");
warn("operation", "message");

// Error handling (creates audit trail)
fn validate(input: &str) -> Result<()> {
    if input.is_empty() {
        return Err(fail_validation("input", "Cannot be empty"));
    }
    Ok(())
}
```

### Key Features

- **Automatic Context Capture**: WHO/WHAT/WHEN/WHERE in all events
- **PII Protection**: 30+ types detected and auto-redacted
- **Compliance Ready**: SOC2, HIPAA, GDPR, PCI-DSS control mapping
- **Multi-Tenant**: Thread-local tenant isolation
- **Multiple Writers**: Console, file (JSONL), SQLite, PostgreSQL

See `docs/observe/` for detailed guides.

## Code Standards

### File Organization

- `mod.rs` - Re-exports only, minimal logic
- `core.rs` or `types.rs` - Main implementation
- `builder.rs` - Builder patterns
- `functions.rs` or `shortcuts.rs` - Convenience functions

### Size Limits

- Preferred: \<300 LOC per file
- Warning: >500 LOC
- Split at: >800 LOC

### Naming Conventions (CRITICAL)

**Core Rule: Prefix indicates return type**

| Return Type | Prefix | Example |
|-------------|--------|---------|
| `bool` | `is_*` | `is_secure()`, `is_threat_present()` |
| `Result<T, E>` | `validate_*` | `validate_secure()`, `validate_no_traversal()` |
| `Vec<T>` | `detect_*` | `detect_threats()`, `detect_pii()` |
| `Option<T>` | `find_*` | `find_extension()`, `find_email()` |
| `&str` (accessor) | no prefix | `stem()`, `filename()`, `extension()` |
| `String` (convert) | `to_*` | `to_unix()`, `to_safe_filename()` |
| `String` (clean) | `sanitize_*` | `sanitize()`, `sanitize_strict()` |
| `String` (hide) | `redact_*` | `redact_email()`, `redact_ssn()` |
| `String` (remove) | `strip_*` | `strip_null_bytes()`, `strip_traversal()` |
| `String` (standardize) | `normalize_*` | `normalize_separators()` |

**Prohibited prefixes:** `has_*`, `contains_*`, `check_*`, `verify_*`, `ensure_*`, `remove_*`

See `docs/api/naming-conventions.md` for full details.

## Testing

### Feature Flag

```toml
[dev-dependencies]
octarine = { path = "../octarine", features = ["testing"] }
```

### Test Infrastructure

The `testing/` module provides:

- `fixtures/` - Filesystem, temp directories
- `generators/` - Attack patterns (proptest strategies)
- `cli/` - CLI testing utilities
- `assertions/` - Security predicates

### Running Tests

```bash
cargo test -p octarine                    # All tests
cargo test -p octarine --features testing # With test utilities
cargo test -p octarine -- --nocapture     # See output
```

### Performance Tests

Performance tests (`test_perf_*`) are **ignored by default** due to flaky timing
assertions under CI coverage. Run them manually before releases:

```bash
cargo test -p octarine test_perf_ -- --ignored
```

See `docs/architecture/testing-patterns.md` for thresholds and details.

## Common Patterns

### Adding a New Security Check

1. Determine which concern applies:
   - FORMAT (normalization) → `primitives/data/{domain}/`
   - THREATS (danger detection) → `primitives/security/{domain}/`
   - CLASSIFICATION (what is it?) → `primitives/identifiers/{domain}/`
1. Add detection function in `primitives/{concern}/{domain}/detection.rs`
1. Add validation function in `primitives/{concern}/{domain}/validation.rs` (calls detection)
1. Add sanitization if needed in `primitives/{concern}/{domain}/sanitization.rs`
1. Wrap in Layer 3 (`data/`) with observe instrumentation
1. Add to builder API
1. Add shortcut function

### Layer 3 Wrapping Pattern

```rust
// In data/paths/validation.rs
use crate::primitives::paths::validation as prim;
use crate::observe::{event, Problem};

pub fn validate_path(path: &str) -> Result<(), Problem> {
    let result = prim::validate_no_traversal(path);

    if result.is_err() {
        event::security("path_validation_failed", path);
    }

    result
}
```

## References

- `docs/api/naming-conventions.md` - **API naming standards (CRITICAL)**
- `docs/architecture/layer-architecture.md` - Full layer specification
- `docs/security/patterns/` - Security patterns
- `docs/observe/` - Observability guides
- `docs/patterns/` - Code patterns
