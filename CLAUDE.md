# Octarine - Claude Code Context

This file provides guidance for working with the octarine project.

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
Layer 3: data/, security/, identifiers/, runtime/, crypto/, io/, auth/, http/ (pub)
                                   - Uses primitives + observe
```

**Golden Rules:**

1. `primitives/` has NO internal dependencies (external crates + Problem type only)
1. `observe/` uses primitives ONLY
1. Layer 3 (`data/`, `security/`, `identifiers/`, `runtime/`, `crypto/`, `io/`, `auth/`, `http/`) uses primitives + observe
1. Production code NEVER imports `testing/`

See `docs/architecture/layer-architecture.md` for full details.

## Development Skills (CRITICAL)

When adding or modifying features, you MUST load the relevant project skills
from `.claude/skills/` to prevent the most common implementation errors:

- **`octarine-architecture`** — BEFORE adding modules, imports, builders,
  shortcuts, or re-exports. Enforces layer boundaries, visibility chain,
  and builder hierarchy. Load its `decision-trees.md` companion when deciding
  module placement or diagnosing visibility issues.
- **`octarine-identifier-checklist`** — BEFORE adding identifier types,
  detection functions, or PII categories. Provides the 12-step checklist
  ensuring complete implementations from detection through shortcuts.
  Load its `implementation-template.md` companion for function signatures.
- **`octarine-pii-bridge`** — WHEN adding identifier types that affect PII
  detection. Ensures `IdentifierType`, `PiiType`, and scanner domains stay
  in sync across the three parallel registries.
- **`octarine-observe-integration`** — WHEN adding or modifying Layer 3
  builders. Enforces metrics, events, silent mode, and the `define_metrics!`
  macro pattern. Load its `patterns.md` companion for the metric registry.
- **`octarine-test-resilience`** — WHEN writing tests involving timing,
  async, sleep, or performance benchmarks. Prevents flaky CI failures from
  hard timing assertions and fixed sleeps.
- **`octarine-platform-compat`** — WHEN writing `cfg()` attributes,
  platform-specific code, file permissions, signal handling, or path
  operations targeting Windows, macOS, Linux, or ARM64.

Seven project-specific audit agents are available in `.claude/agents/` for
codebase audits: `audit-octarine-layers`, `audit-octarine-visibility`,
`audit-octarine-identifiers`, `audit-octarine-pii-sync`,
`audit-octarine-observe`, `audit-octarine-tests`,
`audit-octarine-platforms`.

## Module Structure

```text
crates/octarine/src/
├── primitives/     # Layer 1: Internal foundation (pub(crate))
│   ├── crypto/     # Cryptographic primitives
│   ├── data/       # FORMAT: Normalization, canonicalization
│   │   ├── crypto/ # Cryptographic format primitives
│   │   ├── formats/# Data format primitives
│   │   ├── network/# URL/hostname formatting
│   │   ├── paths/  # Path normalization
│   │   ├── text/   # Text normalization, encoding
│   │   └── tokens/ # Token primitives
│   ├── security/   # THREATS: Danger detection
│   │   ├── commands/# Command injection detection
│   │   ├── crypto/ # Cryptographic threat detection
│   │   ├── formats/# Format-based attacks
│   │   ├── network/# SSRF, encoding attacks
│   │   ├── paths/  # Traversal, injection detection
│   │   └── queries/# Query injection detection
│   ├── identifiers/# CLASSIFICATION: "What is it? Is it PII?"
│   │   ├── network/# IP, MAC, URL, UUID detection
│   │   ├── personal/# SSN, email, phone, names
│   │   ├── financial/# Credit cards, bank accounts
│   │   └── ...     # credentials, medical, government, etc.
│   ├── io/         # File operations
│   ├── runtime/    # Async utilities
│   ├── types/      # Common types (Problem, Result)
│   ├── auth/       # Auth primitives (csrf, lockout, mfa, password, remember, reset, session)
│   └── collections/# Collection primitives (buffer, cache)
├── observe/        # Layer 2: Observability (pub)
│   ├── audit/      # Audit trail generation
│   ├── builder/    # Observe builder patterns
│   ├── compliance/ # SOC2, HIPAA, GDPR, PCI-DSS
│   ├── context/    # Automatic context capture
│   ├── event/      # Event generation
│   ├── metrics/    # Metrics collection
│   ├── pii/        # PII detection and redaction
│   ├── problem/    # Error handling with audit trails
│   ├── tracing/    # Distributed tracing
│   └── writers/    # Output destinations
├── data/           # Layer 3: Data operations with observe (pub)
│   ├── paths/      # Path operations with observability
│   ├── network/    # Network operations with observability
│   ├── text/       # Text operations with observability
│   └── formats/    # Data format operations
├── security/       # Layer 3: Security operations with observe (pub)
├── identifiers/    # Layer 3: Identifier operations with observe (pub)
├── runtime/        # Layer 3: Runtime operations (pub)
├── crypto/         # Layer 3: Crypto operations (pub)
├── io/             # Layer 3: I/O operations (pub)
├── auth/           # Layer 3: Auth operations (pub)
├── http/           # Layer 3: HTTP operations (pub)
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
detection::is_traversal_present(path)  // "file..txt" -> true (sensitive)

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

Layer 3 submodules follow one of three archetypes — see
[Layer 3 Module Archetypes](docs/architecture/layer-architecture.md#layer-3-module-archetypes)
for when to use the pure-function triple (`builder + types + shortcuts`),
the stateful-service pattern (`manager + store + pool`), or a flat utility
layout.

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

### Clippy Lints (CRITICAL)

The project enforces strict clippy lints via `Cargo.toml [lints.clippy]`. Key denied lints:

| Lint | Level | Rule |
|------|-------|------|
| `unwrap_used` | **deny** | Use `?`, `.ok()`, `.unwrap_or()`, or `.expect()` with justification |
| `indexing_slicing` | **deny** | Use `.get()`, `.first()`, `.last()`, or iterators instead of `[i]` |
| `arithmetic_side_effects` | **deny** | Use `.saturating_*()`, `.checked_*()`, or `.wrapping_*()` for arithmetic |
| `expect_used` | warn | Allowed in tests (`#[allow(clippy::expect_used)]`); avoid in production |
| `panic` | **deny** | Never panic in production code |
| `dbg_macro` | **deny** | No debug macros in committed code |
| `print_stdout` / `print_stderr` | **deny** | Use `observe` module for all output |

**In test modules**, add `#![allow(clippy::panic, clippy::expect_used)]` at the module level. Do NOT allow `indexing_slicing` — use `.first()`, `.get()`, etc. even in tests.

**For static regexes**, use `#![allow(clippy::expect_used)]` at the file level with a comment explaining the patterns are compile-time-known-valid.

## Testing

### Feature Flag

```toml
[dev-dependencies]
octarine = { path = "../octarine", features = ["testing"] }
```

### Test Infrastructure

The `testing/` module provides:

- `api/` - API testing utilities
- `assertions/` - Security predicates
- `cli/` - CLI testing utilities
- `fixtures/` - Filesystem, temp directories
- `generators/` - Attack patterns (proptest strategies)

### Running Tests

**CRITICAL: Always use `just` recipes** — never invoke `cargo test`, `cargo clippy`,
`cargo fmt`, or `bash scripts/` directly. `just` recipes ensure consistent flags
(`--all-features`, `-j4`, etc.) across agents, CI, and human developers. Raw
commands can miss feature-gated code or use wrong flags.

```bash
just test                                 # All workspace tests
just test-octarine                        # Octarine crate only
just test-mod "module::path"              # Unit tests by module path (e.g., "correlation::proximity")
just test-filter PATTERN                  # Filter by test name across workspace
just test-verbose                         # All tests with output visible
just test-with-fixtures                   # With testing feature enabled
```

### Linting & Architecture

```bash
just clippy                               # Clippy with all targets + all features
just fmt-check                            # Check formatting (no changes)
just fmt                                  # Apply formatting
just arch-check                           # Architecture enforcement (layer boundaries, naming, lint rules)
just preflight                            # Full pre-push: fmt + clippy + arch-check + test
```

### Performance Tests

Performance tests (`test_perf_*`) are **ignored by default** due to flaky timing
assertions under CI coverage. Run them manually before releases:

```bash
just test-perf
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
// In security/paths/builder.rs
use crate::primitives::security::paths::SecurityBuilder as PrimitiveSecurityBuilder;
use crate::observe::{warn, Problem};

pub fn validate_path(&self, path: &str) -> Result<(), Problem> {
    let prim = PrimitiveSecurityBuilder::new();
    let result = prim.validate_path(path);

    if result.is_err() {
        warn("path_validation", format!("Path validation failed: {}", path));
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
