# Layer Architecture

This document defines the strict layer architecture that governs module dependencies in octarine. Understanding and following these rules is critical to prevent circular dependencies and maintain clean separation of concerns.

## Overview

octarine uses a **four-layer architecture** where each layer can only depend on layers below it:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                        DEPENDENCY DIRECTION: DOWN ONLY                      │
│                                                                             │
│  Higher layers can depend on lower layers, NEVER the reverse               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 3: Application Modules (pub)                                          │
│                                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │  data/   │ │security/ │ │identifi- │ │ runtime/ │ │ crypto/  │          │
│  │          │ │          │ │  ers/    │ │          │ │          │          │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                                   │
│  │   io/    │ │  auth/   │ │  http/   │  All: Public API with full         │
│  │          │ │          │ │          │  observability                      │
│  └──────────┘ └──────────┘ └──────────┘                                    │
│                                                                             │
│  Can use: primitives, observe                                               │
│  Cannot use: testing (except in #[cfg(test)] blocks)                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 2: Observability (pub)                                                │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────┐        │
│  │                         observe/                                 │        │
│  │                                                                  │        │
│  │  - event/      Event generation and types                       │        │
│  │  - context/    Automatic context capture                        │        │
│  │  - problem/    Error handling with automatic events             │        │
│  │  - pii/        PII detection and redaction                      │        │
│  │  - metrics/    Metrics collection                               │        │
│  │  - writers/    Output destinations (console, file, database)    │        │
│  └─────────────────────────────────────────────────────────────────┘        │
│                                                                             │
│  Can use: primitives only                                                   │
│  Cannot use: security, runtime, testing                                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Layer 1: Foundation (no internal dependencies)                              │
│                                                                             │
│  ┌────────────────────────────────┐  ┌────────────────────────────────┐    │
│  │       primitives/              │  │         testing/               │    │
│  │       (pub(crate))             │  │    (pub, feature-gated)        │    │
│  │                                │  │                                │    │
│  │  Three orthogonal concerns:    │  │  Shared test infrastructure:   │    │
│  │                                │  │  - fixtures/    FS, temp dirs  │    │
│  │  data/         FORMAT          │  │  - generators/  Attack patterns│    │
│  │    paths/      normalization   │  │  - cli/         CLI testing    │    │
│  │    network/    URL formatting  │  │  - api/         API/MCP tests  │    │
│  │    text/       encoding        │  │  - assertions/  Security preds │    │
│  │                                │  │                                │    │
│  │  security/     THREATS         │  │  Available to consumers via    │    │
│  │    paths/      traversal       │  │  feature = "testing"           │    │
│  │    network/    SSRF, attacks   │  │                                │    │
│  │    text/       injection       │  │                                │    │
│  │                                │  │                                │    │
│  │  identifiers/  CLASSIFICATION  │  │                                │    │
│  │    network/    IP, MAC, UUID   │  │                                │    │
│  │    personal/   SSN, email      │  │                                │    │
│  │    financial/  credit cards    │  │                                │    │
│  │                                │  │                                │    │
│  │  Also: crypto/, io/, runtime/  │  │                                │    │
│  └────────────────────────────────┘  └────────────────────────────────┘    │
│                                                                             │
│  primitives: Cannot use any internal modules                                │
│  testing: Can use ALL layers (it's a consumer, not a provider)              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## The Four Layers Explained

### Layer 1a: primitives/ (Internal Foundation)

**Visibility**: `pub(crate)` - Only accessible within octarine

**Purpose**: Pure utility functions with ZERO internal dependencies. These are the building blocks that observe and security modules use internally.

**Rules**:

- Can only depend on external crates (regex, chrono, etc.)
- Can use `crate::observe::Problem` error type (exception for error handling)
- MUST NOT import from observe, security, runtime, or testing
- MUST NOT generate events or log anything

**Why Internal Only**: Forces external consumers to use Layer 3 APIs which include proper observability. Prevents bypassing audit logging.

```rust
// primitives/paths/validation.rs
// ✅ ALLOWED
use regex::Regex;
use crate::observe::Problem;  // Error type only

// ❌ FORBIDDEN
use crate::observe::event;    // No event generation in primitives
use crate::security::*;       // No Layer 3 dependencies
use crate::testing::*;        // No testing dependency
```

### Layer 1b: testing/ (Shared Test Infrastructure)

**Visibility**: `pub` with `#[cfg(feature = "testing")]`

**Purpose**: Reusable test utilities, fixtures, and generators that can be shared across octarine and all consuming projects.

**Rules**:

- CAN depend on ALL other layers (primitives, observe, security, runtime)
- Is a **consumer** of the API, not a **provider** to it
- Only compiled when `testing` feature is enabled
- Only used in `[dev-dependencies]` by consumers

**Why Public**: Allows consistent testing patterns across all projects using octarine. Security test generators match the attack patterns that octarine defends against.

```rust
// testing/generators/attacks.rs
// ✅ ALLOWED - testing can use everything
use crate::primitives::data::paths;
use crate::observe::pii;
use crate::security::paths as security_paths;

pub fn arb_path_traversal() -> impl Strategy<Value = String> {
    // Generate attacks that security should catch
}
```

### Layer 2: observe/ (Observability)

**Visibility**: `pub` - Full public API

**Purpose**: Event generation, metrics, PII redaction, and audit logging. Provides the observability infrastructure used by Layer 3.

**Rules**:

- Can use primitives only
- MUST NOT use security, runtime, or testing
- This prevents circular dependencies (security uses observe, so observe cannot use security)

```rust
// observe/pii/scanner.rs
// ✅ ALLOWED
use crate::primitives::identifiers::detection;

// ❌ FORBIDDEN - would create circular dependency
use crate::security::*;
use crate::testing::*;
```

### Layer 3: security/, runtime/ (Application Modules)

**Visibility**: `pub` - Full public API

**Purpose**: High-level APIs that combine primitives with full observability. This is what external consumers use.

**Rules**:

- Can use primitives and observe
- MUST NOT use testing (except in `#[cfg(test)]` blocks)
- Should wrap primitive operations with event generation

```rust
// security/data/validation/paths.rs
// ✅ ALLOWED
use crate::primitives::paths::validation as prim;
use crate::observe::{event, Problem};

pub fn validate_path(path: &str) -> Result<(), Problem> {
    // Call primitive
    let result = prim::validate_no_traversal(path);

    // Add observability
    if result.is_err() {
        event::security("path_validation_failed", &path);
    }

    result
}

// ❌ FORBIDDEN in production code
use crate::testing::*;
```

## The Critical Rule: Testing is a Consumer

The `testing` module breaks the normal "down only" rule because it's a **consumer** of the public API, not a **provider** to it:

```text
Normal dependency flow:       Testing dependency flow:

    Layer 3                       Layer 3
       ↓                             ↑
    Layer 2                       Layer 2
       ↓                             ↑
    Layer 1                       testing (consumes all)
```

**Key Principle**: No production code may depend on testing.

| Module | Can Import `testing`? |
|--------|----------------------|
| primitives/ | ❌ Never |
| observe/ | ❌ Never |
| security/ | ❌ Never (except `#[cfg(test)]`) |
| runtime/ | ❌ Never (except `#[cfg(test)]`) |
| testing/ | N/A (is testing) |
| External crate (dev-deps) | ✅ Yes |

## Why This Architecture?

### Problem We Solved

Before this architecture, we had circular dependencies:

```rust
// OLD: observe used security for PII detection
observe::pii::redact()
    → security::contains_email()
        → observe::trace()  // CIRCULAR!
            → security::...
```

### Solution

1. **Extract pure functions to primitives**: PII detection patterns moved to `primitives/identifiers`
1. **Observe uses primitives only**: No circular dependency possible
1. **Security wraps primitives with observe**: Clean layering

### Benefits

1. **Compiler-enforced safety**: `pub(crate)` prevents external bypass of observability
1. **No circular dependencies**: One-way dependency flow
1. **Testable layers**: Each layer can be tested in isolation
1. **Shared test infrastructure**: `testing` module provides consistent patterns

## Enforcement

### Compile-Time (Visibility)

- `primitives` is `pub(crate)` - external code cannot access it
- `testing` requires feature flag - not compiled in production

### CI/Pre-Commit Hook

The pre-commit hook checks for forbidden imports:

```bash
# Check: Production code must not import testing module
if grep -rE "use crate::testing" src/primitives src/observe src/security src/runtime; then
    echo "ERROR: Production code cannot depend on testing module"
    exit 1
fi
```

### Code Review Checklist

When reviewing PRs, verify:

- [ ] No `use crate::testing` in production code
- [ ] No `#[cfg(feature = "testing")]` in production code (except in test modules)
- [ ] Primitives don't generate events or import observe (except Problem type)
- [ ] Observe doesn't import security or runtime
- [ ] New modules follow the layer architecture

## Module Placement Guide

When adding new functionality, ask:

1. **Is it a pure utility with no octarine dependencies?**
   → `primitives/` (pub(crate))

1. **Does it need observability but no security?**
   → `observe/` (pub)

1. **Does it need security checks with full observability?**
   → `security/` or new Layer 3 module (pub)

1. **Is it test infrastructure for reuse?**
   → `testing/` (pub, feature-gated)

## Three Orthogonal Concerns in Primitives

The `primitives/` module is organized around three orthogonal concerns that apply across all domains (paths, network, text):

| Concern | Module | Question | Purpose |
|---------|--------|----------|---------|
| **FORMAT** | `data/` | "How should this be structured?" | Normalization, canonicalization |
| **THREATS** | `security/` | "Is this dangerous?" | Threat detection, attack prevention |
| **CLASSIFICATION** | `identifiers/` | "What is it? Is it PII?" | Type detection, PII identification |

### Why Three Separate Modules?

Each concern represents a fundamentally different question:

```rust
// CLASSIFICATION (identifiers/): What TYPE of data is this?
identifiers::network::is_ipv4("192.168.1.1")  // true - it's an IP address

// THREATS (security/): Is this data DANGEROUS?
security::network::is_ssrf_target("192.168.1.1")  // true - internal IP, SSRF risk

// FORMAT (data/): How should this be NORMALIZED?
data::network::normalize_url("HTTP://Example.COM/path")  // "http://example.com/path"
```

### Cross-Domain Application

Each domain can have operations in all three areas:

| Domain | data/ (FORMAT) | security/ (THREATS) | identifiers/ (CLASSIFICATION) |
|--------|----------------|---------------------|-------------------------------|
| **paths** | Path normalization | Traversal, injection | Location identifiers |
| **network** | URL formatting | SSRF, encoding attacks | IP, MAC, UUID detection |
| **text** | Encoding, normalization | Log injection, control chars | Personal identifiers |

### Placement Decision Tree

When adding new functionality to primitives:

1. **Does it answer "what type is this?"**
   → `identifiers/{domain}/` (e.g., email detection, IP classification)

1. **Does it answer "is this dangerous?"**
   → `security/{domain}/` (e.g., SSRF detection, traversal detection)

1. **Does it answer "how should this be formatted?"**
   → `data/{domain}/` (e.g., URL normalization, path canonicalization)

## Feature Flags

```toml
[features]
default = ["console", "full", "derive"]
full = ["observe", "security", "cli"]
observe = []
security = []
console = ["dep:console"]
cli = ["dep:clap", "dep:indicatif", "console"]
derive = ["dep:octarine-derive"]

# Optional capabilities
database = ["dep:graphql-parser"]
formats = ["dep:quick-xml", "dep:serde_yaml"]
postgres = ["database", "dep:sqlx", "sqlx?/postgres"]
sqlite = ["database", "dep:sqlx", "sqlx?/sqlite"]
otel = ["dep:opentelemetry", "dep:opentelemetry_sdk", "dep:opentelemetry-otlp"]
http = ["dep:axum", "dep:tower", "dep:tower-http", "dep:tower_governor", "dep:http", "dep:http-body-util"]
auth = ["http", "dep:jsonwebtoken", "dep:zxcvbn"]
auth-hibp = ["auth", "dep:sha1"]
auth-totp = ["auth", "dep:totp-rs"]
auth-full = ["auth-hibp", "auth-totp"]
crypto-validation = ["dep:pem", "dep:x509-parser", "dep:ssh-key", "dep:pkcs8"]
shell = []

# Test utilities - only in dev-dependencies
testing = ["dep:proptest", "dep:rstest", "dep:assert_fs", "dep:predicates",
           "dep:wiremock", "dep:assert_cmd", "dep:rexpect", "dep:shell-escape"]
```

Consumers use testing like this:

```toml
[dependencies]
octarine = { version = "0.2", features = ["full"] }

[dev-dependencies]
octarine = { version = "0.2", features = ["testing"] }
```

## Related Documents

- [Module Patterns](./module-patterns.md) - Three-layer pattern within each module
- [System Design](./system-design.md) - Overall system architecture
- [CLAUDE.md](../../CLAUDE.md) - Development guidelines
- [Testing Patterns](./testing-patterns.md) - How to use the testing module
