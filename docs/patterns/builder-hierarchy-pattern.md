# Builder Hierarchy Pattern

> **Related:** This document covers **file organization** and **directory structure** for builders.
> For the **visibility mechanics** (how `pub`/`pub(super)` cascading works), see [Cascading Visibility Pattern](./cascading-visibility.md).

## Overview

This document defines the standard pattern for organizing builders in a hierarchical module structure. This pattern provides a single, unified API at the root level while keeping internal implementation details encapsulated.

## Core Principles

1. **Single Entry Point**: External developers only interact with root-level builders
1. **Facade Pattern**: Each level creates a facade that composes builders from the level below
1. **Visibility Layers**: Each level exposes to its parent using appropriate visibility modifiers
1. **File Naming**: Use exact submodule names (singular) for traceability
1. **Scoped Shortcuts**: Each domain has its own shortcuts file when applicable
1. **Aggregate for Cross-cutting**: Use aggregate.rs/aggregate_shortcuts.rs for multi-domain operations
1. **Documentation Files**: Create files for ALL submodules, even if just documenting why something isn't exposed

## Visibility by Level

| Level | Module Visibility | Struct Visibility | Who Can Import | Example |
|-------|-------------------|-------------------|----------------|---------|
| **Root builder** | `pub` | `pub struct` | External developers | `security/builder/mod.rs` |
| **Sub builder** | `pub(super)` | `pub struct` | Via re-exports only | `security/data/builder/mod.rs` |
| **Deep builder** | `pub(super)` | `pub struct` | Via re-exports only | `security/data/sanitization/builder/mod.rs` |
| **Domain functions** | private | `pub(super)` or private | Parent builder only | `security/data/sanitization/personal.rs` |

**Critical Distinction**:

- **Modules** use `pub(super)` or `pub(crate)` to stay internal
- **Structs** use `pub struct` at ALL levels (needed for re-export cascade)
- **Re-exports** use `pub use` to bubble items up the hierarchy
- See [Cascading Visibility Pattern](./cascading-visibility.md) for detailed explanation

## File Naming Convention

### 1. Use Exact Submodule Name (Singular)

```text
observe/builder/
├── event.rs           # Matches observe/event/
├── problem.rs         # Matches observe/problem/
├── context.rs         # Matches observe/context/
├── metrics.rs         # Matches observe/metrics/
└── writers.rs         # Matches observe/writers/
```

**Rule**: Use the exact singular name of the submodule. Not plural, not abbreviated, not suffixed.

### 2. Scoped Shortcuts Per Submodule

```text
observe/builder/
├── event.rs
├── event_shortcuts.rs        # Shortcuts ONLY for event operations
├── problem.rs
├── problem_shortcuts.rs      # Shortcuts ONLY for problem operations
├── metrics.rs
├── metrics_shortcuts.rs      # Shortcuts ONLY for metrics operations
```

**Rule**: Create `{submodule}_shortcuts.rs` for domain-specific shortcuts. Only create when applicable.

### 3. Aggregate for Cross-Cutting

```text
observe/builder/
├── aggregate.rs              # Extensions using multiple sub-builders
└── aggregate_shortcuts.rs    # Shortcuts for cross-cutting patterns
```

**Rule**:

- `aggregate.rs` contains extensions that use MULTIPLE sub-builders (e.g., event + problem + context)
- `aggregate_shortcuts.rs` contains shortcuts for these cross-cutting patterns
- Examples: `fail()` logs error event AND returns problem

## File Types and Purpose

### mod.rs - Main Builder Facade

```rust
//! Unified [Module] builder - facade for all [module] operations
//!
//! This builder provides a single, unified API that composes:
//! - [Submodule1] ([purpose])
//! - [Submodule2] ([purpose])
//! - [Submodule3] ([purpose])
//!
//! Users interact with [Module]Builder, which internally delegates to
//! specialized sub-builders that remain private implementation details.

// Extension modules that add methods to [Module]Builder
mod submodule1;
mod submodule2;
mod submodule3;
mod aggregate;

// Shortcuts (when applicable)
mod submodule1_shortcuts;
mod aggregate_shortcuts;

// Import the sub-builders (they stay private to parent module)
use super::submodule1::Submodule1Builder;
use super::submodule2::Submodule2Builder;

/// Unified [module] builder - single API for all [module] operations
#[derive(Debug, Clone)]
pub struct ModuleBuilder {
    // Configuration fields
    pub(super) field1: String,
    pub(super) field2: Option<String>,
}

impl ModuleBuilder {
    pub fn new() -> Self { /* ... */ }

    // Configuration methods
    pub fn field1(mut self, value: impl Into<String>) -> Self { /* ... */ }
}
```

**Purpose**:

- Define the main facade builder struct
- Import sub-builders (with appropriate visibility)
- Provide configuration methods
- NO business logic - only field management

**Visibility**:

- **Struct**: Always `pub struct` (at ALL levels)
- **Module**: `pub` at root, `pub(super)` at sub-levels
- **Methods**: Always `pub` (builder methods are part of public API)

### submodule.rs - Domain Extensions

```rust
//! [Submodule] extensions for [Module]Builder
//!
//! Provides [category] methods that delegate to [Submodule]Builder internally.

use super::ModuleBuilder;
use super::SubmoduleBuilder;

/// Extensions for [Module]Builder related to [submodule] operations
impl ModuleBuilder {
    /// [Operation description]
    pub fn operation_name(self) -> ReturnType {
        // Delegate to sub-builder
        SubmoduleBuilder::new(self.field1)
            .with_context(self.build_context())
            .execute()
    }
}
```

**Purpose**:

- Extend the main builder with domain-specific operations
- Delegate to sub-builders (internal)
- NO business logic - only delegation

**Visibility**:

- **Methods**: Always `pub` (methods on builder structs are always public)
- **Module**: Visibility depends on level (not the methods themselves)

### submodule_shortcuts.rs - Domain Shortcuts

```rust
//! Shortcut functions for [submodule] operations
//!
//! Provides convenient functions that create a builder and call methods.
//! These are scoped to [submodule] operations only.

use super::ModuleBuilder;

/// [Operation] shortcut
pub fn operation_name(param: &str) -> ReturnType {
    ModuleBuilder::new()
        .field1(param)
        .operation_name()
}
```

**Purpose**:

- Convenience functions for common operations
- Create builder + call method in one step
- Scoped to single domain

**When to create**: Only when there are useful shortcuts for this domain

**Visibility**:

- **Functions**: Always `pub` (shortcuts are always public functions)
- **Module**: Shortcuts modules use special visibility (see cascading-visibility.md)

### aggregate.rs - Cross-Cutting Extensions

```rust
//! Aggregate operation extensions for [Module]Builder
//!
//! Provides high-level operations that combine multiple sub-builders.
//! These delegate to aggregate domain functions or coordinate multiple domains.

use super::ModuleBuilder;
use crate::module::aggregate::{aggregate_function};

/// Extensions for [Module]Builder related to aggregate operations
impl ModuleBuilder {
    /// [Cross-cutting operation description]
    ///
    /// This operation combines [submodule1] + [submodule2] + [submodule3]
    pub fn cross_cutting_operation(self) -> ReturnType {
        // Delegate to aggregate domain function
        aggregate_function(self.field1, self.field2)
    }
}
```

**Purpose**:

- Operations that use MULTIPLE sub-builders
- Delegate to aggregate domain functions
- Coordinate cross-cutting concerns

**When to create**: When operations span multiple domains

### aggregate_shortcuts.rs - Cross-Cutting Shortcuts

```rust
//! Shortcut functions for aggregate operations
//!
//! Provides convenient functions for cross-cutting patterns that
//! combine multiple domains (e.g., [submodule1] + [submodule2]).

use super::ModuleBuilder;

/// [Cross-cutting shortcut]
pub fn cross_cutting_shortcut(param: &str) -> ReturnType {
    ModuleBuilder::new()
        .field1(param)
        .cross_cutting_operation()
}
```

**Purpose**: Shortcuts for operations that span multiple domains

### Documentation-Only Files

For submodules that are NOT exposed:

```rust
//! [Submodule] extensions for [Module]Builder
//!
//! NOTE: [Submodule] is [reason not exposed].
//!
//! [Detailed explanation of design decision]
//!
//! Examples:
//! - "Context is automatically captured and does not need explicit configuration"
//! - "Writers are internal infrastructure configured globally, not per-operation"
//! - "Types are core structures, not operations"

// No public API - [summary reason]
```

**Purpose**:

- Document WHY a submodule isn't exposed
- Prevent future confusion
- Create complete architecture map

**When to create**: For EVERY submodule, even if not exposed

## Directory Structure Examples

### Example 1: observe/ (2 levels)

```text
observe/
├── builder/              # Root level (pub)
│   ├── mod.rs           # ObserveBuilder facade
│   ├── event.rs         # Event extensions (delegates to EventBuilder)
│   ├── event_shortcuts.rs
│   ├── problem.rs       # Problem extensions (delegates to ProblemBuilder)
│   ├── problem_shortcuts.rs
│   ├── context.rs       # Documentation: auto-captured
│   ├── metrics.rs       # Metrics extensions (delegates to MetricsBuilder)
│   ├── metrics_shortcuts.rs
│   ├── writers.rs       # Documentation: internal only
│   ├── aggregate.rs     # Cross-cutting (event + problem + context)
│   └── aggregate_shortcuts.rs
│
├── event/
│   └── builder/         # Sub level (pub(super))
│       ├── mod.rs       # EventBuilder
│       └── dispatch.rs  # Extensions
│
├── problem/
│   └── builder/         # Sub level (pub(super))
│       ├── mod.rs       # ProblemBuilder
│       └── create.rs    # Extensions
│
├── context/
│   └── builder/         # Sub level (pub(super))
│       ├── mod.rs       # ContextBuilder
│       └── tenant.rs    # Extensions
│
└── metrics/
    └── builder/         # Sub level (pub(super))
        ├── mod.rs       # MetricsBuilder
        ├── counters.rs  # Extensions
        └── gauges.rs    # Extensions
```

### Example 2: security/data/ (3 levels)

```text
security/
├── builder/                    # Root level (pub)
│   ├── mod.rs                 # SecurityBuilder facade
│   ├── data.rs                # Re-exports from security/data/builder/
│   ├── data_shortcuts.rs
│   ├── access_control.rs      # Re-exports from security/access_control/builder/
│   └── aggregate.rs
│
└── data/
    ├── builder/                # Level 2 (pub(super))
    │   ├── mod.rs             # DataBuilder facade
    │   ├── detection.rs       # Re-exports from detection/builder/
    │   ├── detection_shortcuts.rs
    │   ├── validation.rs      # Re-exports from validation/builder/
    │   ├── validation_shortcuts.rs
    │   ├── sanitization.rs    # Re-exports from sanitization/builder/
    │   ├── sanitization_shortcuts.rs
    │   ├── conversion.rs      # Re-exports from conversion/builder/
    │   └── aggregate.rs       # Cross-cutting (detect + validate + sanitize)
    │
    ├── sanitization/
    │   └── builder/            # Level 3 (pub(super))
    │       ├── mod.rs         # SanitizationBuilder facade
    │       ├── identifiers.rs # Re-exports from identifiers/builder/
    │       ├── identifiers_shortcuts.rs
    │       ├── paths.rs       # Re-exports from paths/builder/
    │       └── aggregate.rs
    │
    └── detection/
        └── builder/            # Level 3 (pub(super))
            ├── mod.rs         # DetectionBuilder facade
            ├── identifiers.rs
            ├── paths.rs
            └── aggregate.rs
```

## Implementation Checklist

When implementing this pattern:

### For Each Level

- [ ] Create `mod.rs` with main builder facade struct
- [ ] Create `{submodule}.rs` for EACH submodule (even if documentation-only)
- [ ] Create `{submodule}_shortcuts.rs` when applicable
- [ ] Create `aggregate.rs` if cross-cutting operations exist
- [ ] Create `aggregate_shortcuts.rs` if cross-cutting shortcuts exist
- [ ] Set correct visibility (`pub` at root, `pub(super)` at sub-levels)
- [ ] Ensure builder struct only has configuration methods
- [ ] Ensure extension files only have delegation (no business logic)

### For Extension Files

- [ ] Import sub-builder with appropriate visibility
- [ ] Implement methods that delegate to sub-builder
- [ ] NO business logic in extension methods
- [ ] Clear documentation of what's being delegated to

### For Shortcut Files

- [ ] Import main builder
- [ ] Create convenience functions
- [ ] Pattern: Create builder → configure → call method
- [ ] Only create file if there are useful shortcuts

### For Documentation-Only Files

- [ ] Include "NOTE:" explaining why not exposed
- [ ] Provide detailed rationale
- [ ] Add comment: `// No public API - [reason]`

## Anti-Patterns to Avoid

### ❌ DON'T: Make modules public at sub-levels

```rust
// DON'T make the MODULE public at sub-levels
// security/data/mod.rs
pub mod builder;  // ❌ Should be pub(super) or pub(crate)

// ✅ DO: Keep module internal, but struct can be pub
pub(super) mod builder;
// Inside builder/mod.rs: pub struct DataBuilder { }  ✅ Struct is pub
```

### ❌ DON'T: Skip documentation files

```rust
// DON'T omit files for non-exposed submodules
// observe/builder/
// (missing context.rs)  // ❌ Should document why not exposed
```

### ❌ DON'T: Put business logic in builders

```rust
impl ObserveBuilder {
    pub fn info(self) {
        // ❌ DON'T: Inline business logic
        let event = Event::new(EventType::Info, self.message);
        writers::dispatch(event);

        // ✅ DO: Delegate to sub-builder
        EventBuilder::new(&self.message)
            .with_context(self.build_context())
            .info();
    }
}
```

### ❌ DON'T: Use inconsistent file names

```rust
// observe/builder/
// events.rs      ❌ Should be event.rs (singular, matches submodule)
// metrics_ops.rs ❌ Should be metrics.rs (no suffix)
```

### ❌ DON'T: Mix domains in shortcuts

```rust
// observe/builder/event_shortcuts.rs
pub fn fail(op: &str, msg: &str) -> Problem {
    // ❌ This uses event + problem, belongs in aggregate_shortcuts.rs
}
```

## Benefits

1. **Single API Surface**: External developers only see root builders
1. **Encapsulation**: Internal builders completely hidden
1. **Refactoring Freedom**: Can reorganize internals without breaking users
1. **Scalability**: Pattern works at any depth
1. **Traceability**: File names map directly to module structure
1. **Documentation**: Architecture decisions are documented in code
1. **Dead Code Consolidation**: Warnings only at public API boundaries
1. **Clear Ownership**: Each file has a single, clear purpose

## Migration Strategy

When applying this pattern to existing modules:

1. Create root builder directory (`module/builder/`)
1. Create `mod.rs` with facade struct
1. For each submodule:
   - Create `{submodule}.rs` extension file
   - Implement delegation to existing sub-builder
   - Create shortcuts file if applicable
1. Create `aggregate.rs` for cross-cutting operations
1. Update visibility modifiers on modules (make modules pub(super), keep structs pub)
1. Update public API to export only root builder
1. Test that external API still works
1. Verify internal builders are not accessible externally

## Questions?

This pattern should apply consistently across:

- `observe/builder/`
- `security/builder/`
- `security/data/builder/`
- `security/data/{detection,validation,sanitization,conversion}/builder/`

If you encounter a case that doesn't fit this pattern, document it as an exception with clear rationale.
