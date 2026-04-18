# Cascading Visibility Pattern

> **Related:** This document explains the **visibility mechanics** of the builder cascade.
> For **file organization** and **directory structure**, see [Builder Hierarchy Pattern](./builder-hierarchy-pattern.md).

## The Problem This Solves

We want:

1. External developers to access builders/shortcuts ONLY at the top level (`octarine::security::`)
1. Internal modules to stay completely hidden (`octarine::security::data::` is NOT accessible)
1. Sub-builders to cascade up through the module hierarchy
1. **Primitives to be accessible crate-wide** (`pub(crate)`) while maintaining encapsulation

## Module Categories and Visibility Rules

This codebase has THREE distinct module categories, each with different visibility requirements:

### 1. **Primitives** (`src/primitives/`)

- **Purpose**: Foundation library - no business logic, pure utilities
- **Module Visibility**: `pub(crate)` - accessible anywhere in the crate
- **Item Visibility**: `pub` - accessible through parent module
- **Export Pattern**: NO cascading - items stay at primitives level
- **Examples**: `primitives::types::Problem()`, `primitives::runtime::RetryBuilder`

### 2. **Observe** (`src/observe/`)

- **Purpose**: Observability system - uses primitives, provides public API
- **Module Visibility**: `pub` - externally accessible
- **Item Visibility**: `pub` - externally accessible
- **Export Pattern**: Direct public modules (no internal/data separation)
- **Examples**: `observe::EventBuilder`, `observe::problem::Problem`

### 3. **Feature Modules** (`src/security/`, `src/runtime/`, etc.)

- **Purpose**: Domain functionality - uses primitives and observe, provides public API
- **Module Visibility**: Cascading (`pub(crate)` → `pub(super)` → `pub`)
- **Item Visibility**: `pub` for re-exports, cascades to top
- **Export Pattern**: Internal modules hidden, builders/shortcuts cascade up
- **Examples**: `security::IdentifierDetector`, `security::validate_path()`

## The Solution: Visibility Separation

**Key Insight:** The visibility of the MODULE and the visibility of RE-EXPORTED ITEMS are INDEPENDENT.

```rust
// data/mod.rs
pub(crate) mod detection;  // MODULE is internal (not accessible externally)

// But we can STILL re-export items from it as public
pub use detection::DetectionBuilder;  // RE-EXPORT is public (accessible to parent)
```

This allows items to "bubble up" through internal modules to become public at the top.

## The Pattern

### Level 4: Deep Implementation (e.g., `detection/identifiers/builder/`)

```rust
// detection/identifiers/builder/mod.rs

/// The actual builder struct
pub struct IdentifierDetector {  // ✅ Plain `pub` - accessible within module tree
    options: DetectionOptions,
}

impl IdentifierDetector {
    pub fn new() -> Self { ... }  // ✅ Plain `pub` methods
    pub fn find_ssns_in_text(&self, text: &str) -> Vec<Match> { ... }
}
```

**Rule:** Builder structs are `pub` (not `pub(super)`), methods are `pub`.

### Level 3: Domain Module (e.g., `detection/identifiers/`)

```rust
// detection/identifiers/mod.rs

mod builder;  // ✅ Module is PRIVATE (default visibility)

// Re-export the builder struct
pub use builder::IdentifierDetector;  // ✅ Plain `pub` - accessible within identifiers/ tree
```

**Rule:**

- Module `builder` stays PRIVATE
- Re-export uses `pub` so siblings and parent can access it

### Level 2: Category Module (e.g., `detection/`)

```rust
// detection/mod.rs

pub(super) mod identifiers;  // ✅ Module visible to parent (data/)
pub(super) mod builder;      // ✅ Module visible to parent

// Re-export builders from submodules
pub use builder::DetectionBuilder;       // ✅ Plain `pub`
pub use builder::IdentifierDetector;     // ✅ Plain `pub`
pub use builder::PathDetector;           // ✅ Plain `pub`
```

**Rule:**

- Submodules use `pub(super)` - visible to parent only
- Re-exports use `pub` - accessible within detection/ tree

### Level 1: Data Module (e.g., `data/`)

```rust
// data/mod.rs

pub(crate) mod detection;    // ✅ Module visible within crate only
pub(super) mod builder;      // ✅ Module visible to parent (security/)

// Re-export builders from submodules
pub use detection::DetectionBuilder;       // ✅ Plain `pub`
pub use detection::IdentifierDetector;     // ✅ Plain `pub`
pub use detection::PathDetector;           // ✅ Plain `pub`
pub use builder::DataBuilder;              // ✅ Plain `pub`
```

**Rule:**

- Submodules use `pub(crate)` or `pub(super)` - internal only
- Re-exports use `pub` - accessible to parent

### Level 0: Top Level (e.g., `security/`)

```rust
// security/builder/mod.rs

// Import from data/ (not data/builder/)
pub use super::data::DataBuilder;           // ✅ Plain `pub` - NOW EXTERNALLY VISIBLE
pub use super::data::DetectionBuilder;      // ✅ Plain `pub`
pub use super::data::IdentifierDetector;    // ✅ Plain `pub`
```

```rust
// security/mod.rs

pub(crate) mod data;   // ✅ Module stays internal
pub mod builder;       // ✅ Builder module is PUBLIC

// Re-export builders from builder/
pub use builder::DataBuilder;           // ✅ EXTERNALLY ACCESSIBLE
pub use builder::IdentifierDetector;    // ✅ EXTERNALLY ACCESSIBLE
```

**Rule:**

- Only at THIS level do items become externally accessible
- Modules below stay internal with `pub(crate)` or `pub(super)`
- Re-exports at this level are the ONLY external API

## Shortcuts Follow the Same Pattern

Shortcuts cascade exactly like builders:

```rust
// Level 4: detection/identifiers/builder/government_shortcuts.rs
pub fn find_ssns_in_text(text: &str) -> Vec<Match> { ... }

// Level 3: detection/identifiers/builder/mod.rs
pub mod shortcuts {
    pub use super::government_shortcuts::*;
}

// Level 2: detection/builder/mod.rs
pub(super) mod shortcuts {
    pub use super::identifiers::builder::shortcuts::*;
}

// Level 1: data/builder/mod.rs
pub(super) mod shortcuts {
    pub use super::detection::shortcuts::*;
}

// Level 0: security/builder/mod.rs
pub mod shortcuts {
    pub use crate::security::data::shortcuts::*;
}

// security/mod.rs
pub use builder::shortcuts::*;  // ✅ Now `find_ssns_in_text` is at security::
```

## The Key Difference: `pub` vs `pub(super)`

### ❌ WRONG: Using `pub(super)` for re-exports

```rust
// detection/identifiers/mod.rs
pub(super) use builder::IdentifierDetector;  // ❌ WRONG!

// detection/builder/mod.rs
pub(super) use super::identifiers::IdentifierDetector;  // ❌ Can't see it!
// ERROR: `IdentifierDetector` is private
```

**Why it fails:** `pub(super)` makes it visible to the PARENT only, not to SIBLINGS. So `detection/builder/` (a sibling of `identifiers/`) cannot see it.

### ✅ CORRECT: Using `pub` for re-exports

```rust
// detection/identifiers/mod.rs
pub use builder::IdentifierDetector;  // ✅ Visible within identifiers/ tree

// detection/builder/mod.rs
pub use super::identifiers::IdentifierDetector;  // ✅ Can access it!
```

**Why it works:** `pub` makes it visible within the module tree. Even though the MODULE `identifiers` is `pub(super)`, the RE-EXPORTED items can be `pub`.

## Visual Summary

```text
External Code
    ↓ (can only access)
security/mod.rs                [pub use builder::*]
    ↓
security/builder/mod.rs        [pub use data::*]
    ↓
security/data/mod.rs           [pub(crate) mod] [pub use detection::*]
    ↓
security/data/detection/mod.rs [pub(super) mod] [pub use builder::*]
    ↓
detection/builder/mod.rs       [pub use identifiers::*]
    ↓
identifiers/mod.rs             [mod builder] [pub use builder::*]
    ↓
identifiers/builder/mod.rs     [pub struct IdentifierDetector]
```

**Left column:** Module visibility (gets more restricted going down)
**Right column:** Re-export visibility (stays `pub` all the way up)

## What Gets Exposed Externally

From `octarine::security::`:

### Builders (Direct Access)

```rust
use octarine::security;

let detector = security::IdentifierDetector::new();
let matches = detector.find_ssns_in_text("text");
```

### Shortcuts (Function Calls)

```rust
use octarine::security;

let matches = security::find_ssns_in_text("text");
let is_safe = security::validate_path("/path");
```

### What's NOT Accessible

```rust
// ❌ These FAIL - modules are internal
use octarine::security::data;                          // ERROR: `data` is private
use octarine::security::data::detection;               // ERROR
use octarine::security::data::detection::identifiers;  // ERROR
```

## Implementation Checklist

When adding a new builder that needs to cascade:

- [ ] Define builder with `pub struct` and `pub` methods
- [ ] Parent module: `mod builder;` (private) + `pub use builder::YourBuilder;`
- [ ] Each level up: `pub use submodule::YourBuilder;` (not `pub(super)`)
- [ ] Module visibility: Use `pub(super)` or `pub(crate)` for modules
- [ ] Top level only: Final re-export in `security/mod.rs` with plain `pub`

## Common Mistakes

### ❌ Making modules `pub` too early

```rust
// data/detection/identifiers/mod.rs
pub mod builder;  // ❌ NO! Makes internal structure visible
```

**Fix:** Keep modules private or `pub(super)`, only re-export items:

```rust
mod builder;
pub use builder::IdentifierDetector;  // ✅ Only the struct is visible
```

### ❌ Using `pub(super)` for re-exports

```rust
pub(super) use builder::MyBuilder;  // ❌ Siblings can't see it
```

**Fix:** Use plain `pub` for re-exports:

```rust
pub use builder::MyBuilder;  // ✅ Visible within module tree
```

### ❌ Importing from `data::builder::` instead of `data::`

```rust
// security/builder/mod.rs
pub use super::data::builder::DataBuilder;  // ❌ Goes too deep
```

**Fix:** Import from the level that re-exports:

```rust
pub use super::data::DataBuilder;  // ✅ From data/mod.rs re-export
```

## Why This Pattern Works

1. **Encapsulation:** Internal modules stay completely hidden
1. **Flexibility:** Can reorganize internals without breaking external API
1. **Single Entry Point:** External code has one clear place to import from
1. **Type Safety:** Builders are real types, not just re-exports
1. **Documentation:** Docs generate cleanly at the top level only

## Primitives: The Exception to Cascading

Primitives do NOT use the cascading pattern. They are foundation utilities with simpler visibility rules.

### Primitives Module Structure

```text
src/primitives/
├── mod.rs              [pub(crate) mod common, runtime, etc.]
├── common/
│   ├── mod.rs          [pub fn dedupe, validate, etc.]
│   ├── dedupe.rs       [pub(super) fn dedupe_vec]
│   └── validate.rs     [pub(super) fn is_valid]
└── runtime/
    ├── mod.rs          [pub struct RetryBuilder, pub use retry::*]
    └── retry.rs        [pub(super) struct RetryConfig]
```

### Primitives Visibility Rules

```rust
// src/primitives/mod.rs
pub(crate) mod common;    // ✅ Accessible crate-wide
pub(crate) mod runtime;   // ✅ Accessible crate-wide

// NO cascading to parent - primitives stay at this level
```

```rust
// src/primitives/common/mod.rs
pub fn dedupe<T>(items: Vec<T>) -> Vec<T> { ... }  // ✅ Accessible as primitives::types::Problem
pub fn validate(input: &str) -> bool { ... }      // ✅ Accessible as primitives::collections::RingBuffer

// Internal helpers
mod dedupe_impl;  // ❌ Private - not accessible outside common/
```

```rust
// src/primitives/common/dedupe_impl.rs
pub(super) fn dedupe_vec<T>(items: Vec<T>) -> Vec<T> { ... }  // ✅ Used by parent common/mod.rs
```

### Using Primitives from Feature Modules

```rust
// src/security/data/detection/identifiers/personal.rs
use crate::primitives::types::Problem;  // ✅ Direct import

pub fn find_emails_in_text(text: &str) -> Vec<Match> {
    let matches = find_all_emails(text);
    dedupe(matches)  // ✅ Using primitive
}
```

### Using Primitives from Observe

```rust
// src/observe/event/builder.rs
use crate::primitives::runtime::RetryBuilder;  // ✅ Direct import

pub struct EventBuilder {
    retry: RetryBuilder,  // ✅ Using primitive
}
```

### Primitives Design Principles

1. **No Business Logic**: Only pure utilities, no domain knowledge
1. **No Dependencies**: Primitives NEVER import from observe or feature modules
1. **Crate-Wide Access**: Always `pub(crate)` modules, `pub` items
1. **No Cascading**: Items stay at primitives level, not re-exported to top
1. **Well-Tested**: Comprehensive unit tests, no integration tests needed
1. **Well-Documented**: Clear doc comments, doc tests for all public items

### Primitives vs Feature Modules

| Aspect | Primitives | Feature Modules (security, runtime) |
|--------|-----------|-------------------------------------------|
| **Purpose** | Foundation utilities | Domain functionality |
| **Module Visibility** | `pub(crate)` | Cascading (internal → public) |
| **Item Visibility** | `pub` | `pub` (cascades to top) |
| **Dependencies** | None (except std) | Can use primitives + observe |
| **Export Pattern** | Direct access | Cascade through builders |
| **Example** | `primitives::types::Problem()` | `security::find_ssns_in_text()` |

## Related Patterns

- [Builder Hierarchy Pattern](./builder-hierarchy-pattern.md) - File organization, naming conventions, directory structure
- [Module Patterns](../architecture/module-patterns.md) - Three-layer architecture (core/builder/shortcuts)
- [Refactor Plan](../architecture/refactor-plan.md) - Strategy for migrating to primitives module
