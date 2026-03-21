# Builder Pattern Architecture

## Quick Reference

### File Structure

```text
module/
├── implementation.rs     # Business logic (pub(super))
├── builder/
│   ├── mod.rs           # THE Builder struct
│   ├── feature.rs       # Builder extensions (delegation only)
│   └── feature_shortcuts.rs  # Domain-specific shortcuts
└── mod.rs               # Minimal exports
```

**Note**: Shortcuts are organized by domain (`feature_shortcuts.rs`) rather than a single `shortcuts.rs` file. This improves clarity, discoverability, and maintainability.

### Dual Function Pattern

```rust
pub fn minimal_builder() -> ContextBuilder { /* configured builder */ }
pub fn minimal() -> EventContext { minimal_builder().build() }
```

### Key Rules

1. **No business logic in builder/**
1. **No builder code in implementation files**
1. **Always provide both `name()` and `name_builder()`**
1. **Builder extensions only delegate to implementation**

## Core Structure

Every module follows this exact structure:

```text
module/
├── mod.rs                     # Public API exports only
├── implementation.rs          # Core business logic (pub(super) functions)
├── domain_a.rs               # Domain A implementation
├── domain_b.rs               # Domain B implementation
├── builder/
│   ├── mod.rs                # THE Builder struct definition
│   ├── domain_a.rs           # Domain A builder extensions
│   ├── domain_a_shortcuts.rs # Domain A shortcuts
│   ├── domain_b.rs           # Domain B builder extensions
│   └── domain_b_shortcuts.rs # Domain B shortcuts
```

## Domain-Specific Shortcuts Pattern

### Why Domain-Specific Shortcuts?

As modules grow, a single `shortcuts.rs` file becomes unwieldy. Instead, we organize shortcuts by their functional domain:

1. **Clarity**: `payment_shortcuts.rs` clearly contains payment-related shortcuts
1. **Discoverability**: Developers can easily find relevant shortcuts
1. **Maintainability**: Changes to one domain don't affect others
1. **Scalability**: New domains don't bloat existing files
1. **Import Control**: Users import only what they need

### Hierarchical Shortcuts Structure

The shortcuts pattern scales to any depth, with each level serving a specific purpose:

```text
module/
├── shortcuts.rs              # Cross-domain shortcuts (combines multiple submodules)
├── domain_a.rs              # Domain A implementation
├── domain_b.rs              # Domain B implementation
├── submodule_a/
│   ├── shortcuts.rs         # Submodule A shortcuts (affects only submodule_a)
│   └── builder/
│       └── ...
├── submodule_b/
│   ├── shortcuts.rs         # Submodule B shortcuts (affects only submodule_b)
│   └── builder/
│       └── ...
└── builder/
    ├── mod.rs               # Compound builders
    ├── domain_a.rs          # Domain A builder extensions
    └── domain_a_shortcuts.rs # Domain A specific shortcuts
```

### Rules for Each Level

1. **`module/shortcuts.rs`**:

   - Combines MULTIPLE submodules or domains
   - Complex use cases spanning the entire module
   - Example: "log error with context and create problem"

1. **`module/submodule/shortcuts.rs`**:

   - Affects ONLY that submodule
   - Pre-configured builders for that submodule's domain
   - Example: "minimal context", "full context"

1. **`module/builder/domain_shortcuts.rs`**:

   - For non-leaf nodes with domain structure
   - Domain-specific shortcuts when module has both submodules AND domains
   - Example: observe has metrics.rs (domain) AND context/ (submodule)

### Real-World Example: Observe Module

```text
observe/
├── shortcuts.rs              # Combines context + event + problem
├── metrics.rs               # Domain: metrics (non-leaf with logic)
├── context/                 # Submodule
│   ├── shortcuts.rs         # Context-only: minimal(), full(), security()
│   └── builder/
│       └── ...
├── event/                   # Submodule
│   ├── shortcuts.rs         # Event-only: info(), warn(), error()
│   └── builder/
│       └── ...
├── problem/                 # Submodule
│   ├── shortcuts.rs         # Problem-only: validation(), security()
│   └── builder/
│       └── ...
└── builder/
    ├── mod.rs               # Compound builders
    ├── metrics.rs           # Metrics builder extensions
    └── metrics_shortcuts.rs # Metrics domain shortcuts
```

### Scaling Pattern

This pattern scales to any depth:

```text
security/
├── shortcuts.rs                      # Cross-module (input + access + secrets)
├── input/
│   ├── shortcuts.rs                  # Cross-input (validation + sanitization)
│   ├── validation/
│   │   ├── shortcuts.rs             # Cross-validation domains
│   │   ├── identifiers/
│   │   │   ├── shortcuts.rs         # Cross-identifier types
│   │   │   ├── payment.rs           # Payment domain
│   │   │   └── builder/
│   │   │       ├── payment.rs
│   │   │       └── payment_shortcuts.rs
│   │   └── text/
│   │       ├── shortcuts.rs         # Text-only shortcuts
│   │       └── ...
│   └── sanitization/
│       ├── shortcuts.rs             # Sanitization-only
│       └── ...
└── access_control/
    ├── shortcuts.rs                  # Access control only
    └── ...
```

### When to Create Shortcuts

Create shortcuts at a level when:

1. **Leaf level (`submodule/shortcuts.rs`)**: Common use cases for that specific domain
1. **Parent level (`module/shortcuts.rs`)**: Operations combining multiple children
1. **Domain-specific (`builder/domain_shortcuts.rs`)**: Non-leaf nodes with domain logic

Don't create shortcuts if:

- They would just duplicate the builder methods
- There's only one obvious way to use the builder
- The shortcuts would be rarely used

### Usage Examples

```rust
// Leaf-level shortcuts (single domain)
use observe::context::shortcuts::{minimal, full, security};

// Parent-level shortcuts (cross-domain)
use observe::shortcuts::log_error_with_context;

// Domain-specific (for non-leaf domains)
use observe::builder::shortcuts::metrics::counter;

// Deep hierarchy
use security::data::validation::identifiers::shortcuts::validate_credit_card;
use security::data::validation::shortcuts::validate_all_identifiers;
use security::data::shortcuts::validate_and_sanitize;
use security::shortcuts::secure_input_pipeline;
```

## Rules

### 1. Implementation Files (\*.rs at module root)

- Contains ONLY business logic
- Functions are `pub(super)` for internal access
- NO builder code, NO API concerns
- Pure implementation

### 2. Builder Module (builder/mod.rs)

- Defines THE single Builder struct for this module
- Contains configuration fields and basic setters
- Has `build()` method that orchestrates implementation calls
- This is the ONLY place the Builder struct is defined

### 3. Builder Extensions (builder/feature.rs)

- Import THE Builder from mod.rs
- Add methods to Builder via impl blocks
- These methods ONLY configure the builder or delegate to implementation
- NO business logic - only delegation

Example:

```rust
// In builder/capture.rs
use super::ContextBuilder;  // THE builder
use crate::observe::context::capture;  // Implementation

impl ContextBuilder {
    pub fn with_auto_capture(mut self) -> Self {
        self.auto_capture = true;
        self
    }

    pub fn capture_tenant_id(&mut self) {
        self.tenant_id = capture::capture_tenant_id();
    }
}
```

### 4. Shortcuts (builder/domain_shortcuts.rs)

- Organized by functional domain (e.g., `payment_shortcuts.rs`, `metrics_shortcuts.rs`)
- Implements DUAL FUNCTION pattern
- Every shortcut has two versions:
  - `name_builder()` - Returns configured Builder for further customization
  - `name()` - Returns built object directly
- NO other logic - just builder configuration

Example (`builder/context_shortcuts.rs`):

```rust
use super::ContextBuilder;
use crate::observe::EventContext;

/// Returns a builder configured for minimal context (customizable)
pub fn minimal_builder() -> ContextBuilder {
    ContextBuilder::new()
        .no_auto_capture()
        .security_relevant(false)
}

/// Returns a minimal context directly (ready to use)
pub fn minimal() -> EventContext {
    minimal_builder().build()
}

/// Returns a builder configured for security events (customizable)
pub fn security_builder() -> ContextBuilder {
    ContextBuilder::new()
        .security_relevant(true)
        .with_pii_detected()
}

/// Returns a security context directly (ready to use)
pub fn security() -> EventContext {
    security_builder().build()
}
```

#### Dual Function Naming Convention

- **`name_builder()`** - Returns a configured Builder instance
- **`name()`** - Returns the built object directly
- The suffix pattern keeps names short and groups related functions in autocomplete
- Users get the built object by default (most common case)
- Users can get the builder when they need customization

### 5. Module Exports (mod.rs)

```rust
// Internal implementation - not exported
mod capture;
mod compliance;

// Builder pattern
mod builder;

// Internal exports (for use within parent module)
pub(super) use builder::ContextBuilder;
pub(super) use builder::shortcuts;

// Public exports (very selective)
pub use some_type::SomeType;  // Only types that external users need
```

## Visibility Hierarchy

1. **Private** - Implementation details
1. **pub(super)** - Available to parent module
1. **pub(crate)** - Available within crate
1. **pub** - Public API (minimize this)

## Composition Pattern

Higher-level builders can compose lower-level ones. These also follow the dual function pattern:

```rust
// In observe/builder/audit_log.rs
use crate::observe::context::{shortcuts as context};
use crate::observe::event::{shortcuts as event};
use crate::observe::problem::{shortcuts as problem};

/// Returns a builder for a security audit (customizable)
pub fn security_audit_builder(user: &str, action: &str) -> AuditBuilder {
    AuditBuilder::new()
        .with_context(context::security_builder().with_user(user))
        .with_event(event::audit_builder().with_action(action))
}

/// Returns a complete security audit event (ready to use)
pub fn security_audit(user: &str, action: &str) -> AuditEvent {
    security_audit_builder(user, action).build()
}
```

### Compound Builder Guidelines

1. **Always provide both functions** - builder and built versions
1. **Compose using `*_builder()` functions** - for maximum flexibility
1. **Keep the built version simple** - just calls builder and builds
1. **Document what's being combined** - helps users understand the value

## Checklist for New Modules

### Structure Requirements

- [ ] Implementation in root .rs files with pub(super) functions
- [ ] Single Builder struct in builder/mod.rs
- [ ] Extensions in builder/domain.rs that only delegate
- [ ] Minimal exports in mod.rs
- [ ] No business logic in builder/
- [ ] No builder code in implementation files

### Shortcuts Organization

- [ ] `module/shortcuts.rs` for cross-submodule operations (if needed)
- [ ] `module/submodule/shortcuts.rs` for submodule-specific shortcuts (if needed)
- [ ] `module/builder/domain_shortcuts.rs` for non-leaf domain shortcuts (if needed)
- [ ] All shortcuts implement dual function pattern:
  - [ ] `name_builder()` functions that return Builders
  - [ ] `name()` functions that return built objects

### Guidelines

- [ ] Only create shortcuts where they add value
- [ ] Don't duplicate simple builder methods as shortcuts
- [ ] Place shortcuts at the appropriate level:
  - Leaf level: Single domain use cases
  - Parent level: Cross-domain combinations
  - Builder level: Non-leaf domain shortcuts
- [ ] Re-exports organized clearly in each mod.rs
