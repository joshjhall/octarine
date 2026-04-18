# Module Patterns

## Overview

octarine uses consistent architectural patterns across all modules to ensure maintainability, security, and ease of use. The primary patterns are the Three-Layer Pattern for module structure and the Builder Pattern for complex configurations.

## The Three-Layer Pattern

Every module in octarine follows a three-layer architecture that separates concerns and provides multiple levels of API access.

### Layer 1: Core Implementation (Private)

The innermost layer contains the actual business logic. These are private or `pub(crate)` functions that do the real work.

```text
module/
├── mod.rs              # Public exports only
├── traversal.rs        # Path traversal prevention logic
├── normalization.rs    # Path normalization logic
├── boundary.rs         # Boundary checking logic
├── filename.rs         # Filename sanitization logic
└── helpers.rs          # Shared utilities (if needed)
```

**Key Principles:**

- Implementation files live at the module root (Rust convention)
- Each file focuses on a single concern
- Functions are `pub(super)` or `pub(crate)` for internal use
- No external API exposure at this level
- Pure business logic, no API concerns

### Layer 2: Builder Pattern (Configuration)

The builder provides a configurable, composable API for complex use cases.

```text
module/
└── builder/            # API access patterns (NO business logic)
    ├── mod.rs          # Builder struct definition & orchestration
    ├── traversal.rs    # Builder methods that delegate to ../traversal
    ├── normalization.rs # Builder methods that delegate to ../normalization
    ├── boundary.rs     # Builder methods that delegate to ../boundary
    └── shortcuts.rs    # Common use-case shortcuts using the builder
```

**Key Principles:**

- **NO business logic** - only orchestration and delegation
- Builder methods delegate to core implementation
- Provides method chaining for ergonomic API
- Handles configuration and option management
- Makes complex operations composable

### Layer 3: Simple Functions (Convenience)

The outermost layer provides simple, direct functions for common use cases.

```rust
// In module/mod.rs or module/shortcuts.rs

/// Simple function with sensible defaults
pub fn sanitize_path(input: &str) -> String {
    PathSanitizer::builder()
        .remove_traversal()
        .normalize()
        .build()
        .sanitize(input)
        .unwrap_or_else(|_| String::from("/"))
}

/// Strict version that returns Result
pub fn sanitize_path_strict(input: &str) -> Result<String, Problem> {
    PathSanitizer::builder()
        .remove_traversal()
        .normalize()
        .strict_mode()
        .build()
        .sanitize(input)
}
```

## Implementation Example

Let's look at a complete example using the path sanitization module:

### Core Implementation (security/data/sanitization/paths/traversal.rs)

```rust
/// Core logic for removing path traversal attempts
pub(super) fn remove_path_traversal(path: &str) -> String {
    // Actual implementation - pure business logic
    let mut result = path.to_string();

    // Remove ../ and ..\
    while result.contains("../") || result.contains("..\\") {
        result = result.replace("../", "/");
        result = result.replace("..\\", "\\");
    }

    // Remove leading ..
    while result.starts_with("..") {
        result = result.trim_start_matches("..").to_string();
    }

    result
}

/// Check if path contains traversal attempts
pub(super) fn has_traversal(path: &str) -> bool {
    path.contains("..") || path.contains("~")
}
```

### Builder Pattern (security/data/sanitization/paths/builder/mod.rs)

```rust
pub struct PathSanitizerBuilder {
    remove_traversal: bool,
    normalize: bool,
    strict: bool,
    max_length: Option<usize>,
}

impl PathSanitizerBuilder {
    pub fn new() -> Self {
        Self {
            remove_traversal: true,  // Safe default
            normalize: true,          // Safe default
            strict: false,
            max_length: Some(4096),   // Safe default
        }
    }

    /// Enable traversal removal
    pub fn remove_traversal(mut self) -> Self {
        self.remove_traversal = true;
        self
    }

    /// Enable path normalization
    pub fn normalize(mut self) -> Self {
        self.normalize = true;
        self
    }

    /// Enable strict mode (returns Result instead of default)
    pub fn strict_mode(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Build the sanitizer
    pub fn build(self) -> PathSanitizer {
        PathSanitizer {
            config: self,
        }
    }
}

pub struct PathSanitizer {
    config: PathSanitizerBuilder,
}

impl PathSanitizer {
    /// Sanitize a path using configured options
    pub fn sanitize(&self, input: &str) -> Result<String, Problem> {
        let mut result = input.to_string();

        // Delegate to core implementations
        if self.config.remove_traversal {
            result = super::traversal::remove_path_traversal(&result);
        }

        if self.config.normalize {
            result = super::normalization::normalize_path(&result);
        }

        if let Some(max) = self.config.max_length {
            if result.len() > max {
                if self.config.strict {
                    return Err(Problem::validation("Path too long"));
                }
                result.truncate(max);
            }
        }

        Ok(result)
    }
}
```

### Simple Functions (security/data/sanitization/paths/mod.rs)

```rust
/// Quick sanitization with safe defaults
pub fn sanitize_path(input: &str) -> String {
    sanitize_path_strict(input)
        .unwrap_or_else(|_| String::from("/"))
}

/// Strict sanitization that returns Result
pub fn sanitize_path_strict(input: &str) -> Result<String, Problem> {
    PathSanitizer::builder()
        .remove_traversal()
        .normalize()
        .strict_mode()
        .build()
        .sanitize(input)
}

/// Check if a path is safe without modifying it
pub fn is_path_safe(input: &str) -> bool {
    !traversal::has_traversal(input) &&
    input.len() <= 4096 &&
    !input.contains('\0')
}
```

## The Dual Function Pattern

Most modules provide two versions of key functions:

### Strict Version (Returns Result)

```rust
pub fn operation_strict(input: &str) -> Result<Output, Problem> {
    // Validation and processing
    if !is_valid(input) {
        return Err(Problem::validation("Invalid input"));
    }

    Ok(process(input))
}
```

### Lenient Version (Returns Safe Default)

```rust
pub fn operation(input: &str) -> Output {
    operation_strict(input)
        .unwrap_or_else(|_| Output::safe_default())
}
```

## Benefits of This Architecture

### 1. Progressive Disclosure

- Simple cases use simple functions
- Complex cases use the builder
- Power users can access internals via `pub(crate)`

### 2. Separation of Concerns

- Business logic is isolated from API design
- Easy to test each layer independently
- Changes to implementation don't affect API

### 3. Safety by Default

- Simple functions have safe defaults
- Builder pattern prevents invalid configurations
- Strict mode available when needed

### 4. Maintainability

- Consistent structure across all modules
- Easy to navigate and understand
- Clear separation between what and how

### 5. Flexibility

- Multiple ways to use each module
- Composable operations via builder
- Extensible without breaking changes

## When to Use Each Layer

### Use Simple Functions When

- You need common, standard behavior
- You want safe defaults
- You're prototyping or exploring
- Performance isn't critical

### Use Builder Pattern When

- You need fine-grained control
- You're composing multiple operations
- You have specific configuration needs
- You're building reusable components

### Use Core Implementation When

- You're implementing new features
- You need maximum performance
- You're within the module (pub(super))
- You're testing specific logic

## Module Organization Guidelines

### File Size Limits

- Target: ~300 lines per file
- Maximum: ~500 lines per file
- Split when files become too large

### Naming Conventions

- Implementation files: descriptive names (e.g., `traversal.rs`)
- Public API in `mod.rs`
- Builder in `builder/` subdirectory
- Tests in same file (Rust convention)

### Visibility Rules

- `pub` - Only for public API
- `pub(crate)` - For cross-module use within crate
- `pub(super)` - For parent module access
- No modifier - Private to module

## Related Documentation

- [System Design](./system-design.md) - Overall architecture
- [API Naming Conventions](../api/naming-conventions.md) - API naming and prefix rules
- [Refactor Plan](./refactor-plan.md) - Current refactoring status
