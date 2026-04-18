# API Design Guide

Principles and patterns for designing clean, secure, and ergonomic APIs in octarine.

## Quick Links

- **Naming Conventions**: [`naming-conventions.md`](./naming-conventions.md) - Prefix rules and API style
- **Error Handling**: [`error-handling.md`](./error-handling.md) - Result patterns
- **Error Architecture**: [`error-architecture.md`](./error-architecture.md) - Problem types and audit trail

## In This Section

### [Naming Conventions](./naming-conventions.md)

- Prefix-indicates-return-type rules
- Consistent naming across layers
- Prohibited prefixes

### [Error Handling](./error-handling.md)

- Result vs Option usage
- Problem types and categories
- Error propagation patterns
- Dual function pattern (strict/lenient)

### [Error Architecture](./error-architecture.md)

- Problem type design
- Audit-trail integration
- Error propagation across layers

## API Patterns

### Builder Pattern

```rust
let sanitizer = PathSanitizer::builder()
    .remove_traversal()
    .normalize()
    .strict_mode()
    .build();
```

### Dual Functions

```rust
// Strict - returns Result
let path = sanitize_path_strict("../file")?;

// Lenient - always succeeds
let path = sanitize_path("../file");
```

### Shortcuts for Common Cases

```rust
// Direct function for simple cases
let safe = sanitize_path(user_input);

// Builder for complex cases
let safe = PathSanitizer::builder()
    .custom_config()
    .build()
    .sanitize(user_input)?;
```

## Public API Surface

The public API is intentionally minimal:

- `octarine::observe` - Observability (events, problems)
- `octarine::security` - Security primitives

Internal modules use `pub(crate)` or `pub(super)` for encapsulation.

## Stability Guarantees

- Public API follows semantic versioning
- Breaking changes only in major versions
- Deprecation warnings before removal
- Migration guides for breaking changes

## Related Sections

- [Architecture](../architecture/) - System design
- [Security](../security/) - Security in APIs

## External Resources

- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Effective Rust](https://www.lurklurk.org/effective-rust/)
- [Rust Design Patterns](https://rust-unofficial.github.io/patterns/)
