# Security Patterns Catalog

Reusable security patterns and implementations for common security challenges.

## Quick Links

- **Detection vs Validation vs Sanitization**: [`detection-validation-sanitization.md`](./detection-validation-sanitization.md) — Layer separation philosophy
- **Input Architecture**: [`input-architecture.md`](./input-architecture.md) — Input validation architecture
- **Zero-Trust**: [`zero-trust.md`](./zero-trust.md) — Zero-trust enforcement
- **Overview**: [`overview.md`](./overview.md) — Patterns overview

## Pattern Categories

### Input Security

#### [Detection vs Validation vs Sanitization Philosophy](./detection-validation-sanitization.md) ⭐

- Module purpose and philosophy
- When to use each layer
- Implementation differences
- Common mistakes to avoid
- Decision trees and examples

#### [Input Architecture](./input-architecture.md)

- Multi-layer validation
- Structure vs pattern validation
- Context-aware validation

#### [Zero-Trust](./zero-trust.md)

- Validate every boundary
- Fail secure
- Audit every security-relevant event

### Overview

#### [Patterns Overview](./overview.md)

- Catalog of patterns with trade-offs
- Cross-references to implementation modules
- Pre-deployment checklist

## Implementation Examples

Each pattern includes:

1. **Problem** — what security issue it addresses
1. **Solution** — how to implement it
1. **Code Example** — Rust implementation
1. **Testing** — how to verify it works
1. **Common Mistakes** — what to avoid

## Related Sections

- [Security Guidelines](../security-guidelines.md) — Project-wide principles
- [Data Module Architecture](../data-module-architecture.md) — Security/data module design
- [Source Code](../../../crates/octarine/src/security/) — Actual implementations

## Quick Reference

```rust
// Pattern: Multi-layer validation
pub fn validate_input(data: &str) -> Result<ValidatedData> {
    // Layer 1: Size check (cheap)
    check_size(data)?;

    // Layer 2: Format check
    check_format(data)?;

    // Layer 3: Content check
    check_content(data)?;

    // Layer 4: Business rules
    check_business_rules(data)?;

    Ok(ValidatedData::new(data))
}
```
