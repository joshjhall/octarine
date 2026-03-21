# Security Patterns Catalog

Reusable security patterns and implementations for common security challenges.

## Quick Links

- **Input Validation**: [`validation.md`](./validation.md) - Validation strategies
- **Sanitization**: [`sanitization.md`](./sanitization.md) - Making input safe
- **Rate Limiting**: [`rate-limiting.md`](./rate-limiting.md) - DoS prevention

## Pattern Categories

### Input Security

#### [Detection vs Validation vs Sanitization Philosophy](./detection-validation-sanitization.md) ⭐ NEW

- Module purpose and philosophy
- When to use each layer
- Implementation differences
- Common mistakes to avoid
- Decision trees and examples

#### [Validation Patterns](./validation.md)

- Multi-layer validation
- Size and complexity limits
- Structure vs pattern validation
- Context-aware validation

#### [Sanitization Patterns](./sanitization.md)

- Strict vs lenient modes
- Context-specific sanitization
- Normalization before sanitization
- Safe defaults and fallbacks

#### [Conversion Patterns](./conversion.md)

- Safe type conversion
- Format transformation
- Encoding/decoding strategies

### Access Control

#### [Rate Limiting](./rate-limiting.md)

- Token bucket implementation
- Per-user/per-IP limiting
- Adaptive rate limiting
- Cost-based throttling

#### [Authentication](./authentication.md)

- Password hashing (Argon2)
- Session management
- Token generation
- Multi-factor patterns

### Data Protection

#### [Cryptography](./cryptography.md)

- High-level API usage
- Key management
- Secure random generation
- Encryption at rest

#### [Redaction](./redaction.md)

- PII/PHI detection
- Contextual redaction
- Logging safely
- Error message sanitization

## Implementation Examples

Each pattern includes:

1. **Problem** - What security issue it addresses
1. **Solution** - How to implement it
1. **Code Example** - Rust implementation
1. **Testing** - How to verify it works
1. **Common Mistakes** - What to avoid

## Related Sections

- [OWASP Guides](../owasp/) - Specific vulnerability prevention
- [API Security](../../api/security.md) - Secure API design
- [Source Code](../../../src/security/) - Actual implementations

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
