---
description: PII-Identifier bridge synchronization for octarine. Use when adding identifier types, PiiType variants, or modifying PII scanner domains to keep the three parallel registries in sync.
---

# Octarine PII-Identifier Bridge

When adding a new identifier type, THREE registries must stay in sync.
Updating one without the others causes silent detection gaps (e.g., a new
credential type detected by primitives but invisible to PII scanning).

## The Three Registries

| Registry | File | Purpose |
|----------|------|---------|
| `IdentifierType` | `identifiers/types/core.rs` | Public API enum (44 variants) |
| `PiiType` | `observe/pii/types.rs` | PII classification enum (47 variants) |
| Scanner domains | `observe/pii/scanner/domains.rs` | Detection dispatch per domain |

**All three MUST be updated together.** There is no compile-time enforcement.

## Update Checklist

When adding a new identifier type `{Type}` to domain `{domain}`:

### 1. IdentifierType (public API)

File: `crates/octarine/src/identifiers/types/core.rs`

```rust
pub enum IdentifierType {
    // ... existing variants
    {Type},  // Add variant
}
```

Update BOTH `From` impls (lines ~145-262):
- `From<primitives::IdentifierType> for IdentifierType`
- `From<IdentifierType> for primitives::IdentifierType`

### 2. PiiType (observe layer)

File: `crates/octarine/src/observe/pii/types.rs`

```rust
pub enum PiiType {
    // ... existing variants in the {domain} section
    {Type},  // Add variant
}
```

Update classification methods:
- `domain()` — return correct `PiiDomain::{Domain}`
- `is_high_risk()` — if the type is high-risk PII
- `is_gdpr_protected()` — if GDPR-relevant
- `is_pci_protected()` — if PCI-DSS-relevant (financial data)
- `is_hipaa_protected()` — if HIPAA-relevant (medical/health data)
- `is_secret()` — if it's a secret/credential

### 3. Scanner Domain Function

File: `crates/octarine/src/observe/pii/scanner/domains.rs`

Add detection call to the appropriate `scan_{domain}` function:
```rust
pub(crate) fn scan_{domain}(text: &str) -> Vec<PiiMatch> {
    let builder = {Domain}IdentifierBuilder::new();
    // ... existing detections
    // Add new detection:
    if builder.is_{type}(text) {
        matches.push(PiiMatch::new(PiiType::{Type}, text));
    }
}
```

### 4. Primitives IdentifierType (if not already added)

File: `crates/octarine/src/primitives/identifiers/common/types.rs` (or equivalent)

Add variant to the primitives-level enum as well.

## Compliance Classification Guide

| Data Category | GDPR | PCI-DSS | HIPAA | High Risk |
|---------------|------|---------|-------|-----------|
| Name, Email, Phone, Birthdate | YES | no | YES | no |
| SSN, Passport, DriverLicense | YES | no | YES | YES |
| CreditCard, BankAccount | YES | YES | no | YES |
| MRN, NPI, ICD codes | no | no | YES | YES |
| ApiKey, JWT, Password, SshKey | no | no | no | YES (secret) |
| IP, MAC, UUID | YES | no | no | no |
| GPS, Address, PostalCode | YES | no | YES | no |

## Verification

After updating all three registries:

```bash
# Verify variant counts match expectations
grep -c "^\s\+[A-Z]" crates/octarine/src/identifiers/types/core.rs
grep -c "^\s\+[A-Z]" crates/octarine/src/observe/pii/types.rs

# Verify From impls cover the new variant
grep "{Type}" crates/octarine/src/identifiers/types/core.rs

# Verify scanner covers the new type
grep "{type}\|{Type}" crates/octarine/src/observe/pii/scanner/domains.rs

# Run PII tests
cargo test -p octarine pii
cargo test -p octarine identifier
```

## When to Use

- Adding any new `IdentifierType` variant
- Adding any new `PiiType` variant
- Modifying PII scanner domain functions
- Adding new identifier domain to primitives

## When NOT to Use

- Modifying detection logic within an existing type (no registry change)
- Changing redaction strategies (no type change)
