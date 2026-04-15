---
description: PII-Identifier bridge synchronization for octarine. Use when adding identifier types, PiiType variants, or modifying PII scanner domains to keep the three parallel registries in sync.
---

# Octarine PII-Identifier Bridge

**There is no compile-time enforcement linking these registries.** When adding
a new identifier type, THREE registries must stay in sync. Updating one without
the others causes silent detection gaps (e.g., a new credential type detected
by primitives but invisible to PII scanning).

Load `octarine-identifier-checklist` alongside this skill for the full 12-step
implementation process; this skill covers only the cross-registry sync steps.

## The Three Registries

| Registry | File | Purpose |
|----------|------|---------|
| `IdentifierType` | `primitives/identifiers/types.rs` | Primitives-level enum (source of truth) |
| `PiiType` | `observe/pii/types.rs` | PII classification enum |
| Scanner domains | `observe/pii/scanner/domains.rs` | Detection dispatch per domain |

**All three MUST be updated together.**

## Update Checklist

When adding a new identifier type `{Type}` to domain `{domain}`:

### 1. IdentifierType (primitives — source of truth)

File: `crates/octarine/src/primitives/identifiers/types.rs`

Add variant to the `IdentifierType` enum in the appropriate domain section.
The Layer 3 file `identifiers/types/core.rs` is a re-export — do not edit it.

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

Read the actual `is_*_protected()` methods in `observe/pii/types.rs` for
current classifications before deciding which to update.

### 3. Scanner Domain Function

File: `crates/octarine/src/observe/pii/scanner/domains.rs`

Add detection call to the appropriate `scan_{domain}` function:
```rust
pub(super) fn scan_{domain}(text: &str, pii_types: &mut Vec<PiiType>) {
    let builder = {Domain}IdentifierBuilder::new();
    // ... existing detections
    if !builder.detect_{type}s_in_text(text).is_empty() {
        pii_types.push(PiiType::{Type});
    }
}
```

## Verification

After updating all three registries:

```bash
# Verify the new variant appears in all three files
grep "{Type}" crates/octarine/src/primitives/identifiers/types.rs
grep "{Type}" crates/octarine/src/observe/pii/types.rs
grep "{type}\|{Type}" crates/octarine/src/observe/pii/scanner/domains.rs

# Run PII and identifier tests
just test-mod "pii"
just test-mod "identifier"
```

## When to Use

- Adding any new `IdentifierType` variant
- Adding any new `PiiType` variant
- Modifying PII scanner domain functions
- Adding new identifier domain to primitives

## When NOT to Use

- Modifying detection logic within an existing type (no registry change)
- Changing redaction strategies (no type change)
