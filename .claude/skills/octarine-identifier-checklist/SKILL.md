---
description: Complete implementation checklist for adding identifier types to octarine. Use when adding detection functions, PII types, identifier categories, or new identifier domains (personal, financial, network, credentials, etc.).
---

# Octarine Identifier Checklist

**Detailed reference**: See `implementation-template.md` in this skill directory
for the full file-by-file template with function signatures, directory structure
for new domains, and verification commands. Load it when implementing any step.

## 12-Step Implementation Checklist

Every identifier type requires ALL applicable steps. Do not skip steps or
leave partial implementations.

### Layer 1: Primitives (pub(crate))

1. **Detection** — `primitives/identifiers/{domain}/detection/{type}.rs`
   - `pub fn is_{type}(value: &str) -> bool`
   - `pub fn detect_{type}s_in_text(text: &str) -> Vec<IdentifierMatch>`
   - Register in `detection/mod.rs`, add to `detect_{domain}_identifier()`

2. **Conversion** — `primitives/identifiers/{domain}/conversion.rs` (if applicable)
   - `pub fn normalize_{type}(value: &str) -> String`

3. **Validation** — `primitives/identifiers/{domain}/validation/{type}.rs`
   - `pub fn validate_{type}(value: &str) -> Result<(), Problem>`
   - MUST call detection first — validators depend on detectors

4. **Sanitization** — `primitives/identifiers/{domain}/sanitization/{type}.rs`
   - `pub fn sanitize_{type}(value: &str) -> Result<String, Problem>`

5. **Redaction** — `primitives/identifiers/{domain}/sanitization/` or dedicated file
   - `pub fn redact_{type}(value: &str, strategy: {Type}RedactionStrategy) -> String`
   - Define `{Type}RedactionStrategy` enum if new

### Layer 1: Primitives Builder (pub(crate))

6. **Detection methods** — `primitives/identifiers/{domain}/builder/detection_methods.rs`
7. **Validation methods** — `primitives/identifiers/{domain}/builder/validation_methods.rs`
8. **Sanitization methods** — `primitives/identifiers/{domain}/builder/sanitization_methods.rs`
   - All builder methods DELEGATE to implementation — no business logic

### Layer 3: Public API (pub)

9. **Public builder** — `identifiers/builder/{domain}.rs`
    - Wraps primitives builder + adds observe (metrics, events, timing)
    - See `octarine-architecture` skill's `decision-trees.md` for wrapping template

10. **Shortcuts** — `identifiers/shortcuts.rs`
    - `pub fn is_{type}(v: &str) -> bool { {Domain}Builder::new().is_{type}(v) }`
    - `pub fn validate_{type}(v: &str) -> Result<(), Problem> { ... }`
    - `pub fn redact_{type}(v: &str) -> String { ... }` (with default strategy)

11. **PII registration** — `observe/pii/types.rs` + `observe/pii/scanner/`
    - Add `IdentifierType::{Type}` variant if new
    - Register in PII scanner if the type is PII

### Verification

12. **Tests** at each layer — primitives tests, builder tests, shortcut tests

## Dual API Requirement

Every domain detection module MUST provide both functions:

```rust
pub fn detect_{domain}_identifier(value: &str) -> Option<IdentifierType> { ... }
pub fn is_{domain}_identifier(value: &str) -> bool {
    detect_{domain}_identifier(value).is_some()
}
```

## Inheritance Arrow (One-Way Dependencies)

```text
detection  -->  validation  -->  sanitization
(pure matching)  (uses detection)  (uses validation)
```

- `validation` imports `detection` — YES
- `sanitization` imports `detection` and `validation` — YES
- `detection` imports `validation` or `sanitization` — **NEVER**

## When to Use

- Adding a new identifier type to an existing domain
- Creating a new identifier domain
- Adding detection/validation/sanitization for any data type
- Reviewing an identifier PR for completeness

## When NOT to Use

- Adding security checks (THREATS) — use `octarine-architecture` skill
- Adding data normalization (FORMAT) — use `octarine-architecture` skill
- Modifying observe infrastructure
