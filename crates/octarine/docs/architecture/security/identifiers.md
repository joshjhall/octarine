# Identifier Security Architecture

> **Purpose**: Cross-cutting architecture documentation for identifier detection, validation, and sanitization modules.
>
> **Audience**: Developers extending the identifier system or understanding design decisions.
>
> **Location**: `src/security/data/{detection,validation,sanitization}/identifiers/`

______________________________________________________________________

## Table of Contents

1. [Overview](#overview)
1. [Design Principles](#design-principles)
1. [Three-Layer Architecture](#three-layer-architecture)
1. [Module Organization](#module-organization)
1. [Security Taxonomy](#security-taxonomy)
1. [Common Patterns](#common-patterns)
1. [Design Decisions](#design-decisions)
1. [Extension Guide](#extension-guide)
1. [Quality Metrics](#quality-metrics)

______________________________________________________________________

## Overview

The identifier security system provides comprehensive protection for sensitive identifiers across three complementary dimensions:

- **Detection** (`detection/identifiers`): Identify identifier types in data
- **Validation** (`validation/identifiers`): Enforce security policies
- **Sanitization** (`sanitization/identifiers`): Transform for safe use

### Key Statistics

| Metric | Count |
|--------|-------|
| **Identifier domains** | 13 (Network, Payment, Personal, Token, Government, Medical, etc.) |
| **Validation functions** | 150+ (strict and lenient variants) |
| **Detection patterns** | 100+ (high-confidence recognition) |
| **Sanitization strategies** | 50+ (PCI-DSS, HIPAA, GDPR compliant) |
| **Test coverage** | 300+ tests across all modules |
| **Lines of code** | ~15,000 LOC |

### Why Three Separate Modules?

Each module serves a distinct security purpose:

```rust
// Detection: "This LOOKS LIKE a credit card" (lenient, false positives OK)
if detect_credit_card(input) { /* found something that might be a card */ }

// Validation: "This IS a valid credit card" (strict, no false positives)
validate_credit_card(input)?; // Enforces Luhn checksum, length, etc.

// Sanitization: "Make this credit card SAFE for logging" (transformative)
let safe = mask_credit_card(input); // "424242******4242"
```

______________________________________________________________________

## Design Principles

### 1. Zero-Trust Security

**"Trust nothing, verify everything, validate at every boundary."**

Every identifier is untrusted regardless of source:

- No shortcuts for "safe-looking" patterns
- No assumptions about caller validation
- Validation at every layer (defense in depth)

**Real Example**: Tilde bypass vulnerability (CVE-INTERNAL-2025-001)

- **Vulnerable**: `if input.starts_with("~/") { return Ok(input); }` // Bypassed ALL validation!
- **Fixed**: Validate FIRST, then allow convenience patterns

### 2. Separation of Concerns

Each layer has a distinct philosophy:

| Layer | Purpose | Returns | Philosophy | Use Case |
|-------|---------|---------|------------|----------|
| **Detection** | Find potential threats | `bool` | Lenient (false positives acceptable) | Log scanning, data discovery |
| **Validation** | Enforce security policy | `Result<()>` | Strict (no false positives) | Input gates, API validation |
| **Sanitization** | Transform safely | `String` | Dual mode (reject or fix) | Logging, display, storage |

**Golden Rule**: Detection finds, validation enforces, sanitization fixes.

### 3. Builder + Shortcuts Pattern

All modules use consistent three-layer API for discoverability and flexibility:

```rust
// Layer 1: Domain modules (private implementation)
mod payment;    // Core logic
mod personal;
mod network;

// Layer 2: Builder (configurable, public)
pub struct IdentifierValidator { config }
impl IdentifierValidator {
    pub fn new() -> Self { /* ... */ }
    pub fn with_max_length(mut self, len: usize) -> Self { /* ... */ }
}

// Layer 3: Shortcuts (convenience, public)
pub mod shortcuts {
    pub fn validate_ssn(ssn: &str) -> Result<()> { /* ... */ }
}
```

### 4. Compliance First

All modules prioritize regulatory requirements:

- **PCI-DSS**: Credit card masking (show first 6 + last 4 only)
- **HIPAA**: Medical identifier redaction (PHI protection)
- **GDPR**: Personal data protection (Articles 4, 9)
- **BIPA**: Biometric data handling (Illinois law)
- **FERPA**: Student privacy protection

______________________________________________________________________

## Three-Layer Architecture

### Layer 1: Domain Modules (Implementation)

**Location**: `{module}/identifiers/{domain}.rs`

**Visibility**: `mod` (private) or `pub(super)` (module-only)

**Purpose**: Core business logic for specific identifier types

**Pattern**: Always provide both strict (`Result`) and lenient (`bool`) variants

```rust
// validation/identifiers/payment.rs
/// Validate credit card format (strict - returns Result)
pub(super) fn validate_credit_card_strict(card: &str) -> Result<(), Problem> {
    // Luhn checksum validation
    if !luhn::validate(digits_only) {
        return Err(Problem::validation("Invalid card number"));
    }
    Ok(())
}

/// Validate credit card format (lenient - returns bool)
pub(super) fn validate_credit_card(card: &str) -> bool {
    validate_credit_card_strict(card).is_ok()
}
```

**Naming Convention**:

- Strict functions: `validate_{identifier}_strict()` � `Result<(), Problem>`
- Lenient functions: `validate_{identifier}()` � `bool`
- Detection functions: `is_{identifier}()` � `bool`
- Sanitization functions: `mask_{identifier}()` or `redact_{identifier}()` � `String`

### Layer 2: Builder (Configuration)

**Location**: `{module}/identifiers/builder/mod.rs`

**Visibility**: `pub` (public API)

**Purpose**: Configuration and orchestration

**Golden Rule**: **Zero business logic in builders!** Only configuration and delegation.

```rust
pub struct IdentifierValidator {
    context: IdentifierContext,
    max_length: usize,
    check_injection: bool,
}

impl IdentifierValidator {
    pub fn new() -> Self { /* defaults */ }

    // Configuration methods
    pub fn with_max_length(mut self, length: usize) -> Self {
        self.max_length = length;
        self
    }

    // Delegation only (no business logic!)
    pub fn validate_credit_card(&self, card: &str) -> Result<(), Problem> {
        payment::validate_credit_card_strict(card) // Delegates to domain module
    }
}
```

**Why No Logic?**: Keeps builders testable, maintainable, and focused on API ergonomics.

### Layer 3: Shortcuts (Convenience)

**Location**:

- Cross-cutting: `{module}/identifiers/shortcuts.rs`
- Domain-specific: `{module}/identifiers/builder/shortcuts/{domain}_shortcuts.rs`

**Visibility**: `pub` (public API)

**Purpose**: Pre-configured helpers for common use cases

**Two Types**:

1. **Cross-cutting shortcuts** (presets, convenience functions):

```rust
// shortcuts.rs
pub fn standard() -> IdentifierValidator { /* ... */ }
pub fn paranoid() -> IdentifierValidator { /* ... */ }
pub fn validate_identifier(id: &str) -> Result<()> { /* ... */ }
```

1. **Domain shortcuts** (one-liner helpers):

```rust
// builder/shortcuts/payment_shortcuts.rs
pub fn validate_credit_card(card: &str) -> Result<()> {
    IdentifierValidator::new().validate_credit_card(card)
}
```

______________________________________________________________________

## Module Organization

### Directory Structure

```text
src/security/data/
�� common/identifiers/              # Shared primitives (DRY)
   �� mod.rs                       # Common validation functions
   �� patterns.rs                  # Regex patterns for text scanning
   �� luhn.rs                      # Luhn checksum (credit cards)
   �� masking.rs                   # Masking/redaction helpers (NEW!)

�� detection/identifiers/           # Find potential identifiers
   �� mod.rs                       # Module exports
   �� shortcuts.rs                 # Cross-cutting shortcuts
   �� types.rs                     # DetectionResult, Confidence
   �� builder/
      �� mod.rs                  # IdentifierDetector
      �� shortcuts/              # Domain helpers
   �� payment.rs                   # Credit card, bank account
   �� personal.rs                  # Email, phone, SSN
   �� token.rs                     # API keys, JWT, GitHub
   �� government.rs                # SSN, passport, driver license
   �� medical.rs                   # MRN, insurance, NPI
   �� biometric.rs                 # Fingerprint, facial, iris
   �� organizational.rs            # Employee, student, badge
   �� location.rs                  # GPS, addresses, postal codes
   �� network.rs                   # UUID, IP, MAC, URL

�� validation/identifiers/          # Enforce security policies
   �� mod.rs
   �� shortcuts.rs
   �� types.rs                     # ValidationResult, Level
   �� builder/
      �� mod.rs                  # IdentifierValidator
      �� shortcuts/
   �� payment.rs
   �� personal.rs
   �� token.rs
   �� government.rs
   �� medical.rs
   �� biometric.rs
   �� organizational.rs
   �� location.rs
   �� network.rs
   �� database.rs                  # SQL identifiers
   �� environment.rs               # Env vars
   �� generic.rs                   # Generic IDs
   �� metrics.rs                   # Metric names (pub(crate))

�� sanitization/identifiers/        # Transform for safe use
    �� mod.rs
    �� shortcuts.rs
    �� types.rs                     # SanitizationStrategy
    �� builder/
       �� mod.rs                  # IdentifierSanitizer
       �� shortcuts/
    �� payment.rs
    �� personal.rs
    �� token.rs
    �� government.rs
    �� medical.rs
    �� biometric.rs
    �� organizational.rs
    �� location.rs
    �� network.rs
```

### Visibility Strategy

Carefully controlled visibility prevents API sprawl and maintains encapsulation:

```rust
// Domain modules: private implementation
mod payment;              // Private (not accessible outside module)
pub(super) mod government; // Module-visible (accessible to parent)

// Public API surface
pub mod builder;          // Public (builder pattern)
pub mod shortcuts;        // Public (convenience functions)

// Selective re-exports
pub use builder::IdentifierValidator;
pub use shortcuts::{validate_credit_card, validate_ssn};

// Internal-only (for observe module)
pub(crate) use builder::shortcuts::metrics::validate_metric_name;
```

______________________________________________________________________

## Security Taxonomy

### 13 Identifier Domains

| Domain | Examples | Security Risk | Compliance |
|--------|----------|---------------|------------|
| **Network** | UUID, MAC, IP, URL | Spoofing, enumeration | OWASP |
| **Payment** | Credit cards, bank accounts | Financial fraud | **PCI-DSS** |
| **Personal** | Email, phone, username | PII exposure | **GDPR, CCPA** |
| **Token** | GitHub tokens, AWS keys, JWT | Secret leakage | OWASP |
| **Government** | SSN, passport, driver license, VIN | Identity theft | **HIPAA** |
| **Medical** | MRN, insurance, prescriptions, NPI | PHI exposure | **HIPAA** |
| **Organizational** | Employee ID, student ID, badge | Unauthorized access | **FERPA** |
| **Location** | GPS coordinates, addresses | Stalking, privacy | **GDPR Art 4** |
| **Biometric** | Fingerprint, facial, iris, voice | Permanent compromise | **GDPR Art 9, BIPA** |
| **Database** | Table, column, schema names | SQL injection | OWASP |
| **Environment** | Environment variables | Command injection | OWASP |
| **Generic** | Variable names, API keys | Injection attacks | OWASP |
| **Metrics** | Metric names, label keys | Cardinality DoS | Internal |

______________________________________________________________________

## Common Patterns

### Pattern 1: Strict/Lenient Pairs

Every validation provides two variants for different use cases:

```rust
// Strict: Returns detailed error for user feedback
pub(super) fn validate_ssn_strict(ssn: &str) -> Result<(), Problem> {
    if !SSN_PATTERN.is_match(ssn) {
        return Err(Problem::validation("Invalid SSN format: must be XXX-XX-XXXX"));
    }
    // ... additional checks
    Ok(())
}

// Lenient: Returns simple bool for filtering
pub(super) fn validate_ssn(ssn: &str) -> bool {
    validate_ssn_strict(ssn).is_ok()
}
```

**When to use**:

- **Strict**: User-facing errors, audit trails, API responses, critical validation
- **Lenient**: Quick checks, filters, boolean conditions, bulk processing

### Pattern 2: Detection Confidence Levels

Detection handles ambiguity with confidence levels:

```rust
pub enum DetectionConfidence {
    High,    // 95%+ certain (e.g., passed Luhn checksum)
    Medium,  // 70-95% certain (e.g., matches pattern but no checksum)
    Low,     // 50-70% certain (e.g., partial match, might be truncated)
}

pub struct DetectionResult {
    pub identifier_type: IdentifierType,
    pub confidence: DetectionConfidence,
    pub value: String,
}
```

**Use case**: Log scanning where you want to flag potential matches for human review.

### Pattern 3: Sanitization Strategies

Flexible masking based on security requirements:

```rust
pub enum SanitizationStrategy {
    Redact,              // Total: "***-**-****" (safest, logs)
    Mask,                // Partial: "424242******4242" (PCI-DSS)
    ShowFirst(usize),    // First N: "12345****" (routing numbers)
    ShowLast(usize),     // Last N: "*****6789" (SSN customer service)
}
```

**Compliance mapping**:

- **PCI-DSS**: `Mask` (show first 6 + last 4 of credit cards)
- **HIPAA**: `Redact` (total masking of PHI in logs)
- **Customer Service**: `ShowLast(4)` (verify without exposing full value)

### Pattern 4: Common Primitives (DRY)

Shared helpers in `common/identifiers/` eliminate duplication:

```rust
// From common/identifiers/mod.rs
pub fn starts_with_valid_char(s: &str) -> bool { /* ... */ }
pub fn contains_injection_pattern(s: &str) -> bool { /* ... */ }

// From common/identifiers/luhn.rs (NEW - eliminated 40 lines duplication)
pub(in crate::security::data) fn validate(number: &str) -> bool { /* ... */ }

// From common/identifiers/masking.rs (NEW - eliminated ~150 lines duplication)
pub(in crate::security::data) fn show_first_and_last(
    value: &str, first: usize, last: usize, mask_char: char
) -> String { /* ... */ }

pub(in crate::security::data) fn mask_digits_preserve_format(
    value: &str, show_last: usize, mask_char: char
) -> String { /* ... */ }
```

**Impact**: Extracted 2 common modules, eliminated ~200 lines of duplication.

______________________________________________________________________

## Design Decisions

### Decision 1: Why Separate Detection/Validation/Sanitization?

**Question**: Why not one unified module?

**Answer**: Different philosophies and use cases.

| Aspect | Detection | Validation | Sanitization |
|--------|-----------|------------|--------------|
| **False positives** | Acceptable | **NOT** acceptable | N/A |
| **Use case** | Scanning, discovery | Security gates | Logging, display |
| **Returns** | `bool` + confidence | `Result<(), Problem>` | `String` |
| **Philosophy** | "Might be X" | "IS valid X" | "Make X safe" |

**Example**:

```rust
// Detection: Scans logs for potential credit cards (false positives OK)
for line in log_file {
    if detect_credit_card(line) {
        alert_security_team(line); // Better safe than sorry
    }
}

// Validation: API input gate (NO false positives allowed)
fn charge_card(card_number: &str) -> Result<()> {
    validate_credit_card(card_number)?; // Must be valid or reject
    // ...
}

// Sanitization: Safe logging
error!("Payment failed for card: {}", mask_credit_card(card_number));
```

### Decision 2: Why Builder Pattern?

**Question**: Why not just simple functions?

**Answer**: Prevents function explosion while maintaining configurability.

**Without Builder** (combinatorial explosion):

```rust
validate_ssn(ssn)?;
validate_ssn_strict(ssn)?;
validate_ssn_with_length(ssn, 9)?;
validate_ssn_with_injection_check(ssn, true)?;
validate_ssn_with_length_and_injection(ssn, 9, true)?;
validate_ssn_with_length_injection_and_sanitize(ssn, 9, true, true)?;
// 2^N combinations! (N = number of options)
```

**With Builder** (composable):

```rust
IdentifierValidator::new()
    .with_max_length(9)
    .with_injection_check(true)
    .with_auto_sanitize(true)
    .validate_ssn(ssn)?;
```

### Decision 3: Why Shortcuts Module?

**Question**: Why not export functions directly from domain modules?

**Answer**: Consistency, discoverability, and versioning.

**Benefits**:

- **Consistent API**: All modules use same pattern (easy to learn)
- **Discoverability**: All shortcuts in one predictable place
- **Versioning**: Can evolve shortcuts without breaking domain modules
- **Presets**: Can provide pre-configured validators (`standard()`, `paranoid()`)

### Decision 4: Why Common Module?

**Question**: Why extract helpers instead of duplicating?

**Answer**: DRY principle and single source of truth.

**Before** (duplication):

```rust
// In payment.rs
let digits: String = card.chars().filter(|c| c.is_ascii_digit()).collect();

// In personal.rs
let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();

// In government.rs
let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();

// ... 8 more times across different files
```

**After** (common module):

```rust
// In common/identifiers/masking.rs
pub fn digits_only(value: &str) -> String {
    value.chars().filter(|c| c.is_ascii_digit()).collect()
}

// Everywhere else
let digits = masking::digits_only(value);
```

**Impact**: ~200 lines eliminated, single source of truth, consistent behavior.

### Decision 5: Why pub(crate) for Metrics?

**Question**: Why is metrics validation internal while others are public?

**Answer**: Metrics are infrastructure, not user-facing features.

**Rationale**:

- Metrics are used by the `observe` module internally
- Users don't validate metric names (that's the library's job)
- Prevents misuse of internal APIs
- Reduces public API surface (easier to maintain)

```rust
// Public (user-facing identifiers)
pub mod payment;
pub mod personal;
pub mod government;

// Internal-only (infrastructure)
pub(crate) mod metrics; // Only visible to crate::observe
```

______________________________________________________________________

## Extension Guide

### Adding a New Identifier Domain

Example: Adding cryptocurrency address validation

#### Step 1: Create Domain Module

**File**: `validation/identifiers/crypto.rs`

```rust
use crate::observe::Problem;
use crate::security::data::common::identifiers;

/// Validate Bitcoin address (strict)
pub(super) fn validate_bitcoin_address_strict(addr: &str) -> Result<(), Problem> {
    // Length check
    if addr.len() < 26 || addr.len() > 35 {
        return Err(Problem::validation("Invalid Bitcoin address length"));
    }

    // Prefix check
    if !addr.starts_with('1') && !addr.starts_with('3') && !addr.starts_with("bc1") {
        return Err(Problem::validation("Invalid Bitcoin address prefix"));
    }

    // Character set validation
    if !addr.chars().all(|c| c.is_alphanumeric()) {
        return Err(Problem::validation("Invalid characters in Bitcoin address"));
    }

    // TODO: Add Base58Check checksum validation

    Ok(())
}

/// Validate Bitcoin address (lenient)
pub(super) fn validate_bitcoin_address(addr: &str) -> bool {
    validate_bitcoin_address_strict(addr).is_ok()
}

/// Validate Ethereum address (strict)
pub(super) fn validate_ethereum_address_strict(addr: &str) -> Result<(), Problem> {
    // Must be 42 chars: "0x" + 40 hex digits
    if addr.len() != 42 {
        return Err(Problem::validation("Ethereum address must be 42 characters"));
    }

    if !addr.starts_with("0x") {
        return Err(Problem::validation("Ethereum address must start with 0x"));
    }

    if !addr[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Problem::validation("Invalid hex digits in Ethereum address"));
    }

    // TODO: Add EIP-55 checksum validation

    Ok(())
}

pub(super) fn validate_ethereum_address(addr: &str) -> bool {
    validate_ethereum_address_strict(addr).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_valid() {
        // Example addresses
        assert!(validate_bitcoin_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(validate_bitcoin_address("3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy"));
    }

    #[test]
    fn test_bitcoin_invalid() {
        assert!(!validate_bitcoin_address("invalid"));
        assert!(!validate_bitcoin_address(""));
        assert!(!validate_bitcoin_address("xyz123"));
    }

    #[test]
    fn test_ethereum_valid() {
        assert!(validate_ethereum_address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"));
    }

    #[test]
    fn test_ethereum_invalid() {
        assert!(!validate_ethereum_address("742d35Cc6634C0532925a3b844Bc9e7595f0bEb")); // No 0x
        assert!(!validate_ethereum_address("0x123")); // Too short
    }
}
```

#### Step 2: Add Builder Methods

**File**: `validation/identifiers/builder/crypto.rs`

```rust
use super::IdentifierValidator;
use crate::observe::Problem;
use crate::security::data::validation::identifiers::crypto;

impl IdentifierValidator {
    /// Configure for cryptocurrency validation
    pub fn for_crypto(mut self) -> Self {
        self.context = IdentifierContext::Generic;
        self
    }

    /// Validate Bitcoin address (strict)
    pub fn validate_bitcoin(&self, addr: &str) -> Result<(), Problem> {
        crypto::validate_bitcoin_address_strict(addr)
    }

    /// Check if Bitcoin address is valid (lenient)
    pub fn is_valid_bitcoin(&self, addr: &str) -> bool {
        crypto::validate_bitcoin_address(addr)
    }

    /// Validate Ethereum address (strict)
    pub fn validate_ethereum(&self, addr: &str) -> Result<(), Problem> {
        crypto::validate_ethereum_address_strict(addr)
    }

    /// Check if Ethereum address is valid (lenient)
    pub fn is_valid_ethereum(&self, addr: &str) -> bool {
        crypto::validate_ethereum_address(addr)
    }
}
```

#### Step 3: Create Shortcuts

**File**: `validation/identifiers/builder/shortcuts/crypto_shortcuts.rs`

```rust
use super::super::IdentifierValidator;
use crate::observe::Problem;

/// Create a crypto validator
pub fn crypto_validator() -> IdentifierValidator {
    IdentifierValidator::new().for_crypto()
}

/// Validate Bitcoin address (strict)
pub fn validate_bitcoin(addr: &str) -> Result<(), Problem> {
    crypto_validator().validate_bitcoin(addr)
}

/// Check if Bitcoin address is valid (lenient)
pub fn is_valid_bitcoin(addr: &str) -> bool {
    crypto_validator().is_valid_bitcoin(addr)
}

/// Validate Ethereum address (strict)
pub fn validate_ethereum(addr: &str) -> Result<(), Problem> {
    crypto_validator().validate_ethereum(addr)
}

/// Check if Ethereum address is valid (lenient)
pub fn is_valid_ethereum(addr: &str) -> bool {
    crypto_validator().is_valid_ethereum(addr)
}
```

#### Step 4: Update Module Exports

**File**: `validation/identifiers/builder/mod.rs`

```rust
// Add to implementation module imports
mod crypto;

// Add to shortcut module imports
mod crypto_shortcuts;

// Add to shortcuts re-exports
pub mod shortcuts {
    // ... existing shortcuts ...

    // Cryptocurrency shortcuts
    pub mod crypto {
        pub use super::super::crypto_shortcuts::{
            crypto_validator,
            validate_bitcoin,
            is_valid_bitcoin,
            validate_ethereum,
            is_valid_ethereum,
        };
    }
}
```

**File**: `validation/identifiers/mod.rs`

```rust
// Add to internal implementation modules
mod crypto; // Cryptocurrency address validation
```

#### Step 5: Add to Main Shortcuts (Optional)

If you want top-level convenience functions:

**File**: `validation/identifiers/shortcuts.rs`

```rust
// Re-export crypto shortcuts
pub use super::builder::shortcuts::crypto::{
    validate_bitcoin as validate_bitcoin_address,
    is_valid_bitcoin as is_valid_bitcoin_address,
};
```

______________________________________________________________________

## Quality Metrics

### Current State (v0.1.0 - November 2025)

| Module | Score | Status |
|--------|-------|--------|
| **detection/identifiers** | 89/100 |  B+ |
| **validation/identifiers** | 96/100 |  A |
| **sanitization/identifiers** | 94/100 |  A |

### Recent Improvements

**Quality Scorecard Issues Resolved** (All 5):

1.  **Issue #1**: Complete Validation Coverage (+10 points)

   - Added 5 new validation modules: government, organizational, location, medical, biometric
   - 98 new tests added
   - ~2,400 lines of validation logic

1.  **Issue #2**: Extract Luhn Algorithm (+5 points)

   - Created `common/identifiers/luhn.rs`
   - Eliminated 40 lines of duplication
   - Shared between detection and validation

1.  **Issue #3**: Standardize Shortcut Organization (+3 points)

   - Added `shortcuts.rs` to detection and sanitization
   - Consistent pattern across all three modules
   - ~250 lines of organized shortcuts

1.  **Issue #4**: Extract Masking Strategy Helpers (+3 points)

   - Created `common/identifiers/masking.rs` (460 lines, 17 tests)
   - Refactored payment.rs (-31 lines), personal.rs (-11 lines), government.rs (-16 lines)
   - Total ~60 lines eliminated from sanitization modules
   - Functions: `digits_only()`, `show_first_n()`, `show_last_n()`, `show_first_and_last()`, `mask_digits_preserve_format()`

1.  **Issue #5**: Create Architecture Documentation (+3 points)

   - This document!
   - Cross-cutting design decisions
   - Extension guides and examples

**Total Impact**: +24 points, ~2,600 lines of new functionality, ~260 lines of duplication eliminated

### Code Quality Standards

All identifier modules maintain:

-  Comprehensive test coverage (>80%)
-  Strict/lenient function pairs
-  OWASP compliance (injection detection)
-  Regulatory compliance docs (PCI, HIPAA, GDPR)
-  Builder pattern purity (zero business logic)
-  Clear separation of concerns

______________________________________________________________________

## References

### Compliance Standards

- **PCI-DSS v4.0**: Payment Card Industry Data Security Standard

  - Requirement 3.3: Mask PAN when displayed (show first 6 + last 4 max)

- **HIPAA Privacy Rule**: 45 CFR Part 160 and Subparts A and E of Part 164

  - Protected Health Information (PHI) includes medical record numbers

- **GDPR**: Regulation (EU) 2016/679

  - Article 4: Location data is personal data
  - Article 9: Biometric data is "special category" data

- **CCPA**: California Consumer Privacy Act of 2018

  - Precise geolocation is sensitive personal information

- **BIPA**: 740 ILCS 14 (Illinois Biometric Information Privacy Act)

  - Biometric identifiers require written consent

### OWASP Guidelines

- OWASP Top 10 2021: A03:2021 - Injection
- OWASP Input Validation Cheat Sheet
- OWASP Testing Guide v4.2: Input Validation Testing

### Internal Documentation

- `src/refactor-plan.md`: Module refactoring roadmap
- `src/security/data/MODULE_QUALITY_SCORECARD.md`: Quality metrics framework
- `CLAUDE.md`: Zero-trust security philosophy
- `docs/security/patterns/detection-validation-sanitization.md`: Layer separation philosophy

______________________________________________________________________

*Last Updated: 2025-11-13*
*Version: 1.0.0*
*Maintainer: Security Team*
