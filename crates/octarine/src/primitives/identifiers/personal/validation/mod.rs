//! Personal identifier validation primitives
//!
//! Pure validation functions for personal identifiers (emails, phones, etc.)
//! with ZERO rust-core dependencies beyond the Problem type.
//!
//! ## Design Principles
//!
//! 1. **No Logging**: Pure functions, no trace/debug calls
//! 2. **No Side Effects**: Only validation logic
//! 3. **Returns Result**: Strict mode returns Result, lenient returns bool
//! 4. **Reusable**: Used by observe/pii and security modules
//!
//! ## Compliance Considerations
//!
//! Personal identifiers validated by this module are protected under:
//!
//! - **GDPR** (EU): Personal data requiring lawful basis for processing
//!   - Email addresses: Article 4(1) - personal data
//!   - Phone numbers: Article 4(1) - personal data
//!   - Birthdates: Article 9 - special category (when revealing age)
//!
//! - **CCPA** (California): Personal information subject to consumer rights
//!   - All identifiers in this module qualify as personal information
//!   - Must disclose collection and allow opt-out of sale
//!
//! - **HIPAA** (US Healthcare): When combined with health information
//!   - Birthdates are PHI identifiers
//!   - Phone/email are PHI when linked to health records
//!
//! ## Security Notes
//!
//! - Validation does not sanitize - use sanitization module for that
//! - Valid format does not mean deliverable (email) or reachable (phone)
//! - Always validate before storing or transmitting PII
//!
//! ## Module Organization
//!
//! - [`phone`] - Phone number validation
//! - [`email`] - Email address validation
//! - [`username`] - Username validation
//! - [`birthdate`] - Birthdate validation and test pattern detection
//! - [`name`] - Personal name validation

mod birthdate;
mod email;
mod name;
mod phone;
mod username;

// ============================================================================
// Re-exports - Phone
// ============================================================================

pub use phone::{find_phone_region, validate_phone};

// ============================================================================
// Re-exports - Email
// ============================================================================

pub use email::validate_email;

// ============================================================================
// Re-exports - Username
// ============================================================================

pub use username::validate_username;

// ============================================================================
// Re-exports - Birthdate
// ============================================================================

pub use birthdate::{is_test_birthdate, validate_birthdate};

// ============================================================================
// Re-exports - Name
// ============================================================================

pub use name::validate_name;
