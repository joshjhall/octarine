//! Government-issued identifier sanitization (primitives layer)
//!
//! Pure sanitization functions for government identifiers with no observe dependencies.
//! Used by observe/pii and security modules.
//!
//! # Supported Identifiers
//!
//! - **SSN**: US Social Security Numbers
//! - **Tax IDs**: EIN, TIN, ITIN (IRS)
//! - **Driver's License**: State DMV
//! - **Passport**: Federal/State Department
//! - **National IDs**: UK NI, Canadian SIN, etc.
//! - **VIN**: Vehicle Identification Numbers
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns data, no side effects
//! - Used by observe/pii and security modules
//!
//! # Redaction Strategies
//!
//! All redaction functions require explicit strategies:
//! - **Token**: Replace with type tag (e.g., `[SSN]`)
//! - **Mask**: Replace digits/chars with asterisks
//! - **Partial**: Show first or last N chars
//! - **Anonymous**: Replace with generic `[Redacted]`
//! - **Skip**: No redaction (pass-through)
//!
//! ## Module Organization
//!
//! - [`strategy`] - Strategy enums for all identifier types
//! - [`ssn`] - SSN-specific redaction functions
//! - [`redaction`] - Strategy-based redaction for other IDs
//! - [`text`] - Text scanning and redaction functions
//! - [`strict`] - Strict sanitization (normalize + validate)

mod redaction;
mod ssn;
mod strategy;
mod strict;
mod text;

// ============================================================================
// Re-exports - Strategies
// ============================================================================

pub use strategy::{
    DriverLicenseRedactionStrategy, NationalIdRedactionStrategy, PassportRedactionStrategy,
    SsnRedactionStrategy, TaxIdRedactionStrategy, VehicleIdRedactionStrategy,
};

// ============================================================================
// Re-exports - Individual Redaction (with strategy)
// ============================================================================

pub use redaction::{
    redact_driver_license_with_strategy, redact_national_id_with_strategy,
    redact_passport_with_strategy, redact_tax_id_with_strategy, redact_vehicle_id_with_strategy,
};

pub use ssn::redact_ssn_with_strategy;

// ============================================================================
// Re-exports - Text Redaction (with strategy/policy)
// ============================================================================

pub use text::{
    redact_all_government_ids_in_text_with_policy, redact_driver_licenses_in_text_with_strategy,
    redact_national_ids_in_text_with_strategy, redact_passports_in_text_with_strategy,
    redact_ssns_in_text_with_strategy, redact_tax_ids_in_text_with_strategy,
    redact_vehicle_ids_in_text_with_strategy,
};

// ============================================================================
// Re-exports - Strict Sanitization
// ============================================================================

pub use strict::{
    sanitize_driver_license_strict, sanitize_ein_strict, sanitize_ssn_strict, sanitize_vin_strict,
};
