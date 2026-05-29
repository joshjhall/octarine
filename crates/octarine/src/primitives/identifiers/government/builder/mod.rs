//! Government identifier builder (primitives layer)
//!
//! Provides a unified API for government identifier operations.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! The builder routes to detection, validation, sanitization, and conversion modules.
//!
//! # Module Structure
//!
//! `GovernmentIdentifierBuilder`'s methods are split across per-country/domain
//! submodules that mirror the underlying primitive layout in sibling
//! `detection/`, `validation/`, and `sanitization/` directories. Each submodule
//! contains one `impl GovernmentIdentifierBuilder` block holding that
//! country/domain's methods. The struct itself and its constructor stay in
//! this `mod.rs`.
//!
//! # Usage
//!
//! ```ignore
//! use crate::primitives::identifiers::IdentifierBuilder;
//!
//! let builder = IdentifierBuilder::new();
//! let gov = builder.government();
//!
//! // Detection
//! let is_ssn = gov.is_ssn("517-29-8346");
//! let matches = gov.find_ssns_in_text("SSN: 517-29-8346");
//!
//! // Validation
//! let valid = gov.validate_ssn("517-29-8346");
//!
//! // Sanitization (with explicit strategy)
//! let redacted = gov.redact_ssn_with_strategy("517-29-8346", SsnRedactionStrategy::Token);
//!
//! // Conversion
//! let normalized = gov.normalize_ssn("900 00 0001");
//! ```

use super::super::types::IdentifierMatch;
use crate::primitives::Problem;
use crate::primitives::collections::CacheStats;

use super::common;
use super::conversion;
use super::detection;
use super::redaction::TextRedactionPolicy;
use super::sanitization::{
    self, DriverLicenseRedactionStrategy, NationalIdRedactionStrategy, PassportRedactionStrategy,
    SsnRedactionStrategy, TaxIdRedactionStrategy, VehicleIdRedactionStrategy,
};
use super::validation;

mod aggregate;
mod australia;
mod brazil;
mod cache;
mod driver_license;
mod europe;
mod india;
mod korea;
mod mexico;
mod national_id;
mod nigeria;
mod passport;
mod singapore;
mod ssn;
mod tax_id;
mod test_patterns;
mod thailand;
mod turkey;
mod uk;
mod vehicle_id;

/// Builder for government identifier operations
///
/// Provides a unified interface to all government identifier functionality:
/// - SSN detection, validation, and sanitization
/// - Tax ID (EIN, ITIN) operations
/// - Driver's license operations
/// - Passport operations
/// - National ID operations
/// - VIN operations
#[derive(Debug, Clone, Copy)]
pub struct GovernmentIdentifierBuilder;

impl Default for GovernmentIdentifierBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernmentIdentifierBuilder {
    /// Create a new government identifier builder
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}
