//! Driver's license validation by jurisdiction
//!
//! This module provides extensible validation for driver's licenses across
//! multiple countries and regions. Each jurisdiction can have:
//! - Format validation (pattern matching)
//! - Checksum validation (where applicable)
//!
//! # Architecture
//!
//! Validators are organized by region:
//! - `north_america`: US states, Canadian provinces, Mexico
//! - `europe`: EU countries, UK (future)
//! - `asia`: Asian countries (future)
//! - `oceania`: Australia, New Zealand (future)
//!
//! # Usage
//!
//! ```ignore
//! use crate::primitives::identifiers::government::licenses;
//!
//! // Validate a California license
//! let result = licenses::validate_license("A1234567", "US-CA");
//! assert!(result.format_valid);
//! assert!(result.checksum_valid.unwrap_or(true));
//!
//! // Get all supported jurisdictions
//! let jurisdictions = licenses::supported_jurisdictions();
//! ```
//!
//! # Adding New Jurisdictions
//!
//! 1. Implement `LicenseValidator` trait for the jurisdiction
//! 2. Add to the appropriate regional module (e.g., `north_america.rs`)
//! 3. Register in `VALIDATORS` static

pub mod north_america;

use once_cell::sync::Lazy;
use std::collections::HashMap;

// ============================================================================
// Types
// ============================================================================

/// Result of license validation
#[derive(Debug, Clone, PartialEq)]
pub struct LicenseValidationResult {
    /// Whether the format matches the jurisdiction's pattern
    pub format_valid: bool,
    /// Whether the checksum is valid (None if jurisdiction has no checksum)
    pub checksum_valid: Option<bool>,
    /// The jurisdiction code (e.g., "US-CA", "CA-ON")
    pub jurisdiction: String,
    /// Human-readable jurisdiction name
    pub jurisdiction_name: String,
}

impl LicenseValidationResult {
    /// Check if the license is fully valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.format_valid && self.checksum_valid.unwrap_or(true)
    }
}

/// Trait for jurisdiction-specific license validators
pub trait LicenseValidator: Send + Sync {
    /// Jurisdiction code (e.g., "US-CA", "CA-ON", "UK")
    fn jurisdiction_code(&self) -> &'static str;

    /// Human-readable jurisdiction name
    fn jurisdiction_name(&self) -> &'static str;

    /// Check if the license format is valid (pattern matching)
    fn is_format_valid(&self, license: &str) -> bool;

    /// Check if the checksum is valid (if the jurisdiction has one)
    /// Returns None if the jurisdiction doesn't use checksums
    fn is_checksum_valid(&self, license: &str) -> Option<bool>;

    /// Brief description of the license format
    fn format_description(&self) -> &'static str;
}

// ============================================================================
// Validator Registry
// ============================================================================

/// Registry of all license validators by jurisdiction code
static VALIDATORS: Lazy<HashMap<&'static str, Box<dyn LicenseValidator>>> = Lazy::new(|| {
    let mut map: HashMap<&'static str, Box<dyn LicenseValidator>> = HashMap::new();

    // Register North American validators
    for validator in north_america::validators() {
        map.insert(validator.jurisdiction_code(), validator);
    }

    // Future: Register European validators
    // for validator in europe::validators() {
    //     map.insert(validator.jurisdiction_code(), validator);
    // }

    map
});

// ============================================================================
// Public API
// ============================================================================

/// Validate a driver's license for a specific jurisdiction
///
/// # Arguments
///
/// * `license` - The license number to validate
/// * `jurisdiction` - Jurisdiction code (e.g., "US-CA", "US-NE", "CA-ON")
///
/// # Returns
///
/// `Some(LicenseValidationResult)` if jurisdiction is supported, `None` otherwise
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::licenses;
///
/// // California license
/// let result = licenses::validate_license("A1234567", "US-CA").unwrap();
/// assert!(result.format_valid);
///
/// // Unknown jurisdiction
/// assert!(licenses::validate_license("12345", "XX-YY").is_none());
/// ```
#[must_use]
pub fn validate_license(license: &str, jurisdiction: &str) -> Option<LicenseValidationResult> {
    let validator = VALIDATORS.get(jurisdiction)?;

    let format_valid = validator.is_format_valid(license);
    let checksum_valid = if format_valid {
        validator.is_checksum_valid(license)
    } else {
        // Don't bother with checksum if format is invalid
        None
    };

    Some(LicenseValidationResult {
        format_valid,
        checksum_valid,
        jurisdiction: validator.jurisdiction_code().to_string(),
        jurisdiction_name: validator.jurisdiction_name().to_string(),
    })
}

/// Check if a jurisdiction is supported
#[must_use]
pub fn is_jurisdiction_supported(jurisdiction: &str) -> bool {
    VALIDATORS.contains_key(jurisdiction)
}

/// Get all supported jurisdiction codes
#[must_use]
pub fn supported_jurisdictions() -> Vec<&'static str> {
    VALIDATORS.keys().copied().collect()
}

/// Get information about a jurisdiction's license format
#[must_use]
pub fn jurisdiction_info(jurisdiction: &str) -> Option<(&'static str, &'static str)> {
    VALIDATORS
        .get(jurisdiction)
        .map(|v| (v.jurisdiction_name(), v.format_description()))
}

/// Validate a license and return just a boolean (convenience function)
///
/// Returns `false` if jurisdiction is not supported or license is invalid.
#[must_use]
pub fn is_valid_license(license: &str, jurisdiction: &str) -> bool {
    validate_license(license, jurisdiction)
        .map(|r| r.is_valid())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_supported_jurisdictions() {
        let jurisdictions = supported_jurisdictions();
        assert!(!jurisdictions.is_empty());
        assert!(jurisdictions.contains(&"US-CA"));
        assert!(jurisdictions.contains(&"US-NE"));
    }

    #[test]
    fn test_is_jurisdiction_supported() {
        assert!(is_jurisdiction_supported("US-CA"));
        assert!(is_jurisdiction_supported("US-NE"));
        assert!(!is_jurisdiction_supported("XX-YY"));
    }

    #[test]
    fn test_unsupported_jurisdiction() {
        assert!(validate_license("12345", "XX-YY").is_none());
    }

    #[test]
    fn test_jurisdiction_info() {
        let (name, desc) = jurisdiction_info("US-CA").expect("CA should be supported");
        assert_eq!(name, "California");
        assert!(desc.contains("letter"));
    }
}
