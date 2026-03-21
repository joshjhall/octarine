//! Builder pattern for location identifier operations
//!
//! Provides a clean interface to detection, validation, and sanitization
//! functions for location identifiers.
//!
//! ## Design Philosophy
//!
//! - **No business logic**: Builder is purely an interface
//! - **Delegates to modules**: All work done by detection, validation, etc.
//! - **Consistent API**: Same pattern across all identifier domains
//!
//! ## Module Structure
//!
//! - `detection` - Detection method implementations
//! - `validation` - Validation and cache method implementations
//! - `sanitization` - Sanitization method implementations
//! - `conversion` - Conversion and normalization method implementations

mod conversion;
mod detection;
mod sanitization;
mod validation;

use super::conversion as conversion_mod;
use super::redaction;

// Re-export redaction strategies for convenience
pub use redaction::{
    AddressRedactionStrategy, GpsRedactionStrategy, PostalCodeRedactionStrategy,
    TextRedactionPolicy,
};

// Re-export conversion types for convenience
pub use conversion_mod::{GpsFormat, PostalCodeNormalization, PostalCodeType};

/// Builder for location identifier operations
///
/// Provides access to detection, validation, and sanitization functions
/// for location identifiers (GPS coordinates, addresses, postal codes).
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::LocationIdentifierBuilder;
///
/// let builder = LocationIdentifierBuilder::new();
///
/// // Detection
/// assert!(builder.is_gps_coordinate("40.7128, -74.0060"));
///
/// // Validation
/// if builder.validate_postal_code("10001") {
///     println!("Valid postal code");
/// }
///
/// // Sanitization
/// let safe = builder.redact_gps_coordinate("40.7128, -74.0060");
/// assert_eq!(safe, "[GPS_COORDINATE]");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct LocationIdentifierBuilder;

impl LocationIdentifierBuilder {
    /// Create a new LocationIdentifierBuilder
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = LocationIdentifierBuilder::new();
        assert!(builder.is_gps_coordinate("40.7128, -74.0060"));
    }
}
