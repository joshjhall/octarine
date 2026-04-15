//! Location and geographic identifier detection, validation, and sanitization
//!
//! This module provides pure functions for location-based identifiers:
//! - **Detection**: Find GPS coordinates, addresses, postal codes in text
//! - **Validation**: Verify format and validity of location identifiers
//! - **Sanitization**: Redact and mask location data for privacy
//!
//! ## Identifiers Covered
//!
//! | Identifier | Examples | Privacy Risk |
//! |------------|----------|--------------|
//! | GPS Coordinates | 40.7128,-74.0060, 40°42'46"N 74°00'21"W | Critical - Exact location |
//! | Street Addresses | 123 Main Street, P.O. Box 12345 | High - Personal residence |
//! | Postal Codes | 10001, SW1A 1AA, K1A 0B1 | Moderate - Demographic info |
//!
//! ## Compliance Coverage
//!
//! Location data is protected under various regulations:
//!
//! | Identifier | GDPR | CCPA | COPPA | HIPAA |
//! |------------|------|------|-------|-------|
//! | GPS Coordinates | Art. 4(1) - Personal data | Sensitive PI | Geolocation prohibited | PHI when linked |
//! | Street Addresses | Art. 4(1) - Personal data | Personal information | Requires consent | PHI identifier |
//! | Postal Codes | Art. 4(1) when linkable | Personal information | May be directory info | PHI (< ZIP3) |
//!
//! ## Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns data, no side effects
//! - Used by observe/pii and security modules
//!
//! ## Privacy Regulations
//!
//! - **GDPR Article 4**: Location data is personal data requiring protection
//! - **CCPA 1798.140**: Geolocation data requires opt-in consent
//! - **COPPA**: Cannot collect precise geolocation from children without consent
//! - **HIPAA**: ZIP codes beyond first 3 digits are PHI
//!
//! ## Usage
//!
//! Access functionality through the builder:
//!
//! ```rust,ignore
//! use octarine::primitives::identifiers::location::LocationIdentifierBuilder;
//!
//! let builder = LocationIdentifierBuilder::new();
//!
//! // Detection
//! assert!(builder.is_gps_coordinate("40.7128, -74.0060"));
//! assert!(builder.is_postal_code("10001"));
//! let locations = builder.find_all_in_text("Meet at 123 Main St, ZIP: 10001");
//!
//! // Validation (dual API)
//! assert!(builder.validate_gps_coordinate("40.7128, -74.0060"));  // Lenient (bool)
//! assert!(builder.validate_gps_coordinate_strict("40.7128, -74.0060").is_ok());  // Strict (Result)
//!
//! // Sanitization
//! assert_eq!(builder.redact_gps_coordinate("40.7128, -74.0060"), "[GPS_COORDINATE]");
//! assert_eq!(builder.redact_postal_code_partial("10001"), "100XX");  // State-level
//!
//! // Text redaction with precision levels
//! use octarine::primitives::identifiers::location::LocationPrecision;
//!
//! let text = "123 Main St, New York, NY 10001 (40.7128, -74.0060)";
//! let safe = builder.redact_with_precision(text, LocationPrecision::State);
//! assert!(safe.contains("100XX"));  // State-level ZIP preserved
//! ```
//!
//! # Performance Characteristics
//!
//! ## Computational Complexity
//!
//! | Operation | Time | Space | Notes |
//! |-----------|------|-------|-------|
//! | `is_gps_coordinate` | O(n) | O(1) | Multiple regex matches |
//! | `is_street_address` | O(n) | O(1) | Multiple regex matches |
//! | `is_postal_code` | O(n) | O(1) | Multiple regex matches |
//! | `find_gps_coordinates_in_text` | O(n) | O(m) | n = text length, m = matches |
//! | `validate_gps_coordinate_strict` | O(1) | O(1) | Parse + range check |
//! | `redact_postal_codes_in_text` | O(n) | O(n) | Cow optimization for clean text |
//! | `redact_with_precision` | O(n) | O(n) | Multiple regex replacements |
//!
//! ## Memory Usage
//!
//! - **Regex patterns**: ~8KB lazily initialized (shared across calls)
//! - **Per-call overhead**: Minimal, typically < 1KB for single identifiers
//! - **Text scanning**: Linear with text size plus detected matches
//!
//! ## Recommendations
//!
//! - For large documents (>1MB), use `StreamingScanner` from Layer 1
//! - Use `Cow<str>` returns when possible to avoid allocations on clean text
//! - Cache builder instances for repeated operations
//! - Default to `LocationPrecision::Full` unless business justification exists

pub(crate) mod builder;
pub(crate) mod redaction;

// Internal modules - not directly accessible outside location/
mod cache;
mod conversion;
mod detection;
mod sanitization;
mod validation;

// Re-export the builder as primary API
pub use builder::LocationIdentifierBuilder;

// Re-export types from builder (for return types)
pub use builder::{GpsFormat, PostalCodeNormalization, PostalCodeType};

// Re-export redaction strategies for convenience
pub use redaction::{
    AddressRedactionStrategy, CountryRedactionStrategy, GpsRedactionStrategy,
    PostalCodeRedactionStrategy, TextRedactionPolicy,
};

// Re-export sanitization functions for convenience
pub use sanitization::{
    redact_addresses_in_text_with_strategy, redact_all_location_data_with_strategy,
    redact_gps_coordinate_with_strategy, redact_gps_coordinates_in_text_with_strategy,
    redact_postal_code_with_strategy, redact_postal_codes_in_text_with_strategy,
    redact_street_address_with_strategy, sanitize_gps_coordinate_strict,
    sanitize_postal_code_strict, sanitize_street_address_strict,
};

// Re-export cache management functions
pub use cache::{
    clear_gps_cache, clear_location_caches, clear_postal_cache, gps_cache_stats, postal_cache_stats,
};

// Export test pattern detection functions (observe module testing)
pub use detection::{is_test_gps_coordinate, is_test_postal_code};
