//! Location identifier sanitization
//!
//! Redacts and masks location identifiers with domain-specific redaction strategies.
//!
//! # Two-Tier Redaction API
//!
//! ## Domain-Specific Strategies (Single Identifiers)
//! Each identifier type has its own strategy enum with only valid options:
//! - `redact_gps_coordinate_with_strategy(coord, GpsRedactionStrategy)` - Precision levels or token
//! - `redact_street_address_with_strategy(address, AddressRedactionStrategy)` - Show region or token
//! - `redact_postal_code_with_strategy(code, PostalCodeRedactionStrategy)` - Show prefix/region or token
//!
//! ## Generic Text Policy (Text Scanning)
//! For scanning text with multiple identifier types, use `TextRedactionPolicy`:
//! - `None` - No redaction (dev/qa only)
//! - `Partial` - Show regional information (city/state level)
//! - `Complete` - Full token redaction ([GPS], [ADDRESS], etc.)
//! - `Anonymous` - Generic [REDACTED] for everything
//!
//! # Module Structure
//!
//! - `gps` - GPS coordinate redaction and sanitization
//! - `address` - Street address redaction and sanitization
//! - `postal` - Postal code redaction and sanitization
//! - `text` - Text scanning with find/replace
//!
//! # Security Considerations
//!
//! - GPS coordinates can reveal exact location under GDPR Article 4(1)
//! - Street addresses are PII requiring consent under CCPA
//! - ZIP codes can be quasi-identifiers when combined with other data
//! - Default to Complete (token) redaction unless business justification exists
//!
//! # Compliance
//!
//! - **GDPR Article 4**: Location data is personal data
//! - **CCPA 1798.140**: Geolocation data requires opt-in consent
//! - **HIPAA**: Protected health information includes geographic subdivisions
//! - **COPPA**: Cannot collect precise geolocation from children

mod address;
mod gps;
mod postal;
mod text;

// Re-export GPS functions
pub use gps::{redact_gps_coordinate_with_strategy, sanitize_gps_coordinate_strict};

// Re-export address functions
pub use address::{redact_street_address_with_strategy, sanitize_street_address_strict};

// Re-export postal code functions
pub use postal::{redact_postal_code_with_strategy, sanitize_postal_code_strict};

// Re-export text functions
pub use text::{
    redact_addresses_in_text_with_strategy, redact_all_location_data_with_strategy,
    redact_gps_coordinates_in_text_with_strategy, redact_postal_codes_in_text_with_strategy,
};
