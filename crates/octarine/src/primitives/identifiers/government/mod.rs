//! Government identifier detection, validation, sanitization, and conversion
//!
//! This module provides pure functions for government-issued identifiers:
//! - **Detection**: Find SSNs, tax IDs, driver's licenses, passports, national IDs, VINs
//! - **Validation**: Verify format and validity per SSA/IRS rules
//! - **Sanitization**: Redact and mask sensitive data
//! - **Conversion**: Normalize formats
//!
//! # Compliance Coverage
//!
//! Government identifiers handled by this module are protected under:
//!
//! | Identifier | OWASP | PCI DSS | HIPAA | CCPA |
//! |------------|-------|---------|-------|------|
//! | SSN | Input Validation | Redacted logging | Medical records | Personal information |
//! | Tax ID | Input Validation | Best Practice | N/A | Personal information |
//! | Driver License | Input Validation | Best Practice | N/A | Personal information |
//! | Passport | Input Validation | Best Practice | N/A | Personal information |
//! | National ID | Input Validation | Best Practice | N/A | Personal information |
//! | VIN | Input Validation | N/A | N/A | N/A |
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns data, no side effects
//! - Used by observe/pii and security modules
//!
//! # Usage
//!
//! Access functionality through the builder:
//!
//! ```ignore
//! use crate::primitives::identifiers::IdentifierBuilder;
//!
//! let builder = IdentifierBuilder::new();
//! let gov = builder.government();
//!
//! // Detection
//! let is_ssn = gov.is_ssn("900-00-0001");
//! let ssns = gov.find_ssns_in_text("SSN: 900-00-0001");
//!
//! // Validation
//! let valid = gov.validate_ssn("234-56-7890");
//!
//! // Sanitization
//! let redacted = gov.redact_ssn("900-00-0001");
//!
//! // Conversion
//! let normalized = gov.normalize_ssn("900 00 0001");
//! ```
//!
//! # Performance Characteristics
//!
//! ## Computational Complexity
//!
//! | Operation | Time | Space | Notes |
//! |-----------|------|-------|-------|
//! | `is_ssn` | O(n) | O(1) | Pattern matching |
//! | `validate_ssn` | O(n) | O(n) | Digit extraction + rule checks |
//! | `find_ssns_in_text` | O(n) | O(m) | n = text length, m = matches |
//! | `redact_ssn` | O(n) | O(n) | n = SSN length |
//! | `normalize_ssn` | O(n) | O(n) | Digit extraction |
//! | `validate_vin_with_checksum` | O(1) | O(1) | Fixed 17-character input |
//!
//! ## Memory Usage
//!
//! - **Regex patterns**: ~20KB lazily initialized (shared across calls)
//! - **SSN validation cache**: Up to 10,000 entries, 1-hour TTL
//! - **VIN checksum cache**: Up to 5,000 entries, 1-hour TTL
//! - **Per-call overhead**: Minimal, typically < 1KB for single identifiers
//! - **Text scanning**: Linear with text size plus detected matches
//!
//! ## Caching
//!
//! SSN validation and VIN checksum validation use LRU caching for performance.
//! For documents with repeated identifiers, expect 15-40% CPU reduction.
//!
//! ```ignore
//! use crate::primitives::identifiers::government;
//!
//! // Check cache performance
//! let stats = government::ssn_cache_stats();
//! println!("Hit rate: {:.2}%", stats.hit_rate() * 100.0);
//!
//! // Clear caches when memory pressure is high
//! government::clear_government_caches();
//! ```
//!
//! ## Recommendations
//!
//! - For large documents (>1MB), consider streaming scanner from parent module
//! - Use cache stats to monitor hit rate in production
//! - Clear caches periodically in memory-constrained environments
//! - Use `Cow<str>` returns when possible to avoid allocations on clean text

pub mod builder;
pub mod licenses;
pub mod redaction;

// Internal modules - not directly accessible outside government/
mod conversion;
mod detection;
mod sanitization;
mod validation;

// Export builder as primary API
pub use builder::GovernmentIdentifierBuilder;

// Export redaction strategies
pub use redaction::TextRedactionPolicy;
pub use sanitization::SsnRedactionStrategy;

// Export cache stats functions for performance monitoring
pub use validation::{clear_government_caches, ssn_cache_stats, vin_cache_stats};

// Export test pattern detection functions (observe module testing)
pub use validation::{
    is_test_australia_abn, is_test_australia_tfn, is_test_driver_license, is_test_ein,
    is_test_korea_rrn, is_test_vin,
};

// Export Australia validation functions
pub use validation::{
    validate_australia_abn, validate_australia_abn_with_checksum, validate_australia_tfn,
    validate_australia_tfn_with_checksum,
};

// Export Korea RRN validation functions
pub use validation::{validate_korea_rrn, validate_korea_rrn_with_checksum};

// Export strategy types for explicit redaction control
pub use sanitization::{
    DriverLicenseRedactionStrategy, NationalIdRedactionStrategy, PassportRedactionStrategy,
    TaxIdRedactionStrategy, VehicleIdRedactionStrategy,
};

// Export strategy-based redaction functions
pub use sanitization::{
    redact_driver_license_with_strategy, redact_national_id_with_strategy,
    redact_passport_with_strategy, redact_ssn_with_strategy, redact_tax_id_with_strategy,
    redact_vehicle_id_with_strategy,
};

// Export strategy-based text redaction functions
pub use sanitization::{
    redact_all_government_ids_in_text_with_policy, redact_driver_licenses_in_text_with_strategy,
    redact_national_ids_in_text_with_strategy, redact_passports_in_text_with_strategy,
    redact_ssns_in_text_with_strategy, redact_tax_ids_in_text_with_strategy,
    redact_vehicle_ids_in_text_with_strategy,
};

// Export strict sanitization functions
pub use sanitization::{
    sanitize_driver_license_strict, sanitize_ein_strict, sanitize_ssn_strict, sanitize_vin_strict,
};

// Export common normalization functions (observe module convenience)
pub use conversion::{normalize_driver_license, normalize_ein, normalize_ssn, normalize_vin};
