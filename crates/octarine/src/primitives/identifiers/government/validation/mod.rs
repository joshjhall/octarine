//! Government-issued identifier validation (primitives layer)
//!
//! Pure validation functions for government identifiers with no observe dependencies.
//! Used by observe/pii and security modules.
//!
//! # Supported Identifiers
//!
//! - **Social Security Numbers (SSN)**: US Social Security Administration IDs
//! - **Individual Taxpayer Identification Numbers (ITIN)**: IRS tax processing
//! - **Employer Identification Numbers (EIN)**: IRS business tax IDs
//! - **Driver's Licenses**: State-specific format validation
//! - **Vehicle Identification Numbers (VIN)**: 17-character vehicle IDs
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns data, no side effects
//! - Used by observe/pii and security modules
//!
//! # Module Structure
//!
//! - `cache` - Shared caching infrastructure for validation results
//! - `ssn` - Social Security Number validation
//! - `ein` - Employer Identification Number validation
//! - `driver_license` - State-specific driver's license validation
//! - `vin` - Vehicle Identification Number validation
//!
//! # Compliance Coverage
//!
//! Government identifiers handled by this module are protected under:
//!
//! | Identifier | OWASP | PCI DSS | HIPAA |
//! |------------|-------|---------|-------|
//! | SSN | Input Validation | Redacted logging | Medical record patterns |
//! | ITIN | Input Validation | Best Practice | N/A |
//! | EIN | Input Validation | Best Practice | N/A |

mod cache;
mod driver_license;
mod ein;
mod national_id;
mod passport;
mod ssn;
mod vin;

// Re-export cache utilities
pub use cache::{clear_government_caches, ssn_cache_stats, vin_cache_stats};

// Re-export SSN functions
pub use ssn::{is_itin_area, is_test_ssn, validate_ssn};

// Re-export EIN functions
pub use ein::{is_test_ein, is_valid_ein_prefix, validate_ein};

// Re-export driver's license functions
pub use driver_license::{is_test_driver_license, validate_driver_license};

// Re-export passport functions
pub use passport::{is_test_passport, validate_passport};

// Re-export national ID functions
pub use national_id::{
    is_test_national_id, validate_canada_sin, validate_national_id, validate_uk_ni,
};

// Re-export VIN functions
pub use vin::{is_test_vin, validate_vin, validate_vin_with_checksum};
