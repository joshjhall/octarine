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

mod australia;
mod brazil;
mod cache;
mod driver_license;
mod ein;
mod finland;
mod india;
mod italy;
mod korea_rrn;
mod mexico;
mod national_id;
mod nigeria;
mod passport;
mod poland;
mod singapore;
mod spain;
mod ssn;
mod thailand;
mod vin;

// Re-export cache utilities
pub use cache::{clear_government_caches, ssn_cache_stats, vin_cache_stats};

// Re-export SSN functions
pub use ssn::validate_ssn;

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

// Re-export Australia functions
pub use australia::{
    is_test_australia_abn, is_test_australia_tfn, validate_australia_abn,
    validate_australia_abn_with_checksum, validate_australia_tfn,
    validate_australia_tfn_with_checksum,
};

// Re-export Finland functions
pub use finland::{
    is_test_finland_hetu, validate_finland_hetu, validate_finland_hetu_with_checksum,
};

// Re-export Poland functions
pub use poland::{
    is_test_poland_pesel, validate_poland_pesel, validate_poland_pesel_with_checksum,
};

// Re-export Italy functions
pub use italy::{
    is_test_italy_fiscal_code, validate_italy_fiscal_code, validate_italy_fiscal_code_with_checksum,
};

// Re-export Spain functions
pub use spain::{
    is_test_spain_nie, is_test_spain_nif, validate_spain_nie, validate_spain_nie_with_checksum,
    validate_spain_nif, validate_spain_nif_with_checksum,
};

// Re-export India functions
pub use india::{
    is_test_india_aadhaar, is_test_india_gstin, is_test_india_pan, is_test_india_passport,
    is_test_india_vehicle_registration, is_test_india_voter_id, validate_india_aadhaar,
    validate_india_aadhaar_with_checksum, validate_india_gstin, validate_india_gstin_with_checksum,
    validate_india_pan, validate_india_passport, validate_india_vehicle_registration,
    validate_india_voter_id,
};

// Re-export Singapore functions
pub use singapore::{
    is_test_singapore_nric, validate_singapore_nric, validate_singapore_nric_with_checksum,
};

// Re-export Korea RRN functions
pub use korea_rrn::{is_test_korea_rrn, validate_korea_rrn, validate_korea_rrn_with_checksum};

// Re-export Brazil functions
pub use brazil::{
    is_test_brazil_cnpj, is_test_brazil_cpf, validate_brazil_cnpj,
    validate_brazil_cnpj_with_checksum, validate_brazil_cpf, validate_brazil_cpf_with_checksum,
};

// Re-export Mexico functions
pub use mexico::{is_test_mexico_curp, validate_mexico_curp, validate_mexico_curp_with_checksum};

// Re-export Nigeria functions
pub use nigeria::{is_test_nigeria_nin, validate_nigeria_nin};

// Re-export Thailand functions
pub use thailand::{
    is_test_thailand_tnin, validate_thailand_tnin, validate_thailand_tnin_with_checksum,
};

// Re-export VIN functions
pub use vin::{is_test_vin, validate_vin, validate_vin_with_checksum};
