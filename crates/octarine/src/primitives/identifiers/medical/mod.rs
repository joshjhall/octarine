//! Medical identifier primitives
//!
//! Pure detection, validation, and sanitization for medical identifiers.
//! No observe dependencies - used by Layer 2 and Layer 3 modules.
//!
//! # Supported Identifiers
//!
//! - **MRN**: Medical Record Number
//! - **Insurance**: Health insurance policy/member numbers
//! - **Prescription**: RX prescription numbers
//! - **NPI**: National Provider Identifier
//! - **Medical Codes**: ICD-10 diagnosis codes, CPT procedure codes
//!
//! # HIPAA Compliance
//!
//! All identifiers are Protected Health Information (PHI) under:
//! - HIPAA Privacy Rule (45 CFR 164.514)
//! - HITECH Act requirements
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::identifiers::medical::MedicalIdentifierBuilder;
//!
//! let builder = MedicalIdentifierBuilder::new();
//!
//! // Detection
//! if builder.is_provider_id("NPI: 1234567890") {
//!     println!("Found NPI");
//! }
//!
//! // Validation
//! if builder.validate_npi("1245319599").is_ok() {
//!     println!("Valid NPI");
//! }
//!
//! // Sanitization
//! let safe = builder.redact_all_in_text("NPI: 1234567890");
//! ```

pub(crate) mod builder;
pub(crate) mod redaction;

// Internal modules - not directly accessible outside medical/
mod conversion;
mod detection;
mod sanitization;
mod validation;

// Re-export builder for convenient access
pub use builder::MedicalIdentifierBuilder;

// Re-export redaction strategies for type-safe redaction API
pub use redaction::{
    InsuranceRedactionStrategy, MedicalCodeRedactionStrategy, MrnRedactionStrategy,
    NpiRedactionStrategy, PrescriptionRedactionStrategy, TextRedactionPolicy,
};

// Re-export conversion format styles (needed for builder parameters)
pub use conversion::{Icd10FormatStyle, NpiFormatStyle};

// Export cache stats functions for performance monitoring
pub use detection::{clear_medical_caches, npi_cache_stats};

// Export test pattern detection functions (observe module testing)
pub use detection::{is_test_insurance, is_test_mrn, is_test_npi};

// Export common normalization functions (observe module convenience)
pub use conversion::normalize_icd10;
