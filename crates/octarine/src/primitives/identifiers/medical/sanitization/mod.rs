//! Medical identifier sanitization (primitives layer)
//!
//! Pure sanitization functions for medical identifiers with no observe dependencies.
//! Used by observe/pii and security modules.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns sanitized data, no side effects
//! - Used by observe/pii and security modules
//!
//! # HIPAA Compliance
//!
//! All identifiers require redaction for de-identification under:
//! - 45 CFR 164.514(b)(2) - Safe Harbor method
//!
//! # Two-Tier Redaction API
//!
//! ## Domain-Specific Strategies (Single Identifiers)
//! Each identifier type has its own strategy enum with only valid options:
//! - `redact_mrn_with_strategy(id, MrnRedactionStrategy)` - ShowPrefix, ShowFacility, Token, etc.
//! - `redact_insurance_number_with_strategy(id, InsuranceRedactionStrategy)` - ShowProvider, ShowLast4, Token, etc.
//! - `redact_prescription_number_with_strategy(id, PrescriptionRedactionStrategy)` - ShowPharmacy, Token, etc.
//! - `redact_npi_with_strategy(id, NpiRedactionStrategy)` - ShowFirst4, Token, etc.
//! - `redact_medical_code_with_strategy(code, MedicalCodeRedactionStrategy)` - ShowCategory, Token, etc.
//!
//! ## Generic Text Policy (Text Scanning)
//! For scanning text with multiple identifier types, use `TextRedactionPolicy`:
//! - `None` - No redaction
//! - `Partial` - Show some information (sensible defaults per type)
//! - `Complete` - Full token redaction (<MEDICAL_RECORD>, <INSURANCE_INFO>, etc.)
//! - `Anonymous` - Generic [REDACTED] for everything

mod individual;
mod text;

// Re-export individual redaction functions (explicit strategy required)
pub use individual::{
    redact_insurance_number_with_strategy, redact_medical_code_with_strategy,
    redact_mrn_with_strategy, redact_npi_with_strategy, redact_prescription_number_with_strategy,
    redact_provider_id_with_strategy,
};

// Re-export text redaction functions
pub use text::{
    redact_all_medical_in_text, redact_insurance_in_text, redact_medical_codes_in_text,
    redact_mrn_in_text, redact_prescriptions_in_text, redact_provider_ids_in_text,
};
