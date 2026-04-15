//! Biometric identifier primitives
//!
//! Pure detection, validation, and sanitization for biometric identifiers.
//! No observe dependencies - used by Layer 2 and Layer 3 modules.
//!
//! # Supported Identifiers
//!
//! - **Fingerprints**: Fingerprint hashes and identifiers
//! - **Facial Recognition**: Face encodings, FaceID/TouchID
//! - **Iris Scans**: IrisCode format, iris templates
//! - **Voice Prints**: Voice/speaker identification
//! - **DNA Sequences**: Genetic information, STR markers
//! - **Biometric Templates**: ISO/IEC 19794 standard formats
//!
//! # Privacy Compliance
//!
//! All biometric identifiers are protected under:
//! - GDPR Article 9 (special category data requiring explicit consent)
//! - BIPA (Biometric Information Privacy Act - Illinois)
//! - CCPA (California Consumer Privacy Act)
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
//! use octarine::primitives::identifiers::biometric::BiometricIdentifierBuilder;
//!
//! let builder = BiometricIdentifierBuilder::new();
//!
//! // Detection
//! if builder.is_fingerprint("fingerprint: abc123...") {
//!     println!("Found fingerprint");
//! }
//!
//! // Validation
//! if builder.validate_fingerprint_id("FP-A1B2C3D4") {
//!     println!("Valid fingerprint ID");
//! }
//!
//! // Sanitization
//! let safe = builder.redact_all_in_text("fingerprint: abc123...");
//! ```

pub(crate) mod builder;
pub(crate) mod redaction;

// Internal modules - not directly accessible outside biometric/
mod detection;
mod sanitization;
mod validation;

// Re-export builder for convenient access
pub use builder::BiometricIdentifierBuilder;

// Re-export redaction strategies for type-safe redaction API
pub use redaction::{
    BiometricTemplateRedactionStrategy, DnaRedactionStrategy, FacialIdRedactionStrategy,
    FingerprintRedactionStrategy, IrisIdRedactionStrategy, TextRedactionPolicy,
    VoiceIdRedactionStrategy,
};

// Export test pattern detection functions (observe module testing)
pub use detection::{is_test_biometric_id, is_test_dna, is_test_fingerprint};
