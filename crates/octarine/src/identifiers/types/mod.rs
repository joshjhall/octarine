//! Public types for identifier operations — re-exported from primitives
//!
//! These types form the public API for identifier detection, validation, and redaction.
//! They are re-exported directly from the internal primitives layer.

mod biometric;
mod cache;
mod core;
mod correlation;
mod financial;
mod location;
mod network;
mod personal;
mod policies;

// Re-export all types for convenience
pub use biometric::{
    BiometricTemplateRedactionStrategy, BiometricTextPolicy, DnaRedactionStrategy,
    FacialIdRedactionStrategy, FingerprintRedactionStrategy, IrisIdRedactionStrategy,
    VoiceIdRedactionStrategy,
};
pub use cache::CacheStats;
pub use core::{DetectionConfidence, DetectionResult, IdentifierMatch, IdentifierType};
pub use correlation::{CorrelationConfig, CorrelationMatch, CredentialPairType};
pub use financial::{CreditCardType, FinancialTextPolicy};
pub use location::{GpsFormat, LocationTextPolicy, PostalCodeNormalization, PostalCodeType};
pub use network::{ApiKeyProvider, UuidVersion};
pub use personal::{CredentialMatch, CredentialType, PhoneRegion};
pub use policies::{GovernmentTextPolicy, MedicalTextPolicy, OrganizationalTextPolicy};
