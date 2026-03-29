//! Public types for identifier operations
//!
//! These types form the public API for identifier detection, validation, and redaction.
//! They mirror the internal primitives types but are stable public API.
//!
//! ## Design Philosophy
//!
//! - **Compliance-aware**: Types support GDPR, CCPA, HIPAA, PCI-DSS requirements
//! - **Security-focused**: Types capture sensitive data categories
//! - **User-friendly**: Clear documentation and helpful methods
//!
//! ## Module Organization
//!
//! - [`core`] - Core types: `IdentifierType`, `DetectionConfidence`, `IdentifierMatch`, `DetectionResult`
//! - [`personal`] - Personal identifiers: `PhoneRegion`, `CredentialType`, `CredentialMatch`
//! - [`financial`] - Financial identifiers: `CreditCardType`, `FinancialTextPolicy`
//! - [`biometric`] - Biometric identifiers: redaction strategies and policies
//! - [`location`] - Location identifiers: `GpsFormat`, `PostalCodeType`, `LocationTextPolicy`
//! - [`network`] - Network identifiers: `UuidVersion`, `ApiKeyProvider`
//! - [`policies`] - Text redaction policies: `MedicalTextPolicy`, `GovernmentTextPolicy`, `OrganizationalTextPolicy`
//! - [`cache`] - Cache statistics: `CacheStats`

pub mod biometric;
pub mod cache;
pub mod core;
pub mod financial;
pub mod location;
pub mod network;
pub mod personal;
pub mod policies;

// Re-export all types for convenience
pub use biometric::{
    BiometricTemplateRedactionStrategy, BiometricTextPolicy, DnaRedactionStrategy,
    FacialIdRedactionStrategy, FingerprintRedactionStrategy, IrisIdRedactionStrategy,
    VoiceIdRedactionStrategy,
};
pub use cache::CacheStats;
pub use core::{DetectionConfidence, DetectionResult, IdentifierMatch, IdentifierType};
pub use financial::{CreditCardType, FinancialTextPolicy};
pub use location::{GpsFormat, LocationTextPolicy, PostalCodeNormalization, PostalCodeType};
pub use network::{ApiKeyProvider, UuidVersion};
pub use personal::{CredentialMatch, CredentialType, PhoneRegion};
pub use policies::{GovernmentTextPolicy, MedicalTextPolicy, OrganizationalTextPolicy};

// Correlation types (public wrappers of primitives)
pub mod correlation;
pub use correlation::{CorrelationConfig, CorrelationMatch, CredentialPairType};
