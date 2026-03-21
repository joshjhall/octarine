// Allow dead code and unused imports - this module is being built incrementally
// and not all items are used yet. They will be used when security module migrates.
#![allow(dead_code)]
#![allow(unused_imports)]

//! Pure identifier detection, validation, and sanitization primitives
//!
//! This module provides pure functions for detecting, validating, and sanitizing
//! identifiers (PII, credentials, etc.) with ZERO rust-core dependencies beyond
//! the Problem type for error handling.
//!
//! ## Architecture
//!
//! This is part of **Layer 1 (primitives)** - used by both observe and security modules.
//!
//! ## Module Structure
//!
//! - `common` - Shared utilities (patterns, luhn, masking, utils)
//! - `types` - Type definitions (IdentifierType, IdentifierMatch, etc.)
//! - Domain modules (personal, government, financial, etc.) - Detection via builders
//!
//! ## Design Principles
//!
//! 1. **No Logging**: Pure functions, no trace/debug calls
//! 2. **No Side Effects**: Only pattern matching and validation
//! 3. **Returns Data**: Detection returns matches, validation returns bool/Result
//! 4. **Reusable**: Used by observe/pii and security modules
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::primitives::identifiers::PersonalIdentifierBuilder;
//!
//! // Find all emails in text via builder
//! let personal = PersonalIdentifierBuilder::new();
//! let matches = personal.find_emails_in_text("Contact: user@example.com");
//!
//! // Check for SSNs via builder
//! let gov = GovernmentIdentifierBuilder::new();
//! let has_ssn = !gov.find_ssns_in_text("SSN: 123-45-6789").is_empty();
//! ```

// Private to identifiers/ - sibling modules (like paths/) cannot access
mod common;

// Accessible within crate - observe/pii and security can use these
pub(crate) mod builder;
pub(crate) mod streaming;
pub(crate) mod types;

// Domain modules - private, accessed through builder
mod biometric;
mod credentials;
mod financial;
mod government;
mod location;
mod medical;
mod organizational;
mod personal;
mod token;

// Network module - pub(crate) for IP types used by observe
pub(crate) mod network;

// Identifier validation modules (for observe module to use)
pub(crate) mod database;
pub(crate) mod environment;
pub(crate) mod generic;
pub(crate) mod metrics;

// Crypto artifact identification (feature-gated)
#[cfg(feature = "crypto-validation")]
pub(crate) mod crypto;

// NOTE: Raw detection functions from detection/ are NOT re-exported.
// All access to identifier operations should go through the builders:
// - IdentifierBuilder (main entry point)
// - PersonalIdentifierBuilder (emails, phones, names, birthdates)
// - GovernmentIdentifierBuilder (SSNs, driver licenses, passports, VINs, EINs)
// - FinancialIdentifierBuilder (credit cards, bank accounts, routing numbers)
// - CredentialIdentifierBuilder (API keys, passwords, tokens)
// - BiometricIdentifierBuilder (fingerprints, facial recognition)
// - MedicalIdentifierBuilder (MRNs, health records)
// - LocationIdentifierBuilder (addresses, coordinates)
// - OrganizationalIdentifierBuilder (employee IDs, department codes)
// - TokenIdentifierBuilder (JWTs, OAuth tokens)
// - NetworkIdentifierBuilder (IPs, MACs, URLs)

// Re-export types for crate-internal use
// These will become pub when IdentifierBuilder is complete
pub(crate) use types::{
    CredentialMatch, CredentialType, CreditCardType, DetectionConfidence, DetectionResult,
    IdentifierMatch, IdentifierType, PhoneRegion,
};

// Re-export builder for crate-internal use
pub(crate) use builder::IdentifierBuilder;

// Re-export streaming scanner for crate-internal use
pub(crate) use streaming::StreamingScanner;

// Re-export domain builders for crate-internal use
pub(crate) use biometric::BiometricIdentifierBuilder;
pub(crate) use credentials::CredentialIdentifierBuilder;
pub(crate) use database::DatabaseBuilder;
pub(crate) use environment::EnvironmentBuilder;
pub(crate) use financial::FinancialIdentifierBuilder;
pub(crate) use generic::GenericBuilder;
pub(crate) use government::GovernmentIdentifierBuilder;
pub(crate) use location::LocationIdentifierBuilder;
pub(crate) use medical::MedicalIdentifierBuilder;
pub(crate) use metrics::MetricsBuilder;
pub(crate) use network::NetworkIdentifierBuilder;
pub(crate) use organizational::OrganizationalIdentifierBuilder;
pub(crate) use personal::PersonalIdentifierBuilder;
pub(crate) use token::TokenIdentifierBuilder;

// Re-export crypto builder (feature-gated)
#[cfg(feature = "crypto-validation")]
pub(crate) use crypto::CryptoIdentifierBuilder;

// Re-export crypto types for crate-internal use (feature-gated)
#[cfg(feature = "crypto-validation")]
pub(crate) use crypto::{
    CertificateType, CryptoDetectionResult, KeyFormat, KeyType, SignatureAlgorithm,
};

// Re-export TextRedactionPolicy types for crate-internal use by observe/pii
pub(crate) use biometric::redaction::TextRedactionPolicy as BiometricTextPolicy;

// Re-export biometric redaction strategies for data layer
pub(crate) use biometric::builder::{
    BiometricTemplateRedactionStrategy, DnaRedactionStrategy, FacialIdRedactionStrategy,
    FingerprintRedactionStrategy, IrisIdRedactionStrategy, VoiceIdRedactionStrategy,
};
pub(crate) use credentials::redaction::TextRedactionPolicy as CredentialTextPolicy;
pub(crate) use government::TextRedactionPolicy as GovernmentTextPolicy;
pub(crate) use location::redaction::TextRedactionPolicy as LocationTextPolicy;
pub(crate) use medical::redaction::TextRedactionPolicy as MedicalTextPolicy;
pub(crate) use personal::TextRedactionPolicy as PersonalTextPolicy;

// Re-export domain-specific redaction strategies for observe/pii config
pub(crate) use financial::{
    BankAccountRedactionStrategy, CreditCardRedactionStrategy, PaymentTokenRedactionStrategy,
    RoutingNumberRedactionStrategy,
};
pub(crate) use government::{
    DriverLicenseRedactionStrategy, NationalIdRedactionStrategy, PassportRedactionStrategy,
    SsnRedactionStrategy, TaxIdRedactionStrategy, VehicleIdRedactionStrategy,
};
pub(crate) use personal::{EmailRedactionStrategy, PhoneRedactionStrategy};

// Re-export all personal builder types for data layer
pub(crate) use personal::{
    BirthdateRedactionStrategy, NameRedactionStrategy, PhoneFormatStyle, UsernameRedactionStrategy,
};

// Re-export medical builder types for data layer
pub(crate) use medical::{
    Icd10FormatStyle, InsuranceRedactionStrategy, MedicalCodeRedactionStrategy,
    MrnRedactionStrategy, NpiFormatStyle, NpiRedactionStrategy, PrescriptionRedactionStrategy,
};

// Re-export location builder types for data layer
pub(crate) use location::{
    AddressRedactionStrategy, GpsFormat, GpsRedactionStrategy, PostalCodeNormalization,
    PostalCodeRedactionStrategy, PostalCodeType,
};

// Re-export token builder types for data layer
pub(crate) use token::TextRedactionPolicy as TokenTextPolicy;
pub(crate) use token::{
    ApiKeyProvider, ApiKeyRedactionStrategy, JwtAlgorithm, JwtMetadata, JwtRedactionStrategy,
    SessionIdRedactionStrategy, SshFingerprintRedactionStrategy, SshKeyRedactionStrategy,
    TokenType,
};

// Re-export network builder types for data layer
pub(crate) use network::{
    ApiKeyRedactionStrategy as NetworkApiKeyRedactionStrategy, IpAddress, IpAddressList,
    IpClassification, IpRedactionStrategy, MacRedactionStrategy, NetworkInterface, PortRange,
    TextRedactionPolicy as NetworkTextPolicy, UrlRedactionStrategy, UuidRedactionStrategy,
    UuidVersion,
};

// Re-export credential builder types for data layer
pub(crate) use credentials::{
    PassphraseRedactionStrategy, PasswordRedactionStrategy, PinRedactionStrategy,
    SecurityAnswerRedactionStrategy,
};

// Re-export financial builder types for data layer
pub(crate) use financial::TextRedactionPolicy as FinancialTextPolicy;

// Re-export organizational builder types for data layer
pub(crate) use organizational::TextRedactionPolicy as OrganizationalTextPolicy;

// NOTE: Strategy-based text redaction functions are NOT re-exported.
// Access these through the domain-specific builders:
// - PersonalIdentifierBuilder::redact_emails_in_text_with_strategy()
// - PersonalIdentifierBuilder::redact_phones_in_text_with_strategy()
// - GovernmentIdentifierBuilder::redact_ssns_in_text_with_strategy()
// - FinancialIdentifierBuilder::redact_credit_cards_in_text_with_strategy()
//
// NOTE: PII detection functions are NOT re-exported.
// Access these through the builders:
// - PersonalIdentifierBuilder::is_pii_present()
