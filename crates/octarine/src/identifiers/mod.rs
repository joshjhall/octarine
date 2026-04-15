//! Identifier operations with built-in security and observability
//!
//! This module provides comprehensive identifier handling for PII, credentials,
//! and other sensitive data types. All operations are instrumented with observe
//! for compliance-grade audit trails.
//!
//! # Features
//!
//! - **Detection**: Find identifiers (emails, phones, SSNs, credit cards, etc.) in text
//! - **Validation**: Verify format and validity of identifiers
//! - **Sanitization**: Redact, mask, and clean sensitive data
//! - **Conversion**: Normalize formats (E.164 phones, lowercase emails)
//! - **Streaming**: Process large text efficiently
//!
//! # Domain Organization
//!
//! Identifiers are organized by domain for compliance mapping:
//!
//! - `PersonalBuilder` - Emails, phones, names, birthdates (GDPR, CCPA)
//! - `FinancialBuilder` - Credit cards, bank accounts, routing numbers (PCI-DSS)
//! - `GovernmentBuilder` - SSNs, driver licenses, passports, VINs, EINs
//! - `NetworkBuilder` - IPs, MACs, URLs, UUIDs, hostnames, ports
//! - `CredentialsBuilder` - API keys, passwords, tokens, session IDs
//! - `LocationBuilder` - Addresses, GPS coordinates, postal codes
//! - `TokenBuilder` - JWTs, OAuth tokens, session tokens
//! - `MedicalBuilder` - Medical record numbers, health insurance (HIPAA)
//! - `BiometricBuilder` - Fingerprints, facial recognition, voice prints (BIPA)
//! - `OrganizationalBuilder` - Employee IDs, badge numbers, department codes
//! - `DatabaseBuilder` - Connection strings, database identifiers
//! - `EnvironmentBuilder` - Environment variables, config values
//! - `GenericBuilder` - Generic identifier validation
//! - `MetricsBuilder` - Metrics and telemetry identifiers
//!
//! # Usage
//!
//! ## Using the Unified IdentifierBuilder
//!
//! ```
//! use octarine::identifiers::IdentifierBuilder;
//!
//! let builder = IdentifierBuilder::new();
//!
//! // Access domain-specific builders
//! let emails = builder.personal().find_emails_in_text("Contact: user@example.com");
//! let cards = builder.financial().detect_credit_cards_in_text("Card: 4242424242424242");
//!
//! // Detect any identifier
//! let id_type = builder.detect("user@example.com");
//!
//! // Scan text for all identifiers
//! let matches = builder.scan_text("Email: user@example.com, SSN: 123-45-6789");
//! ```
//!
//! ## Using Domain-Specific Builders
//!
//! ```
//! use octarine::identifiers::{PersonalBuilder, FinancialBuilder};
//!
//! // Personal identifiers (emails, phones, names)
//! let personal = PersonalBuilder::new();
//! if personal.is_email("user@example.com") {
//!     // Process email...
//! }
//!
//! // Financial identifiers (credit cards, bank accounts)
//! let financial = FinancialBuilder::new();
//! if financial.is_credit_card("4242424242424242") {
//!     // Process credit card...
//! }
//! ```
//!
//! ## Using Shortcuts (Common Operations)
//!
//! ```
//! use octarine::identifiers::{is_email, redact_email, redact_credit_cards};
//!
//! // Quick detection
//! if is_email("user@example.com") {
//!     // Handle email
//! }
//!
//! // Quick redaction (uses sensible default strategies)
//! let safe = redact_email("user@example.com");
//! let safe_cards = redact_credit_cards("Card: 4242424242424242");
//! ```
//!
//! # Compliance Mapping
//!
//! | Domain | GDPR | CCPA | HIPAA | PCI-DSS | SOC2 |
//! |--------|------|------|-------|---------|------|
//! | Personal | Art. 4(1) | Personal Info | PHI | - | CC6.1 |
//! | Financial | Art. 4(1) | Financial Info | - | Req 3 | CC6.1 |
//! | Government | Art. 4(1) | Personal Info | PHI | - | CC6.1 |
//! | Medical | Art. 9 | Sensitive | PHI | - | CC6.1 |
//! | Biometric | Art. 9 | Sensitive | - | - | CC6.1 |
//! | Credentials | Art. 4(1) | Personal Info | - | Req 3 | CC6.1 |
//!
//! # Observe Integration
//!
//! All operations emit:
//! - **Events**: DEBUG for detections, WARN for PII found, CRITICAL for credentials
//! - **Metrics**: Detection counts, timing, redaction rates

// Private submodules - re-export at identifiers level
mod builder;
mod facade;
mod shortcuts;
mod tokens;
mod types;

// Re-export the main IdentifierBuilder
pub use builder::IdentifierBuilder;

// Re-export the Identifiers facade at module level
pub use facade::Identifiers;

// Re-export all domain-specific builders
pub use builder::{
    BiometricBuilder, ConfidenceBuilder, CorrelationBuilder, CredentialsBuilder, DatabaseBuilder,
    EntropyBuilder, EnvironmentBuilder, FinancialBuilder, GenericBuilder, GovernmentBuilder,
    LocationBuilder, MedicalBuilder, MetricsBuilder, NetworkBuilder, OrganizationalBuilder,
    PersonalBuilder, TokenBuilder,
};

// Re-export types for public API
pub use types::{
    ApiKeyProvider, BiometricTemplateRedactionStrategy, BiometricTextPolicy, CacheStats,
    CorrelationConfig, CorrelationMatch, CredentialMatch, CredentialPairType, CredentialTextPolicy,
    CredentialType, CreditCardType, DetectionConfidence, DetectionResult, DnaRedactionStrategy,
    FacialIdRedactionStrategy, FinancialTextPolicy, FingerprintRedactionStrategy,
    GovernmentTextPolicy, GpsFormat, IdentifierMatch, IdentifierType, IrisIdRedactionStrategy,
    LocationTextPolicy, MedicalTextPolicy, MetricViolation, OrganizationalTextPolicy,
    PersonalTextPolicy, PhoneRegion, PostalCodeNormalization, PostalCodeType, UuidVersion,
    VoiceIdRedactionStrategy,
};

// Re-export RedactionToken (public API for redaction tokens)
pub use tokens::RedactionToken;

// Re-export shortcuts at module level for convenience
pub use shortcuts::*;
