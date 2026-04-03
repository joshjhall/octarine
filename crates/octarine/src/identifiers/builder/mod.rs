//! Identifier builders with observability
//!
//! This module provides builders for all identifier operations, wrapping
//! `primitives::data::identifiers` with observe instrumentation.
//!
//! # Builder Organization
//!
//! Each builder focuses on a specific domain:
//!
//! - `PersonalBuilder` - Emails, phones, names, birthdates
//! - `FinancialBuilder` - Credit cards, bank accounts, routing numbers
//! - `GovernmentBuilder` - SSNs, driver licenses, passports, VINs, EINs
//! - `NetworkBuilder` - IPs, MACs, URLs, UUIDs, hostnames
//! - `CredentialsBuilder` - API keys, passwords, tokens
//! - `LocationBuilder` - Addresses, GPS coordinates, postal codes
//! - `TokenBuilder` - JWTs, OAuth tokens, session tokens
//! - `MedicalBuilder` - Medical record numbers, health insurance (HIPAA)
//! - `BiometricBuilder` - Fingerprints, facial recognition (BIPA)
//! - `OrganizationalBuilder` - Employee IDs, badge numbers
//! - `DatabaseBuilder` - Connection strings, database identifiers
//! - `EnvironmentBuilder` - Environment variables
//! - `GenericBuilder` - Generic identifier operations
//! - `MetricsBuilder` - Metrics identifiers
//!
//! # Unified IdentifierBuilder
//!
//! `IdentifierBuilder` provides a unified API that delegates to specialized builders.
//! Use it when you need multiple domain operations or prefer a single entry point.
//!
//! # Examples
//!
//! ## Using Specialized Builders
//!
//! ```
//! use octarine::identifiers::{PersonalBuilder, FinancialBuilder};
//!
//! // Personal identifiers
//! let personal = PersonalBuilder::new();
//! if personal.is_email("user@example.com") {
//!     // Process email...
//! }
//!
//! // Financial identifiers
//! let financial = FinancialBuilder::new();
//! if financial.is_credit_card("4242424242424242") {
//!     // Process credit card...
//! }
//! ```
//!
//! ## Using IdentifierBuilder
//!
//! ```
//! use octarine::identifiers::IdentifierBuilder;
//!
//! let builder = IdentifierBuilder::new();
//!
//! // Access domain builders
//! let emails = builder.personal().find_emails_in_text("Contact: user@example.com");
//! let cards = builder.financial().detect_credit_cards_in_text("Card: 4242424242424242");
//!
//! // Unified detection
//! let id_type = builder.detect("user@example.com");
//! ```

// Domain-specific builders
mod biometric;
mod correlation;
mod credentials;
mod database;
mod entropy;
mod environment;
mod financial;
mod generic;
mod government;
mod location;
mod medical;
mod metrics;
mod network;
mod organizational;
mod personal;
mod token;

// Re-export all domain builders
pub use biometric::BiometricBuilder;
pub use correlation::CorrelationBuilder;
pub use credentials::CredentialsBuilder;
pub use database::DatabaseBuilder;
pub use entropy::EntropyBuilder;
pub use environment::EnvironmentBuilder;
pub use financial::FinancialBuilder;
pub use generic::GenericBuilder;
pub use government::GovernmentBuilder;
pub use location::LocationBuilder;
pub use medical::MedicalBuilder;
pub use metrics::MetricsBuilder;
pub use network::NetworkBuilder;
pub use organizational::OrganizationalBuilder;
pub use personal::PersonalBuilder;
pub use token::TokenBuilder;

use std::time::Instant;

use crate::observe;
use crate::observe::metrics::{MetricName, increment_by, record};
use crate::primitives::identifiers::StreamingScanner;

use super::types::{IdentifierMatch, IdentifierType};

// Pre-validated metric names for IdentifierBuilder
#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn detect_ms() -> MetricName {
        MetricName::new("data.identifiers.detect_ms").expect("valid metric name")
    }

    pub fn scan_ms() -> MetricName {
        MetricName::new("data.identifiers.scan_ms").expect("valid metric name")
    }

    pub fn detected() -> MetricName {
        MetricName::new("data.identifiers.detected").expect("valid metric name")
    }

    pub fn pii_found() -> MetricName {
        MetricName::new("data.identifiers.pii_found").expect("valid metric name")
    }
}

/// Unified identifier operations builder with observability
///
/// Provides a single entry point for all identifier operations, delegating to
/// specialized builders internally.
///
/// # Examples
///
/// ```
/// use octarine::identifiers::IdentifierBuilder;
///
/// let builder = IdentifierBuilder::new();
///
/// // Access domain builders
/// let personal = builder.personal();
/// let financial = builder.financial();
///
/// // Detect identifier type
/// let id_type = builder.detect("user@example.com");
///
/// // Scan text for all identifiers
/// let matches = builder.scan_text("Email: user@example.com, SSN: 123-45-6789");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentifierBuilder;

impl IdentifierBuilder {
    /// Create a new IdentifierBuilder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // ========================================================================
    // Domain Builder Access
    // ========================================================================

    /// Get personal identifier builder (emails, phones, names, birthdates)
    #[must_use]
    pub fn personal(&self) -> PersonalBuilder {
        PersonalBuilder::new()
    }

    /// Get financial identifier builder (credit cards, bank accounts)
    #[must_use]
    pub fn financial(&self) -> FinancialBuilder {
        FinancialBuilder::new()
    }

    /// Get government identifier builder (SSNs, driver licenses, passports)
    #[must_use]
    pub fn government(&self) -> GovernmentBuilder {
        GovernmentBuilder::new()
    }

    /// Get network identifier builder (IPs, MACs, URLs, UUIDs)
    #[must_use]
    pub fn network(&self) -> NetworkBuilder {
        NetworkBuilder::new()
    }

    /// Get credentials identifier builder (API keys, passwords, tokens)
    #[must_use]
    pub fn credentials(&self) -> CredentialsBuilder {
        CredentialsBuilder::new()
    }

    /// Get location identifier builder (addresses, GPS coordinates)
    #[must_use]
    pub fn location(&self) -> LocationBuilder {
        LocationBuilder::new()
    }

    /// Get token identifier builder (JWTs, OAuth tokens)
    #[must_use]
    pub fn token(&self) -> TokenBuilder {
        TokenBuilder::new()
    }

    /// Get medical identifier builder (MRNs, health insurance)
    #[must_use]
    pub fn medical(&self) -> MedicalBuilder {
        MedicalBuilder::new()
    }

    /// Get biometric identifier builder (fingerprints, facial recognition)
    #[must_use]
    pub fn biometric(&self) -> BiometricBuilder {
        BiometricBuilder::new()
    }

    /// Get organizational identifier builder (employee IDs, badge numbers)
    #[must_use]
    pub fn organizational(&self) -> OrganizationalBuilder {
        OrganizationalBuilder::new()
    }

    /// Get database identifier builder (connection strings)
    #[must_use]
    pub fn database(&self) -> DatabaseBuilder {
        DatabaseBuilder::new()
    }

    /// Get environment identifier builder (env vars)
    #[must_use]
    pub fn environment(&self) -> EnvironmentBuilder {
        EnvironmentBuilder::new()
    }

    /// Get generic identifier builder
    #[must_use]
    pub fn generic(&self) -> GenericBuilder {
        GenericBuilder::new()
    }

    /// Get metrics identifier builder
    #[must_use]
    pub fn metrics(&self) -> MetricsBuilder {
        MetricsBuilder::new()
    }

    /// Get entropy identifier builder (high-entropy string detection)
    #[must_use]
    pub fn entropy(&self) -> EntropyBuilder {
        EntropyBuilder::new()
    }

    /// Get credential pair correlation builder
    #[must_use]
    pub fn correlation(&self) -> CorrelationBuilder {
        CorrelationBuilder::new()
    }

    // ========================================================================
    // Unified Detection
    // ========================================================================

    /// Detect identifier type from value
    ///
    /// Attempts to identify what type of identifier the value represents.
    /// Returns None if not recognized as a known identifier type.
    #[must_use]
    pub fn detect(&self, value: &str) -> Option<IdentifierType> {
        let start = Instant::now();

        // Try each domain in order of likelihood
        if let Some(id_type) = self.personal().detect(value) {
            self.emit_detection_metrics(start, &id_type);
            return Some(id_type);
        }

        if let Some(id_type) = self.network().detect(value) {
            self.emit_detection_metrics(start, &id_type);
            return Some(id_type);
        }

        if let Some(id_type) = self.financial().find(value) {
            self.emit_detection_metrics(start, &id_type);
            return Some(id_type);
        }

        // Note: government and credentials builders don't have detect() methods
        // They use specific detection methods like is_ssn(), contains_passwords(), etc.

        record(
            metric_names::detect_ms(),
            start.elapsed().as_micros() as f64 / 1000.0,
        );
        None
    }

    /// Scan text for all identifiers
    ///
    /// Comprehensive scan that returns all identifier matches found in text.
    #[must_use]
    pub fn scan_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();

        // Use default capacity of 1000 matches
        let scanner = StreamingScanner::new(1000);
        let count = scanner.scan_all_identifiers(text);

        record(
            metric_names::scan_ms(),
            start.elapsed().as_micros() as f64 / 1000.0,
        );

        if count > 0 {
            increment_by(metric_names::detected(), count as u64);
        }

        // Drain and convert matches from primitive to local types
        let matches: Vec<IdentifierMatch> = scanner.drain();

        if !matches.is_empty() {
            // Check for sensitive types
            let has_pii = matches.iter().any(|m| is_pii_type(&m.identifier_type));
            if has_pii {
                increment_by(metric_names::pii_found(), 1);
                observe::warn(
                    "pii_detected_in_scan",
                    format!("PII detected: {} identifiers found", matches.len()),
                );
            }
        }

        matches
    }

    /// Check if text contains any identifiers
    #[must_use]
    pub fn is_identifiers_present(&self, text: &str) -> bool {
        !self.scan_text(text).is_empty()
    }

    /// Check if text contains PII (personally identifiable information)
    #[must_use]
    pub fn is_pii_present(&self, text: &str) -> bool {
        // Check personal identifiers (emails, phones, names)
        self.personal().is_pii_present(text)
            // Check government identifiers (SSNs, etc.) - scan for matches
            || !self.government().find_ssns_in_text(text).is_empty()
            // Check financial identifiers (credit cards, etc.) - scan for matches
            || !self.financial().detect_credit_cards_in_text(text).is_empty()
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    fn emit_detection_metrics(&self, start: Instant, id_type: &IdentifierType) {
        record(
            metric_names::detect_ms(),
            start.elapsed().as_micros() as f64 / 1000.0,
        );
        increment_by(metric_names::detected(), 1);

        if is_pii_type(id_type) {
            increment_by(metric_names::pii_found(), 1);
            observe::debug(
                "identifier_detected",
                format!("Identifier type detected: {:?}", id_type),
            );
        }
    }
}

/// Check if identifier type is PII
fn is_pii_type(id_type: &IdentifierType) -> bool {
    matches!(
        id_type,
        IdentifierType::Email
            | IdentifierType::PhoneNumber
            | IdentifierType::Ssn
            | IdentifierType::PersonalName
            | IdentifierType::Birthdate
            | IdentifierType::CreditCard
            | IdentifierType::BankAccount
            | IdentifierType::DriverLicense
            | IdentifierType::Passport
            | IdentifierType::MedicalRecordNumber
            | IdentifierType::HealthInsurance
            | IdentifierType::GPSCoordinate
            | IdentifierType::StreetAddress
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_identifier_builder_creation() {
        let builder = IdentifierBuilder::new();
        assert!(builder.detect("user@example.com").is_some());
    }

    #[test]
    fn test_domain_builder_access() {
        let builder = IdentifierBuilder::new();

        // Access domain builders
        let _personal = builder.personal();
        let _financial = builder.financial();
        let _government = builder.government();
        let _network = builder.network();
    }

    #[test]
    fn test_detect_email() {
        let builder = IdentifierBuilder::new();
        assert_eq!(
            builder.detect("user@example.com"),
            Some(IdentifierType::Email)
        );
    }

    #[test]
    fn test_detect_ip() {
        let builder = IdentifierBuilder::new();
        assert_eq!(
            builder.detect("192.168.1.1"),
            Some(IdentifierType::IpAddress)
        );
    }

    #[test]
    fn test_scan_text() {
        let builder = IdentifierBuilder::new();
        let matches = builder.scan_text("Contact: user@example.com, IP: 192.168.1.1");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_is_pii_present() {
        let builder = IdentifierBuilder::new();
        assert!(builder.is_pii_present("Email: user@example.com"));
        assert!(!builder.is_pii_present("Just some random text"));
    }
}
