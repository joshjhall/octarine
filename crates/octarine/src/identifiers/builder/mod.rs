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
mod confidence;
mod correlation;
mod credentials;
#[cfg(feature = "crypto-validation")]
mod crypto;
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
pub use confidence::ConfidenceBuilder;
pub use correlation::CorrelationBuilder;
pub use credentials::CredentialsBuilder;
#[cfg(feature = "crypto-validation")]
pub use crypto::CryptoBuilder;
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
use crate::primitives::identifiers::confidence::ConfidenceBuilder as PrimitiveConfidenceBuilder;

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
/// Use [`IdentifierBuilder::silent`] or [`IdentifierBuilder::with_events`] to
/// suppress all observe events and metrics. The silent flag propagates through
/// the domain accessors (`personal()`, `financial()`, etc.) so that
/// `IdentifierBuilder::silent().personal()` returns a silent
/// `PersonalBuilder`.
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
#[derive(Debug, Clone, Copy)]
pub struct IdentifierBuilder {
    emit_events: bool,
}

impl Default for IdentifierBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentifierBuilder {
    /// Create a new IdentifierBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self { emit_events: true }
    }

    /// Create an IdentifierBuilder that suppresses all observe events and metrics
    #[must_use]
    pub fn silent() -> Self {
        Self { emit_events: false }
    }

    /// Toggle observe event/metric emission
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // Domain Builder Access
    // ========================================================================

    /// Get personal identifier builder (emails, phones, names, birthdates)
    #[must_use]
    pub fn personal(&self) -> PersonalBuilder {
        PersonalBuilder::new().with_events(self.emit_events)
    }

    /// Get financial identifier builder (credit cards, bank accounts)
    #[must_use]
    pub fn financial(&self) -> FinancialBuilder {
        FinancialBuilder::new().with_events(self.emit_events)
    }

    /// Get government identifier builder (SSNs, driver licenses, passports)
    #[must_use]
    pub fn government(&self) -> GovernmentBuilder {
        GovernmentBuilder::new().with_events(self.emit_events)
    }

    /// Get network identifier builder (IPs, MACs, URLs, UUIDs)
    #[must_use]
    pub fn network(&self) -> NetworkBuilder {
        NetworkBuilder::new().with_events(self.emit_events)
    }

    /// Get credentials identifier builder (API keys, passwords, tokens)
    #[must_use]
    pub fn credentials(&self) -> CredentialsBuilder {
        CredentialsBuilder::new().with_events(self.emit_events)
    }

    /// Get location identifier builder (addresses, GPS coordinates)
    #[must_use]
    pub fn location(&self) -> LocationBuilder {
        LocationBuilder::new().with_events(self.emit_events)
    }

    /// Get token identifier builder (JWTs, OAuth tokens)
    #[must_use]
    pub fn token(&self) -> TokenBuilder {
        TokenBuilder::new().with_events(self.emit_events)
    }

    /// Get medical identifier builder (MRNs, health insurance)
    #[must_use]
    pub fn medical(&self) -> MedicalBuilder {
        MedicalBuilder::new().with_events(self.emit_events)
    }

    /// Get biometric identifier builder (fingerprints, facial recognition)
    #[must_use]
    pub fn biometric(&self) -> BiometricBuilder {
        BiometricBuilder::new().with_events(self.emit_events)
    }

    /// Get organizational identifier builder (employee IDs, badge numbers)
    #[must_use]
    pub fn organizational(&self) -> OrganizationalBuilder {
        OrganizationalBuilder::new().with_events(self.emit_events)
    }

    /// Get database identifier builder (connection strings)
    #[must_use]
    pub fn database(&self) -> DatabaseBuilder {
        DatabaseBuilder::new().with_events(self.emit_events)
    }

    /// Get environment identifier builder (env vars)
    #[must_use]
    pub fn environment(&self) -> EnvironmentBuilder {
        EnvironmentBuilder::new().with_events(self.emit_events)
    }

    /// Get generic identifier builder
    #[must_use]
    pub fn generic(&self) -> GenericBuilder {
        GenericBuilder::new().with_events(self.emit_events)
    }

    /// Get metrics identifier builder
    #[must_use]
    pub fn metrics(&self) -> MetricsBuilder {
        MetricsBuilder::new().with_events(self.emit_events)
    }

    /// Get crypto identifier builder (keys, certificates, signatures)
    #[cfg(feature = "crypto-validation")]
    #[must_use]
    pub fn crypto(&self) -> CryptoBuilder {
        CryptoBuilder::new().with_events(self.emit_events)
    }

    /// Get entropy identifier builder (high-entropy string detection)
    #[must_use]
    pub fn entropy(&self) -> EntropyBuilder {
        EntropyBuilder::new().with_events(self.emit_events)
    }

    /// Get confidence scoring builder (context-aware confidence boosting)
    #[must_use]
    pub fn confidence(&self) -> ConfidenceBuilder {
        ConfidenceBuilder::new().with_events(self.emit_events)
    }

    /// Get credential pair correlation builder
    #[must_use]
    pub fn correlation(&self) -> CorrelationBuilder {
        CorrelationBuilder::new().with_events(self.emit_events)
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

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
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

        if self.emit_events {
            record(
                metric_names::scan_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if count > 0 {
                increment_by(metric_names::detected(), count as u64);
            }
        }

        // Drain and convert matches from primitive to local types
        let mut matches: Vec<IdentifierMatch> = scanner.drain();

        // Context-aware confidence scoring pass: boost confidence when
        // contextual keywords are found near each match
        if !matches.is_empty() {
            let confidence_scorer = PrimitiveConfidenceBuilder::new();
            for m in &mut matches {
                let context_present =
                    confidence_scorer.is_context_present(text, m.start, m.end, &m.identifier_type);
                m.confidence = m.confidence.clone().with_context_boost(context_present);
            }
        }

        if self.emit_events && !matches.is_empty() {
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
        if self.emit_events {
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
        assert!(builder.emit_events);
        assert!(builder.detect("user@example.com").is_some());

        let silent = IdentifierBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events_toggle() {
        let b = IdentifierBuilder::new().with_events(false);
        assert!(!b.emit_events);

        let b = IdentifierBuilder::silent().with_events(true);
        assert!(b.emit_events);
    }

    #[test]
    fn test_silent_propagates_to_domain_accessors() {
        let s = IdentifierBuilder::silent();
        assert!(!s.personal().emit_events());
        assert!(!s.financial().emit_events());
        assert!(!s.network().emit_events());

        let n = IdentifierBuilder::new();
        assert!(n.personal().emit_events());
        assert!(n.financial().emit_events());
        assert!(n.network().emit_events());
    }

    #[test]
    fn test_silent_mode_does_not_panic() {
        // Structural test only — behavioral delta-assertions race with
        // concurrent tests across the workspace.
        let s = IdentifierBuilder::silent();
        assert!(!s.emit_events);

        // Functional sanity: silent builder still detects identifiers.
        assert_eq!(s.detect("user@example.com"), Some(IdentifierType::Email));
        let _ = s.scan_text("Email: user@example.com");
        assert!(s.is_pii_present("Email: user@example.com"));
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
