//! Identifiers facade for unified PII detection access
//!
//! The `Identifiers` facade provides a single entry point to all identifier-related
//! operations in octarine. It answers the question: "What is it? Is it PII?"
//!
//! # Example
//!
//! ```
//! use octarine::identifiers::Identifiers;
//!
//! let identifiers = Identifiers::new();
//!
//! // Personal identifiers (emails, phones, SSNs)
//! let personal = identifiers.personal();
//!
//! // Financial identifiers (credit cards, bank accounts)
//! let financial = identifiers.financial();
//!
//! // Network identifiers (IPs, UUIDs, hostnames)
//! let network = identifiers.network();
//! ```

use super::builder::{
    BiometricBuilder, CredentialsBuilder, DatabaseBuilder, EnvironmentBuilder, FinancialBuilder,
    GenericBuilder, GovernmentBuilder, IdentifierBuilder, LocationBuilder, MedicalBuilder,
    MetricsBuilder, NetworkBuilder, OrganizationalBuilder, PersonalBuilder, TokenBuilder,
};
use super::types::{IdentifierMatch, IdentifierType};

/// Unified facade for all identifier operations (CLASSIFICATION concern)
///
/// The Identifiers facade provides access to domain-specific identifier builders
/// that handle detection, validation, and redaction of PII and other identifiers.
///
/// All operations automatically emit observe events for audit trails.
///
/// # Domains
///
/// | Domain | Builder | Compliance |
/// |--------|---------|------------|
/// | `personal` | [`PersonalBuilder`] | GDPR, CCPA |
/// | `financial` | [`FinancialBuilder`] | PCI-DSS |
/// | `government` | [`GovernmentBuilder`] | GDPR, CCPA |
/// | `network` | [`NetworkBuilder`] | SOC2 |
/// | `credentials` | [`CredentialsBuilder`] | SOC2, PCI-DSS |
/// | `location` | [`LocationBuilder`] | GDPR |
/// | `token` | [`TokenBuilder`] | SOC2 |
/// | `medical` | [`MedicalBuilder`] | HIPAA |
/// | `biometric` | [`BiometricBuilder`] | BIPA, GDPR |
/// | `organizational` | [`OrganizationalBuilder`] | SOC2 |
/// | `database` | [`DatabaseBuilder`] | SOC2 |
/// | `environment` | [`EnvironmentBuilder`] | SOC2 |
/// | `generic` | [`GenericBuilder`] | - |
/// | `metrics` | [`MetricsBuilder`] | - |
///
/// # Example
///
/// ```
/// use octarine::identifiers::Identifiers;
///
/// let identifiers = Identifiers::new();
///
/// // Check if text is an email
/// if identifiers.personal().is_email("user@example.com") {
///     // Handle email
/// }
///
/// // Detect credit cards in text
/// let cards = identifiers.financial().detect_credit_cards_in_text("Card: 4242424242424242");
///
/// // Scan for any identifiers
/// let matches = identifiers.scan_text("Email: user@example.com, SSN: 123-45-6789");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Identifiers {
    inner: IdentifierBuilder,
}

impl Identifiers {
    /// Create a new Identifiers facade
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: IdentifierBuilder::new(),
        }
    }

    /// Access personal identifier operations
    ///
    /// Handles detection, validation, and redaction for:
    /// - Email addresses
    /// - Phone numbers (with regional formats)
    /// - Names and birthdates
    ///
    /// Compliance: GDPR Art. 4(1), CCPA Personal Info
    ///
    /// # Example
    ///
    /// ```
    /// use octarine::identifiers::Identifiers;
    ///
    /// let identifiers = Identifiers::new();
    /// let personal = identifiers.personal();
    ///
    /// if personal.is_email("user@example.com") {
    ///     // Handle email
    /// }
    ///
    /// let phones = personal.find_phones_in_text("Call me at 555-123-4567");
    /// ```
    #[must_use]
    pub fn personal(&self) -> PersonalBuilder {
        self.inner.personal()
    }

    /// Access financial identifier operations
    ///
    /// Handles detection, validation, and redaction for:
    /// - Credit card numbers (with Luhn validation)
    /// - Bank account numbers
    /// - Routing numbers
    ///
    /// Compliance: PCI-DSS Requirement 3
    ///
    /// # Example
    ///
    /// ```
    /// use octarine::identifiers::Identifiers;
    ///
    /// let identifiers = Identifiers::new();
    /// let financial = identifiers.financial();
    ///
    /// if financial.is_credit_card("4242424242424242") {
    ///     // Handle credit card
    /// }
    /// ```
    #[must_use]
    pub fn financial(&self) -> FinancialBuilder {
        self.inner.financial()
    }

    /// Access government identifier operations
    ///
    /// Handles detection, validation, and redaction for:
    /// - Social Security Numbers (SSN)
    /// - Driver's licenses
    /// - Passport numbers
    /// - Vehicle Identification Numbers (VIN)
    /// - Employer Identification Numbers (EIN)
    ///
    /// Compliance: GDPR Art. 4(1), CCPA Personal Info
    #[must_use]
    pub fn government(&self) -> GovernmentBuilder {
        self.inner.government()
    }

    /// Access network identifier operations
    ///
    /// Handles detection and validation for:
    /// - IP addresses (IPv4, IPv6)
    /// - MAC addresses
    /// - UUIDs (all versions)
    /// - Hostnames
    /// - Ports
    #[must_use]
    pub fn network(&self) -> NetworkBuilder {
        self.inner.network()
    }

    /// Access credential identifier operations
    ///
    /// Handles detection and redaction for:
    /// - API keys (AWS, Azure, GCP, etc.)
    /// - Passwords
    /// - Tokens
    /// - Session IDs
    ///
    /// Compliance: SOC2 CC6.1, PCI-DSS Requirement 3
    #[must_use]
    pub fn credentials(&self) -> CredentialsBuilder {
        self.inner.credentials()
    }

    /// Access location identifier operations
    ///
    /// Handles detection, validation, and redaction for:
    /// - Street addresses
    /// - GPS coordinates
    /// - Postal codes
    ///
    /// Compliance: GDPR (location data is personal data)
    #[must_use]
    pub fn location(&self) -> LocationBuilder {
        self.inner.location()
    }

    /// Access token identifier operations
    ///
    /// Handles detection and validation for:
    /// - JWT tokens
    /// - OAuth tokens
    /// - Session tokens
    #[must_use]
    pub fn token(&self) -> TokenBuilder {
        self.inner.token()
    }

    /// Access medical identifier operations
    ///
    /// Handles detection, validation, and redaction for:
    /// - Medical Record Numbers (MRN)
    /// - Health insurance IDs
    /// - NPI numbers
    ///
    /// Compliance: HIPAA PHI
    #[must_use]
    pub fn medical(&self) -> MedicalBuilder {
        self.inner.medical()
    }

    /// Access biometric identifier operations
    ///
    /// Handles detection and redaction for:
    /// - Fingerprint templates
    /// - Facial recognition IDs
    /// - Voice print IDs
    /// - Iris scan IDs
    /// - DNA markers
    ///
    /// Compliance: BIPA, GDPR Art. 9
    #[must_use]
    pub fn biometric(&self) -> BiometricBuilder {
        self.inner.biometric()
    }

    /// Access organizational identifier operations
    ///
    /// Handles detection and validation for:
    /// - Employee IDs
    /// - Badge numbers
    /// - Department codes
    #[must_use]
    pub fn organizational(&self) -> OrganizationalBuilder {
        self.inner.organizational()
    }

    /// Access database identifier operations
    ///
    /// Handles detection and redaction for:
    /// - Connection strings
    /// - Database URLs
    #[must_use]
    pub fn database(&self) -> DatabaseBuilder {
        self.inner.database()
    }

    /// Access environment identifier operations
    ///
    /// Handles detection for:
    /// - Environment variables
    /// - Configuration values
    #[must_use]
    pub fn environment(&self) -> EnvironmentBuilder {
        self.inner.environment()
    }

    /// Access generic identifier operations
    ///
    /// Handles generic identifier validation and detection
    #[must_use]
    pub fn generic(&self) -> GenericBuilder {
        self.inner.generic()
    }

    /// Access metrics identifier operations
    ///
    /// Handles metrics and telemetry identifiers
    #[must_use]
    pub fn metrics(&self) -> MetricsBuilder {
        self.inner.metrics()
    }

    /// Detect the type of an identifier
    ///
    /// Returns the detected identifier type or `None` if not recognized.
    ///
    /// # Example
    ///
    /// ```
    /// use octarine::identifiers::Identifiers;
    ///
    /// let identifiers = Identifiers::new();
    ///
    /// let id_type = identifiers.detect("user@example.com");
    /// ```
    #[must_use]
    pub fn detect(&self, value: &str) -> Option<IdentifierType> {
        self.inner.detect(value)
    }

    /// Scan text for all identifiers
    ///
    /// Returns a list of all detected identifiers with their positions.
    ///
    /// # Example
    ///
    /// ```
    /// use octarine::identifiers::Identifiers;
    ///
    /// let identifiers = Identifiers::new();
    ///
    /// let matches = identifiers.scan_text("Email: user@example.com, SSN: 123-45-6789");
    /// for m in matches {
    ///     println!("Found {:?} at {}..{}", m.identifier_type, m.start, m.end);
    /// }
    /// ```
    pub fn scan_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.scan_text(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identifiers_facade_creation() {
        let identifiers = Identifiers::new();
        // Verify we can access each builder
        let _ = identifiers.personal();
        let _ = identifiers.financial();
        let _ = identifiers.government();
        let _ = identifiers.network();
        let _ = identifiers.credentials();
        let _ = identifiers.location();
        let _ = identifiers.token();
        let _ = identifiers.medical();
        let _ = identifiers.biometric();
        let _ = identifiers.organizational();
        let _ = identifiers.database();
        let _ = identifiers.environment();
        let _ = identifiers.generic();
        let _ = identifiers.metrics();
    }

    #[test]
    fn test_identifiers_is_copy() {
        let identifiers = Identifiers::new();
        let copy = identifiers;
        let _ = identifiers.personal();
        let _ = copy.personal();
    }

    #[test]
    fn test_identifiers_is_default() {
        let identifiers = Identifiers::default();
        let _ = identifiers.personal();
    }

    #[test]
    fn test_personal_email_detection() {
        let identifiers = Identifiers::new();
        assert!(identifiers.personal().is_email("user@example.com"));
        assert!(!identifiers.personal().is_email("not-an-email"));
    }

    #[test]
    fn test_financial_credit_card_detection() {
        let identifiers = Identifiers::new();
        assert!(identifiers.financial().is_credit_card("4242424242424242"));
    }

    #[test]
    fn test_network_ip_detection() {
        let identifiers = Identifiers::new();
        assert!(identifiers.network().is_ipv4("192.168.1.1"));
        assert!(identifiers.network().is_ipv6("::1"));
    }

    #[test]
    fn test_detect_email() {
        let identifiers = Identifiers::new();
        let detected = identifiers.detect("user@example.com");
        assert!(detected.is_some());
    }

    #[test]
    fn test_scan_text() {
        let identifiers = Identifiers::new();
        let matches = identifiers.scan_text("Email: user@example.com");
        assert!(!matches.is_empty());
    }
}
