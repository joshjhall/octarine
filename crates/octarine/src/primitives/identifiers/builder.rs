//! Builder pattern for identifier operations
//!
//! Provides the main entry point for all identifier detection, validation,
//! sanitization, and conversion operations.
//!
//! ## Design Philosophy
//!
//! - **Single entry point**: All identifier operations through one builder
//! - **Domain delegation**: Routes to domain-specific builders (personal, financial, etc.)
//! - **No business logic**: Pure interface, all work done by domain modules

use super::biometric::BiometricIdentifierBuilder;
use super::credentials::CredentialIdentifierBuilder;
use super::database::DatabaseBuilder;
use super::environment::EnvironmentBuilder;
use super::financial::FinancialIdentifierBuilder;
use super::generic::GenericBuilder;
use super::government::GovernmentIdentifierBuilder;
use super::location::LocationIdentifierBuilder;
use super::medical::MedicalIdentifierBuilder;
use super::metrics::MetricsBuilder;
use super::network::NetworkIdentifierBuilder;
use super::organizational::OrganizationalIdentifierBuilder;
use super::personal::PersonalIdentifierBuilder;
use super::token::TokenIdentifierBuilder;

/// Builder for all identifier operations
///
/// Provides access to domain-specific builders for detection, validation,
/// sanitization, and conversion of identifiers.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::IdentifierBuilder;
///
/// let builder = IdentifierBuilder::new();
///
/// // Access personal identifier operations
/// let personal = builder.personal();
/// let has_pii = personal.is_pii_present("user@example.com");
/// ```
#[derive(Debug, Clone, Default)]
pub struct IdentifierBuilder {
    personal: PersonalIdentifierBuilder,
    financial: FinancialIdentifierBuilder,
    government: GovernmentIdentifierBuilder,
    network: NetworkIdentifierBuilder,
    credentials: CredentialIdentifierBuilder,
    token: TokenIdentifierBuilder,
    medical: MedicalIdentifierBuilder,
    biometric: BiometricIdentifierBuilder,
    organizational: OrganizationalIdentifierBuilder,
    location: LocationIdentifierBuilder,
    database: DatabaseBuilder,
    environment: EnvironmentBuilder,
    generic: GenericBuilder,
    metrics: MetricsBuilder,
}

impl IdentifierBuilder {
    /// Create a new IdentifierBuilder
    #[must_use]
    pub fn new() -> Self {
        Self {
            personal: PersonalIdentifierBuilder::new(),
            financial: FinancialIdentifierBuilder::new(),
            government: GovernmentIdentifierBuilder::new(),
            network: NetworkIdentifierBuilder::new(),
            credentials: CredentialIdentifierBuilder::new(),
            token: TokenIdentifierBuilder::new(),
            medical: MedicalIdentifierBuilder::new(),
            biometric: BiometricIdentifierBuilder::new(),
            organizational: OrganizationalIdentifierBuilder::new(),
            location: LocationIdentifierBuilder::new(),
            database: DatabaseBuilder::new(),
            environment: EnvironmentBuilder::new(),
            generic: GenericBuilder::new(),
            metrics: MetricsBuilder::new(),
        }
    }

    /// Get the personal identifier builder
    ///
    /// Access detection, validation, sanitization, and conversion
    /// for personal identifiers (emails, phones, names, birthdates).
    #[must_use]
    pub fn personal(&self) -> &PersonalIdentifierBuilder {
        &self.personal
    }

    /// Get the financial identifier builder
    ///
    /// Access detection, validation, sanitization, and conversion
    /// for financial identifiers (credit cards, bank accounts, routing numbers).
    #[must_use]
    pub fn financial(&self) -> &FinancialIdentifierBuilder {
        &self.financial
    }

    /// Get the government identifier builder
    ///
    /// Access detection, validation, sanitization, and conversion
    /// for government identifiers (SSNs, tax IDs, driver licenses, passports, VINs).
    #[must_use]
    pub fn government(&self) -> &GovernmentIdentifierBuilder {
        &self.government
    }

    /// Get the network identifier builder
    ///
    /// Access detection, validation, sanitization, and conversion
    /// for network identifiers (IPs, MACs, URLs, UUIDs).
    #[must_use]
    pub fn network(&self) -> &NetworkIdentifierBuilder {
        &self.network
    }

    /// Get the credentials identifier builder
    ///
    /// Access detection, validation, and sanitization
    /// for credential identifiers (passwords, PINs, security answers, passphrases).
    #[must_use]
    pub fn credentials(&self) -> &CredentialIdentifierBuilder {
        &self.credentials
    }

    /// Get the token identifier builder
    ///
    /// Access detection, validation, and sanitization
    /// for token identifiers (JWTs, API keys, OAuth tokens, SSH keys).
    #[must_use]
    pub fn token(&self) -> &TokenIdentifierBuilder {
        &self.token
    }

    /// Get the medical identifier builder
    ///
    /// Access detection, validation, and sanitization
    /// for medical identifiers (MRNs, NPIs, prescriptions, insurance IDs).
    #[must_use]
    pub fn medical(&self) -> &MedicalIdentifierBuilder {
        &self.medical
    }

    /// Get the biometric identifier builder
    ///
    /// Access detection, validation, and sanitization
    /// for biometric identifiers (fingerprints, facial recognition, iris scans).
    #[must_use]
    pub fn biometric(&self) -> &BiometricIdentifierBuilder {
        &self.biometric
    }

    /// Get the organizational identifier builder
    ///
    /// Access detection, validation, and sanitization
    /// for organizational identifiers (employee IDs, student IDs, badge numbers).
    #[must_use]
    pub fn organizational(&self) -> &OrganizationalIdentifierBuilder {
        &self.organizational
    }

    /// Get the location identifier builder
    ///
    /// Access detection, validation, and sanitization
    /// for location identifiers (GPS coordinates, addresses, postal codes).
    #[must_use]
    pub fn location(&self) -> &LocationIdentifierBuilder {
        &self.location
    }

    /// Get the database identifier builder
    ///
    /// Access detection and validation for database identifiers
    /// (table names, column names, schema names).
    #[must_use]
    pub fn database(&self) -> &DatabaseBuilder {
        &self.database
    }

    /// Get the environment variable identifier builder
    ///
    /// Access detection and validation for environment variable names.
    #[must_use]
    pub fn environment(&self) -> &EnvironmentBuilder {
        &self.environment
    }

    /// Get the generic identifier builder
    ///
    /// Access detection and validation for generic identifiers
    /// (API keys, config keys, variable names).
    #[must_use]
    pub fn generic(&self) -> &GenericBuilder {
        &self.generic
    }

    /// Get the metrics identifier builder
    ///
    /// Access detection, validation, and sanitization for metric names
    /// and labels (Prometheus, StatsD, OpenMetrics compatible).
    #[must_use]
    pub fn metrics(&self) -> &MetricsBuilder {
        &self.metrics
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::primitives::identifiers::IdentifierType;

    #[test]
    fn test_builder_creation() {
        let builder = IdentifierBuilder::new();
        assert!(builder.personal().is_pii("user@example.com"));
    }

    #[test]
    fn test_personal_access() {
        let builder = IdentifierBuilder::new();
        let personal = builder.personal();

        assert_eq!(
            personal.find("user@example.com"),
            Some(IdentifierType::Email)
        );
    }

    #[test]
    fn test_default() {
        let builder = IdentifierBuilder::default();
        assert!(builder.personal().is_email("test@example.com"));
    }

    #[test]
    fn test_financial_access() {
        let builder = IdentifierBuilder::new();
        let financial = builder.financial();

        assert_eq!(
            financial.find("4242424242424242"),
            Some(IdentifierType::CreditCard)
        );
    }

    #[test]
    fn test_financial_credit_card() {
        let builder = IdentifierBuilder::new();
        assert!(builder.financial().is_credit_card("4242424242424242"));
    }

    #[test]
    fn test_financial_routing_number() {
        let builder = IdentifierBuilder::new();
        assert!(builder.financial().is_routing_number("121000358"));
    }

    #[test]
    fn test_government_access() {
        let builder = IdentifierBuilder::new();
        let government = builder.government();

        assert!(government.is_ssn("900-00-0001"));
    }

    #[test]
    fn test_government_ssn_validation() {
        let builder = IdentifierBuilder::new();
        // Valid SSN format (not a test pattern)
        assert!(builder.government().validate_ssn("234-56-7890").is_ok());
        // Test pattern should be rejected
        assert!(builder.government().validate_ssn("123-45-6789").is_err());
    }

    #[test]
    fn test_government_ssn_redaction() {
        use crate::primitives::identifiers::SsnRedactionStrategy;
        let builder = IdentifierBuilder::new();
        assert_eq!(
            builder
                .government()
                .redact_ssn_with_strategy("900-00-0001", SsnRedactionStrategy::Token),
            "[SSN]"
        );
        assert_eq!(
            builder
                .government()
                .redact_ssn_with_strategy("900-00-0001", SsnRedactionStrategy::LastFour),
            "***-**-0001"
        );
    }

    #[test]
    fn test_government_vin() {
        let builder = IdentifierBuilder::new();
        assert!(builder.government().is_vehicle_id("1HGBH41JXMN109186"));
        assert!(
            builder
                .government()
                .validate_vin("1HGBH41JXMN109186")
                .is_ok()
        );
    }

    // =========================================================================
    // Database Builder Tests
    // =========================================================================

    #[test]
    fn test_database_access() {
        let builder = IdentifierBuilder::new();
        let db = builder.database();

        assert!(db.is_valid_identifier("users"));
        assert!(!db.is_valid_identifier("select")); // Reserved keyword
    }

    #[test]
    fn test_database_validation() {
        let builder = IdentifierBuilder::new();
        assert!(builder.database().validate_identifier("users").is_ok());
        assert!(builder.database().validate_identifier("drop").is_err());
    }

    // =========================================================================
    // Environment Builder Tests
    // =========================================================================

    #[test]
    fn test_environment_access() {
        let builder = IdentifierBuilder::new();
        let env = builder.environment();

        assert!(env.is_valid_env_var("MY_APP_CONFIG"));
        assert!(!env.is_valid_env_var("LD_PRELOAD")); // Critical var
    }

    #[test]
    fn test_environment_validation() {
        let builder = IdentifierBuilder::new();
        assert!(builder.environment().validate_env_var("DEBUG").is_ok());
        assert!(builder.environment().validate_env_var("PATH").is_err());
    }

    // =========================================================================
    // Generic Builder Tests
    // =========================================================================

    #[test]
    fn test_generic_access() {
        let builder = IdentifierBuilder::new();
        let generator = builder.generic();

        assert!(generator.is_valid_identifier("api-key-123"));
        assert!(!generator.is_valid_identifier("$(whoami)")); // Injection
    }

    #[test]
    fn test_generic_validation() {
        let builder = IdentifierBuilder::new();
        assert!(builder.generic().validate_identifier("config_key").is_ok());
        assert!(builder.generic().validate_identifier("").is_err());
    }

    // =========================================================================
    // Metrics Builder Tests
    // =========================================================================

    #[test]
    fn test_metrics_access() {
        let builder = IdentifierBuilder::new();
        let metrics = builder.metrics();

        assert!(metrics.is_name("api.requests.total"));
        assert!(!metrics.is_name("api-requests")); // Hyphens not allowed
    }

    #[test]
    fn test_metrics_validation() {
        let builder = IdentifierBuilder::new();
        assert!(builder.metrics().validate_name("cpu_usage").is_ok());
        assert!(builder.metrics().validate_name("").is_err());
    }

    #[test]
    fn test_metrics_normalization() {
        let builder = IdentifierBuilder::new();
        assert_eq!(
            builder.metrics().normalize_name("API-Requests"),
            "api_requests"
        );
    }

    #[test]
    fn test_metrics_sanitization() {
        let builder = IdentifierBuilder::new();
        assert!(builder.metrics().sanitize_name("api_requests").is_ok());
        // Sanitization rejects empty strings
        assert!(builder.metrics().sanitize_name("").is_err());
        // Sanitization rejects injection patterns
        assert!(builder.metrics().sanitize_name("$(whoami)").is_err());
    }
}
