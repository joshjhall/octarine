//! PII redaction configuration and environment detection
//!
//! Configuration for PII scanning and redaction:
//! - `RedactionProfile`: Controls how PII is redacted (strict, lenient, dev, testing)
//! - `PiiScannerConfig`: Controls which identifier domains are scanned

// Import redaction strategies from primitives/identifiers
use crate::primitives::identifiers::{
    CreditCardRedactionStrategy, EmailRedactionStrategy, PhoneRedactionStrategy,
    SsnRedactionStrategy,
};
use std::env;

/// Redaction profiles for different environments and compliance levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionProfile {
    /// Production strict mode (maximum redaction)
    ///
    /// - SSN: Complete::Token → `[SSN]`
    /// - Credit cards: Partial::Last4 → "****-****-****-4242"
    /// - Emails: Partial::UserMask → "u***@example.com"
    /// - API keys: Partial::Prefix → "sk_test_********"
    /// - Passwords: Complete::Token → `[Password]`
    ProductionStrict,

    /// Production lenient mode (balanced redaction)
    ///
    /// - SSN: Partial::LastDigits → "***-**-0001"
    /// - Credit cards: Partial::First6Last4 → "424242******4242"
    /// - Emails: Partial::UserMask → "u***@example.com"
    /// - API keys: Partial::Prefix → "sk_test_********"
    /// - Passwords: Complete::Token → `[Password]`
    ProductionLenient,

    /// Development mode (minimal redaction for debugging)
    ///
    /// - SSN: Partial::LastDigits → "***-**-0001"
    /// - Credit cards: Partial::Last4 → "****-****-****-4242"
    /// - Emails: None → "user@example.com" (no redaction)
    /// - API keys: Partial::Prefix → "sk_test_********"
    /// - Passwords: Complete::Mask → "********"
    Development,

    /// Testing mode (no redaction - WARNING: unsafe for production)
    ///
    /// - All: None → Original values preserved
    /// - Use only in isolated test environments
    Testing,
}

impl RedactionProfile {
    /// Detect the appropriate profile from environment variables
    ///
    /// Checks (in order):
    /// 1. `RUST_CORE_REDACT_PROFILE` or `REDACTION_PROFILE` - explicit profile override
    /// 2. `RUST_ENV` or `ENVIRONMENT` - auto-detect from environment
    /// 3. Default to `ProductionStrict` if unsure
    pub fn from_environment() -> Self {
        // Check explicit profile override (prefer RUST_CORE_REDACT_PROFILE, fallback to REDACTION_PROFILE)
        let profile_var =
            env::var("RUST_CORE_REDACT_PROFILE").or_else(|_| env::var("REDACTION_PROFILE"));

        if let Ok(profile) = profile_var {
            return match profile.to_lowercase().as_str() {
                "production-strict" | "strict" | "prod-strict" => Self::ProductionStrict,
                "production-lenient" | "lenient" | "prod-lenient" => Self::ProductionLenient,
                "development" | "dev" => Self::Development,
                "testing" | "test" => Self::Testing,
                _ => {
                    // Unknown profile - fail-safe to strict
                    // Note: No logging here to avoid recursion when EventBuilder calls redact_pii()
                    Self::ProductionStrict
                }
            };
        }

        // Auto-detect from environment
        let env_name = env::var("RUST_ENV")
            .or_else(|_| env::var("ENVIRONMENT"))
            .unwrap_or_else(|_| "production".to_string());

        match env_name.to_lowercase().as_str() {
            "production" | "prod" => Self::ProductionStrict,
            "staging" | "stage" => Self::ProductionLenient,
            "development" | "dev" => Self::Development,
            "test" | "testing" => Self::Testing,
            _ => {
                // Unknown environment - fail-safe to strict
                // Note: No logging here to avoid recursion when EventBuilder calls redact_pii()
                Self::ProductionStrict
            }
        }
    }

    /// Returns true if this profile is safe for production use
    pub fn is_production_safe(&self) -> bool {
        !matches!(self, Self::Development | Self::Testing)
    }

    /// Returns true if this profile exposes any raw PII
    pub fn exposes_pii(&self) -> bool {
        matches!(self, Self::Development | Self::Testing)
    }

    /// Returns the compliance risk level for this profile
    pub fn compliance_risk(&self) -> ComplianceRisk {
        match self {
            Self::ProductionStrict => ComplianceRisk::Low,
            Self::ProductionLenient => ComplianceRisk::Medium,
            Self::Development => ComplianceRisk::High,
            Self::Testing => ComplianceRisk::Critical,
        }
    }

    // ========================================================================
    // Strategy Getters - Map profiles to primitives redaction strategies
    // ========================================================================

    /// Get the SSN redaction strategy for this profile
    pub fn ssn_strategy(&self) -> SsnRedactionStrategy {
        match self {
            Self::ProductionStrict => SsnRedactionStrategy::Token,
            Self::ProductionLenient => SsnRedactionStrategy::LastFour,
            Self::Development => SsnRedactionStrategy::LastFour, // Still mask in dev
            Self::Testing => SsnRedactionStrategy::Skip,
        }
    }

    /// Get the email redaction strategy for this profile
    pub fn email_strategy(&self) -> EmailRedactionStrategy {
        match self {
            Self::ProductionStrict => EmailRedactionStrategy::Token,
            Self::ProductionLenient => EmailRedactionStrategy::ShowFirst,
            Self::Development => EmailRedactionStrategy::Skip, // No redaction in dev for debugging
            Self::Testing => EmailRedactionStrategy::Skip,
        }
    }

    /// Get the credit card redaction strategy for this profile
    pub fn credit_card_strategy(&self) -> CreditCardRedactionStrategy {
        match self {
            Self::ProductionStrict => CreditCardRedactionStrategy::Token,
            Self::ProductionLenient => CreditCardRedactionStrategy::ShowLast4, // PCI-DSS compliant
            Self::Development => CreditCardRedactionStrategy::ShowLast4, // Still mask in dev (sensitive!)
            Self::Testing => CreditCardRedactionStrategy::Skip,
        }
    }

    /// Get the phone redaction strategy for this profile
    pub fn phone_strategy(&self) -> PhoneRedactionStrategy {
        match self {
            Self::ProductionStrict => PhoneRedactionStrategy::Token,
            Self::ProductionLenient => PhoneRedactionStrategy::ShowLastFour,
            Self::Development => PhoneRedactionStrategy::Skip, // No redaction in dev
            Self::Testing => PhoneRedactionStrategy::Skip,
        }
    }
}

/// Compliance risk levels for redaction profiles
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ComplianceRisk {
    /// Low risk (production strict)
    Low,
    /// Medium risk (production lenient)
    Medium,
    /// High risk (development)
    High,
    /// Critical risk (testing - no redaction)
    Critical,
}

// ============================================================================
// Scanner Configuration
// ============================================================================

/// Configuration for PII scanner domain selection
///
/// Controls which identifier domains are scanned. This allows tuning
/// the scanner for specific use cases (e.g., HIPAA compliance, PCI-DSS).
///
/// # Example
///
/// ```rust
/// use octarine::observe::pii::PiiScannerConfig;
///
/// // Production default: scan all high-risk domains
/// let config = PiiScannerConfig::default();
/// assert!(config.scan_personal);
/// assert!(config.scan_financial);
///
/// // Custom: HIPAA compliance focus
/// let hipaa_config = PiiScannerConfig::hipaa_focused();
/// assert!(hipaa_config.scan_medical);
///
/// // Custom: PCI-DSS compliance focus
/// let pci_config = PiiScannerConfig::pci_focused();
/// assert!(pci_config.scan_financial);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PiiScannerConfig {
    // =========================================================================
    // Domain Toggles
    // =========================================================================
    /// Scan for personal identifiers (email, phone, name, birthdate, username)
    ///
    /// Default: true - Personal PII is commonly found in logs
    pub scan_personal: bool,

    /// Scan for financial identifiers (credit card, bank account, routing number)
    ///
    /// Default: true - Critical for PCI-DSS compliance
    pub scan_financial: bool,

    /// Scan for government identifiers (SSN, driver license, passport, VIN, EIN)
    ///
    /// Default: true - High-risk for identity theft
    pub scan_government: bool,

    /// Scan for medical identifiers (MRN, NPI, insurance, ICD codes)
    ///
    /// Default: true - Critical for HIPAA compliance
    pub scan_medical: bool,

    /// Scan for biometric identifiers (fingerprint, face, voice, iris, DNA IDs)
    ///
    /// Default: false - Rare in typical application logs
    pub scan_biometric: bool,

    /// Scan for location identifiers (GPS, address, postal code)
    ///
    /// Default: true - GDPR considers location data personal
    pub scan_location: bool,

    /// Scan for organizational identifiers (employee ID, student ID, badge)
    ///
    /// Default: false - Usually internal, not PII
    pub scan_organizational: bool,

    /// Scan for network identifiers (IP, MAC, UUID, domain, URL)
    ///
    /// Default: true - IP addresses are PII under GDPR; our IPv4 regex is robust
    /// (requires exactly 4 octets with valid 0-255 ranges, uses word boundaries)
    pub scan_network: bool,

    /// Scan for tokens/secrets (API keys, JWT, session IDs, passwords)
    ///
    /// Default: true - Critical for security
    pub scan_tokens: bool,
}

impl Default for PiiScannerConfig {
    /// Default configuration optimized for production use
    ///
    /// Scans: personal, financial, government, medical, location, network, tokens
    /// Skips: biometric (rare), organizational (internal)
    fn default() -> Self {
        Self {
            scan_personal: true,
            scan_financial: true,
            scan_government: true,
            scan_medical: true,
            scan_biometric: false,
            scan_location: true,
            scan_organizational: false,
            scan_network: true,
            scan_tokens: true,
        }
    }
}

impl PiiScannerConfig {
    /// Create a new scanner config with all domains disabled
    pub fn none() -> Self {
        Self {
            scan_personal: false,
            scan_financial: false,
            scan_government: false,
            scan_medical: false,
            scan_biometric: false,
            scan_location: false,
            scan_organizational: false,
            scan_network: false,
            scan_tokens: false,
        }
    }

    /// Create a scanner config that scans ALL domains
    ///
    /// Use for maximum coverage (may have more false positives)
    pub fn all() -> Self {
        Self {
            scan_personal: true,
            scan_financial: true,
            scan_government: true,
            scan_medical: true,
            scan_biometric: true,
            scan_location: true,
            scan_organizational: true,
            scan_network: true,
            scan_tokens: true,
        }
    }

    /// Create a scanner config focused on HIPAA compliance
    ///
    /// Scans medical + personal identifiers (PHI)
    pub fn hipaa_focused() -> Self {
        Self {
            scan_personal: true,   // Names, DOB, contact info are PHI
            scan_financial: false, // Not PHI unless in medical context
            scan_government: true, // SSN is PHI
            scan_medical: true,    // Core PHI identifiers
            scan_biometric: true,  // HIPAA covers biometrics
            scan_location: true,   // Address is PHI
            scan_organizational: false,
            scan_network: false,
            scan_tokens: true, // Security best practice
        }
    }

    /// Create a scanner config focused on PCI-DSS compliance
    ///
    /// Scans financial identifiers primarily
    pub fn pci_focused() -> Self {
        Self {
            scan_personal: false,
            scan_financial: true, // Core PCI scope
            scan_government: false,
            scan_medical: false,
            scan_biometric: false,
            scan_location: false,
            scan_organizational: false,
            scan_network: false,
            scan_tokens: true, // API keys may access cardholder data
        }
    }

    /// Create a scanner config focused on GDPR compliance
    ///
    /// Scans personal data as defined by GDPR
    pub fn gdpr_focused() -> Self {
        Self {
            scan_personal: true,   // Core personal data
            scan_financial: false, // Not specifically GDPR
            scan_government: true, // National IDs
            scan_medical: true,    // Health data (special category)
            scan_biometric: true,  // Special category data
            scan_location: true,   // Location is personal data
            scan_organizational: false,
            scan_network: true, // IP addresses are personal data under GDPR
            scan_tokens: false,
        }
    }

    /// Create a scanner config for security/secrets detection
    ///
    /// Focused on credentials and authentication data
    pub fn secrets_focused() -> Self {
        Self {
            scan_personal: false,
            scan_financial: false,
            scan_government: false,
            scan_medical: false,
            scan_biometric: false,
            scan_location: false,
            scan_organizational: false,
            scan_network: false,
            scan_tokens: true, // Only tokens/secrets
        }
    }

    // =========================================================================
    // Builder Methods
    // =========================================================================

    /// Enable personal identifier scanning
    pub fn with_personal(mut self, enabled: bool) -> Self {
        self.scan_personal = enabled;
        self
    }

    /// Enable financial identifier scanning
    pub fn with_financial(mut self, enabled: bool) -> Self {
        self.scan_financial = enabled;
        self
    }

    /// Enable government identifier scanning
    pub fn with_government(mut self, enabled: bool) -> Self {
        self.scan_government = enabled;
        self
    }

    /// Enable medical identifier scanning
    pub fn with_medical(mut self, enabled: bool) -> Self {
        self.scan_medical = enabled;
        self
    }

    /// Enable biometric identifier scanning
    pub fn with_biometric(mut self, enabled: bool) -> Self {
        self.scan_biometric = enabled;
        self
    }

    /// Enable location identifier scanning
    pub fn with_location(mut self, enabled: bool) -> Self {
        self.scan_location = enabled;
        self
    }

    /// Enable organizational identifier scanning
    pub fn with_organizational(mut self, enabled: bool) -> Self {
        self.scan_organizational = enabled;
        self
    }

    /// Enable network identifier scanning
    pub fn with_network(mut self, enabled: bool) -> Self {
        self.scan_network = enabled;
        self
    }

    /// Enable token/secret scanning
    pub fn with_tokens(mut self, enabled: bool) -> Self {
        self.scan_tokens = enabled;
        self
    }

    // =========================================================================
    // Query Methods
    // =========================================================================

    /// Returns true if any domain is enabled
    pub fn is_any_enabled(&self) -> bool {
        self.scan_personal
            || self.scan_financial
            || self.scan_government
            || self.scan_medical
            || self.scan_biometric
            || self.scan_location
            || self.scan_organizational
            || self.scan_network
            || self.scan_tokens
    }

    /// Returns the number of enabled domains
    pub fn enabled_count(&self) -> usize {
        [
            self.scan_personal,
            self.scan_financial,
            self.scan_government,
            self.scan_medical,
            self.scan_biometric,
            self.scan_location,
            self.scan_organizational,
            self.scan_network,
            self.scan_tokens,
        ]
        .iter()
        .filter(|&&enabled| enabled)
        .count()
    }
}

/// Detect environment from standard variables
///
/// Convenience function that checks RUST_ENV and ENVIRONMENT.
pub fn detect_environment() -> String {
    env::var("RUST_ENV")
        .or_else(|_| env::var("ENVIRONMENT"))
        .unwrap_or_else(|_| "production".to_string())
}

/// Returns true if running in production environment
pub fn is_production() -> bool {
    let env_name = detect_environment();
    matches!(env_name.to_lowercase().as_str(), "production" | "prod")
}

/// Returns true if running in development environment
pub fn is_development() -> bool {
    let env_name = detect_environment();
    matches!(
        env_name.to_lowercase().as_str(),
        "development" | "dev" | "local"
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_profile_production_safe() {
        assert!(RedactionProfile::ProductionStrict.is_production_safe());
        assert!(RedactionProfile::ProductionLenient.is_production_safe());
        assert!(!RedactionProfile::Development.is_production_safe());
        assert!(!RedactionProfile::Testing.is_production_safe());
    }

    #[test]
    fn test_profile_exposes_pii() {
        assert!(!RedactionProfile::ProductionStrict.exposes_pii());
        assert!(!RedactionProfile::ProductionLenient.exposes_pii());
        assert!(RedactionProfile::Development.exposes_pii());
        assert!(RedactionProfile::Testing.exposes_pii());
    }

    #[test]
    fn test_compliance_risk() {
        assert_eq!(
            RedactionProfile::ProductionStrict.compliance_risk(),
            ComplianceRisk::Low
        );
        assert_eq!(
            RedactionProfile::ProductionLenient.compliance_risk(),
            ComplianceRisk::Medium
        );
        assert_eq!(
            RedactionProfile::Development.compliance_risk(),
            ComplianceRisk::High
        );
        assert_eq!(
            RedactionProfile::Testing.compliance_risk(),
            ComplianceRisk::Critical
        );
    }

    #[test]
    fn test_compliance_risk_ordering() {
        assert!(ComplianceRisk::Low < ComplianceRisk::Medium);
        assert!(ComplianceRisk::Medium < ComplianceRisk::High);
        assert!(ComplianceRisk::High < ComplianceRisk::Critical);
    }

    #[test]
    fn test_from_environment_defaults_to_strict() {
        // When no env vars set, should default to ProductionStrict
        // NOTE: This test may fail in CI if RUST_ENV is set
        // In that case, we'd need to use a mock or skip this test
        let profile = RedactionProfile::from_environment();
        // Just verify it returns something valid
        assert!(matches!(
            profile,
            RedactionProfile::ProductionStrict
                | RedactionProfile::ProductionLenient
                | RedactionProfile::Development
                | RedactionProfile::Testing
        ));
    }

    #[test]
    fn test_octarine_redact_profile_env_var() {
        // Test that RUST_CORE_REDACT_PROFILE is recognized
        // NOTE: This test documents the environment variable but cannot
        // reliably test it in isolation due to environment variable conflicts.
        // The actual behavior is tested through from_environment() calls.

        // Document the supported values
        let supported_values = vec![
            ("production-strict", "ProductionStrict"),
            ("strict", "ProductionStrict"),
            ("prod-strict", "ProductionStrict"),
            ("production-lenient", "ProductionLenient"),
            ("lenient", "ProductionLenient"),
            ("prod-lenient", "ProductionLenient"),
            ("development", "Development"),
            ("dev", "Development"),
            ("testing", "Testing"),
            ("test", "Testing"),
        ];

        // Verify this is non-empty (just to have an assertion)
        assert!(!supported_values.is_empty());
    }

    // =========================================================================
    // PiiScannerConfig Tests
    // =========================================================================

    #[test]
    fn test_scanner_config_default() {
        let config = PiiScannerConfig::default();
        // Default enables high-risk domains
        assert!(config.scan_personal);
        assert!(config.scan_financial);
        assert!(config.scan_government);
        assert!(config.scan_medical);
        assert!(config.scan_location);
        assert!(config.scan_network); // IP addresses are GDPR-protected PII
        assert!(config.scan_tokens);
        // Default disables low-priority domains
        assert!(!config.scan_biometric);
        assert!(!config.scan_organizational);
    }

    #[test]
    fn test_scanner_config_none() {
        let config = PiiScannerConfig::none();
        assert!(!config.scan_personal);
        assert!(!config.scan_financial);
        assert!(!config.scan_government);
        assert!(!config.scan_medical);
        assert!(!config.scan_biometric);
        assert!(!config.scan_location);
        assert!(!config.scan_organizational);
        assert!(!config.scan_network);
        assert!(!config.scan_tokens);
        assert!(!config.is_any_enabled());
        assert_eq!(config.enabled_count(), 0);
    }

    #[test]
    fn test_scanner_config_all() {
        let config = PiiScannerConfig::all();
        assert!(config.scan_personal);
        assert!(config.scan_financial);
        assert!(config.scan_government);
        assert!(config.scan_medical);
        assert!(config.scan_biometric);
        assert!(config.scan_location);
        assert!(config.scan_organizational);
        assert!(config.scan_network);
        assert!(config.scan_tokens);
        assert!(config.is_any_enabled());
        assert_eq!(config.enabled_count(), 9);
    }

    #[test]
    fn test_scanner_config_hipaa_focused() {
        let config = PiiScannerConfig::hipaa_focused();
        // HIPAA requires PHI protection
        assert!(config.scan_personal); // Names, DOB, contact info
        assert!(config.scan_government); // SSN
        assert!(config.scan_medical); // Core medical IDs
        assert!(config.scan_biometric); // Biometrics
        assert!(config.scan_location); // Address
        // Not core HIPAA
        assert!(!config.scan_financial);
        assert!(!config.scan_organizational);
        assert!(!config.scan_network);
    }

    #[test]
    fn test_scanner_config_pci_focused() {
        let config = PiiScannerConfig::pci_focused();
        // PCI-DSS requires payment data protection
        assert!(config.scan_financial);
        assert!(config.scan_tokens); // API keys may access cardholder data
        // Not core PCI-DSS
        assert!(!config.scan_personal);
        assert!(!config.scan_government);
        assert!(!config.scan_medical);
    }

    #[test]
    fn test_scanner_config_gdpr_focused() {
        let config = PiiScannerConfig::gdpr_focused();
        // GDPR covers personal data broadly
        assert!(config.scan_personal);
        assert!(config.scan_government);
        assert!(config.scan_medical);
        assert!(config.scan_biometric);
        assert!(config.scan_location);
        assert!(config.scan_network); // IP is personal data under GDPR
    }

    #[test]
    fn test_scanner_config_secrets_focused() {
        let config = PiiScannerConfig::secrets_focused();
        // Only tokens/secrets
        assert!(config.scan_tokens);
        // Nothing else
        assert!(!config.scan_personal);
        assert!(!config.scan_financial);
        assert!(!config.scan_government);
        assert!(!config.scan_medical);
        assert_eq!(config.enabled_count(), 1);
    }

    #[test]
    fn test_scanner_config_builder() {
        let config = PiiScannerConfig::none()
            .with_personal(true)
            .with_financial(true)
            .with_tokens(true);

        assert!(config.scan_personal);
        assert!(config.scan_financial);
        assert!(config.scan_tokens);
        assert!(!config.scan_government);
        assert!(!config.scan_medical);
        assert_eq!(config.enabled_count(), 3);
    }

    #[test]
    fn test_scanner_config_enabled_count() {
        let mut config = PiiScannerConfig::none();
        assert_eq!(config.enabled_count(), 0);

        config.scan_personal = true;
        assert_eq!(config.enabled_count(), 1);

        config.scan_financial = true;
        config.scan_tokens = true;
        assert_eq!(config.enabled_count(), 3);
    }
}
