//! PII type definitions
//!
//! Covers all 9 identifier domains:
//! - Personal: Email, Phone, SSN, Name, Birthdate, Username
//! - Financial: Credit Card, Bank Account, Routing Number
//! - Government: SSN, Driver License, Passport, VIN, EIN, Tax ID, National ID
//! - Medical: MRN, NPI, Insurance Number, ICD Code, Prescription
//! - Biometric: Fingerprint ID, Face ID, Voice ID, Iris ID, DNA ID
//! - Location: GPS Coordinates, Address, Postal Code
//! - Organizational: Employee ID, Student ID, Badge Number
//! - Network: IP Address, MAC Address, UUID, Domain, URL, Hostname, Port
//! - Token: API Key, JWT, Session ID, OAuth Token, SSH Key

use serde::{Deserialize, Serialize};

/// Types of PII that can be detected
///
/// Organized by domain for clarity. Each variant maps to detection
/// functions in the corresponding primitives/identifiers domain module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PiiType {
    // =========================================================================
    // Personal Domain
    // =========================================================================
    /// Email address
    Email,
    /// Phone number
    Phone,
    /// Personal name
    Name,
    /// Date of birth
    Birthdate,
    /// Username or handle
    Username,

    // =========================================================================
    // Financial Domain
    // =========================================================================
    /// Credit card number
    CreditCard,
    /// Bank account number
    BankAccount,
    /// Bank routing number
    RoutingNumber,
    /// Payment token (Stripe, PayPal, etc.)
    PaymentToken,

    // =========================================================================
    // Government Domain
    // =========================================================================
    /// Social Security Number (US)
    Ssn,
    /// Driver's license number
    DriverLicense,
    /// Passport number
    Passport,
    /// Vehicle Identification Number
    Vin,
    /// Employer Identification Number
    Ein,
    /// Tax ID (generic)
    TaxId,
    /// National ID number (non-US government identifiers)
    NationalId,

    // =========================================================================
    // Medical Domain (PHI - Protected Health Information)
    // =========================================================================
    /// Medical Record Number
    Mrn,
    /// National Provider Identifier
    Npi,
    /// Health insurance number
    InsuranceNumber,
    /// ICD diagnostic code
    IcdCode,
    /// Prescription number
    PrescriptionNumber,

    // =========================================================================
    // Biometric Domain
    // =========================================================================
    /// Fingerprint template ID
    FingerprintId,
    /// Facial recognition ID
    FaceId,
    /// Voice print ID
    VoiceId,
    /// Iris scan ID
    IrisId,
    /// DNA profile ID
    DnaId,

    // =========================================================================
    // Location Domain
    // =========================================================================
    /// GPS coordinates
    GpsCoordinates,
    /// Street address
    Address,
    /// Postal/ZIP code
    PostalCode,

    // =========================================================================
    // Organizational Domain
    // =========================================================================
    /// Employee ID
    EmployeeId,
    /// Student ID
    StudentId,
    /// Badge/access card number
    BadgeNumber,

    // =========================================================================
    // Network Domain
    // =========================================================================
    /// IP address (v4 or v6)
    IpAddress,
    /// MAC address
    MacAddress,
    /// UUID/GUID
    Uuid,
    /// Domain name
    Domain,
    /// URL
    Url,
    /// Hostname (bare hostname without scheme)
    Hostname,
    /// Network port number
    Port,

    // =========================================================================
    // Token Domain (Secrets)
    // =========================================================================
    /// API key or token
    ApiKey,
    /// JSON Web Token
    Jwt,
    /// Session ID/token
    SessionId,
    /// OAuth token
    OAuthToken,
    /// SSH key (public or private)
    SshKey,
    /// 1Password service account token
    OnePasswordToken,
    /// 1Password vault reference (op://vault/item/field)
    OnePasswordVaultRef,
    /// Bearer token (Authorization header)
    BearerToken,
    /// URL with embedded credentials
    UrlWithCredentials,
    /// Connection string with embedded credentials (MSSQL, JDBC, database URLs)
    ConnectionString,

    // =========================================================================
    // Credential Domain (NIST 800-63 Factor 1: Something You Know)
    // =========================================================================
    /// Password (context-based detection via labels like "password=")
    Password,
    /// PIN code (context-based detection via labels like "pin=")
    Pin,
    /// Security question answer
    SecurityAnswer,
    /// Passphrase (multi-word secret)
    Passphrase,

    // =========================================================================
    // Catch-all
    // =========================================================================
    /// Generic/unknown PII
    Generic,
}

impl PiiType {
    /// Returns a human-readable name for this PII type
    pub fn name(&self) -> &'static str {
        match self {
            // Personal
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Name => "name",
            Self::Birthdate => "birthdate",
            Self::Username => "username",
            // Financial
            Self::CreditCard => "credit_card",
            Self::BankAccount => "bank_account",
            Self::RoutingNumber => "routing_number",
            Self::PaymentToken => "payment_token",
            // Government
            Self::Ssn => "ssn",
            Self::DriverLicense => "driver_license",
            Self::Passport => "passport",
            Self::Vin => "vin",
            Self::Ein => "ein",
            Self::TaxId => "tax_id",
            Self::NationalId => "national_id",
            // Medical
            Self::Mrn => "mrn",
            Self::Npi => "npi",
            Self::InsuranceNumber => "insurance_number",
            Self::IcdCode => "icd_code",
            Self::PrescriptionNumber => "prescription_number",
            // Biometric
            Self::FingerprintId => "fingerprint_id",
            Self::FaceId => "face_id",
            Self::VoiceId => "voice_id",
            Self::IrisId => "iris_id",
            Self::DnaId => "dna_id",
            // Location
            Self::GpsCoordinates => "gps_coordinates",
            Self::Address => "address",
            Self::PostalCode => "postal_code",
            // Organizational
            Self::EmployeeId => "employee_id",
            Self::StudentId => "student_id",
            Self::BadgeNumber => "badge_number",
            // Network
            Self::IpAddress => "ip_address",
            Self::MacAddress => "mac_address",
            Self::Uuid => "uuid",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Hostname => "hostname",
            Self::Port => "port",
            // Token
            Self::ApiKey => "api_key",
            Self::Jwt => "jwt",
            Self::SessionId => "session_id",
            Self::OAuthToken => "oauth_token",
            Self::SshKey => "ssh_key",
            Self::OnePasswordToken => "onepassword_token",
            Self::OnePasswordVaultRef => "onepassword_vault_ref",
            Self::BearerToken => "bearer_token",
            Self::UrlWithCredentials => "url_with_credentials",
            Self::ConnectionString => "connection_string",
            // Credential
            Self::Password => "password",
            Self::Pin => "pin",
            Self::SecurityAnswer => "security_answer",
            Self::Passphrase => "passphrase",
            // Catch-all
            Self::Generic => "generic",
        }
    }

    /// Returns the domain this PII type belongs to
    pub fn domain(&self) -> &'static str {
        match self {
            Self::Email | Self::Phone | Self::Name | Self::Birthdate | Self::Username => "personal",
            Self::CreditCard | Self::BankAccount | Self::RoutingNumber | Self::PaymentToken => {
                "financial"
            }
            Self::Ssn
            | Self::DriverLicense
            | Self::Passport
            | Self::Vin
            | Self::Ein
            | Self::TaxId
            | Self::NationalId => "government",
            Self::Mrn
            | Self::Npi
            | Self::InsuranceNumber
            | Self::IcdCode
            | Self::PrescriptionNumber => "medical",
            Self::FingerprintId | Self::FaceId | Self::VoiceId | Self::IrisId | Self::DnaId => {
                "biometric"
            }
            Self::GpsCoordinates | Self::Address | Self::PostalCode => "location",
            Self::EmployeeId | Self::StudentId | Self::BadgeNumber => "organizational",
            Self::IpAddress
            | Self::MacAddress
            | Self::Uuid
            | Self::Domain
            | Self::Url
            | Self::Hostname
            | Self::Port => "network",
            Self::ApiKey
            | Self::Jwt
            | Self::SessionId
            | Self::OAuthToken
            | Self::SshKey
            | Self::OnePasswordToken
            | Self::OnePasswordVaultRef
            | Self::BearerToken
            | Self::UrlWithCredentials
            | Self::ConnectionString => "token",
            Self::Password | Self::Pin | Self::SecurityAnswer | Self::Passphrase => "credential",
            Self::Generic => "generic",
        }
    }

    /// Returns true if this PII type is considered high-risk
    ///
    /// High-risk types include financial data, government IDs, medical records,
    /// biometric data, and authentication credentials.
    pub fn is_high_risk(&self) -> bool {
        matches!(
            self,
            // Financial
            Self::CreditCard | Self::BankAccount | Self::RoutingNumber | Self::PaymentToken |
            // Government (identity theft risk)
            Self::Ssn | Self::DriverLicense | Self::Passport | Self::Ein | Self::TaxId | Self::NationalId |
            // Medical (HIPAA)
            Self::Mrn | Self::Npi | Self::InsuranceNumber |
            // Biometric (irreplaceable)
            Self::FingerprintId | Self::FaceId | Self::VoiceId | Self::IrisId | Self::DnaId |
            // Authentication (security breach)
            Self::Password | Self::Pin | Self::SecurityAnswer | Self::Passphrase |
            Self::ApiKey | Self::Jwt | Self::SessionId | Self::OAuthToken | Self::SshKey |
            Self::OnePasswordToken | Self::OnePasswordVaultRef | Self::BearerToken | Self::UrlWithCredentials |
            Self::ConnectionString
        )
    }

    /// Returns true if this PII type is covered by GDPR
    pub fn is_gdpr_protected(&self) -> bool {
        matches!(
            self,
            // Personal data
            Self::Email | Self::Phone | Self::Name | Self::Birthdate | Self::Username |
            // Government IDs
            Self::Ssn | Self::DriverLicense | Self::Passport | Self::TaxId | Self::NationalId |
            // Location
            Self::IpAddress | Self::GpsCoordinates | Self::Address | Self::PostalCode |
            // Biometric
            Self::FingerprintId | Self::FaceId | Self::VoiceId | Self::IrisId | Self::DnaId |
            // Medical
            Self::Mrn | Self::InsuranceNumber
        )
    }

    /// Returns true if this PII type is covered by PCI-DSS
    pub fn is_pci_protected(&self) -> bool {
        matches!(
            self,
            Self::CreditCard | Self::BankAccount | Self::RoutingNumber | Self::PaymentToken
        )
    }

    /// Returns true if this PII type is covered by HIPAA (PHI)
    pub fn is_hipaa_protected(&self) -> bool {
        matches!(
            self,
            Self::Mrn
                | Self::Npi
                | Self::InsuranceNumber
                | Self::IcdCode
                | Self::PrescriptionNumber
                | Self::Ssn // SSN is also PHI in medical context
                | Self::Name // Names in medical context
                | Self::Birthdate // DOB in medical context
                | Self::Address // Address in medical context
                | Self::Phone // Phone in medical context
                | Self::Email // Email in medical context
        )
    }

    /// Returns true if this is a secret/credential that should never be logged
    pub fn is_secret(&self) -> bool {
        matches!(
            self,
            Self::Password
                | Self::ApiKey
                | Self::Jwt
                | Self::SessionId
                | Self::OAuthToken
                | Self::SshKey
                | Self::OnePasswordToken
                | Self::OnePasswordVaultRef
                | Self::BearerToken
                | Self::UrlWithCredentials
                | Self::ConnectionString
                | Self::PaymentToken
        )
    }
}

/// Result of PII scanning operation
#[derive(Debug, Clone)]
pub(crate) struct PiiScanResult {
    /// Types of PII found in the input
    pub pii_types: Vec<PiiType>,

    /// Redacted output
    pub redacted: String,

    /// Whether any PII was found
    pub contains_pii: bool,

    /// Compliance flags
    pub contains_phi: bool, // Protected Health Information (future: medical record numbers, etc.)
}

impl PiiScanResult {
    /// Create a result with no PII detected
    pub fn no_pii(original: String) -> Self {
        Self {
            pii_types: Vec::new(),
            redacted: original,
            contains_pii: false,
            contains_phi: false,
        }
    }

    /// Create a result with PII detected and redacted
    pub fn with_pii(pii_types: Vec<PiiType>, redacted: String) -> Self {
        // Check if any PII types are HIPAA-protected (PHI)
        let contains_phi = pii_types.iter().any(|t| t.is_hipaa_protected());
        Self {
            pii_types,
            redacted,
            contains_pii: true,
            contains_phi,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_pii_type_name() {
        assert_eq!(PiiType::Ssn.name(), "ssn");
        assert_eq!(PiiType::Email.name(), "email");
        assert_eq!(PiiType::CreditCard.name(), "credit_card");
        assert_eq!(PiiType::Mrn.name(), "mrn");
        assert_eq!(PiiType::ApiKey.name(), "api_key");
    }

    #[test]
    fn test_pii_type_domain() {
        assert_eq!(PiiType::Email.domain(), "personal");
        assert_eq!(PiiType::CreditCard.domain(), "financial");
        assert_eq!(PiiType::Ssn.domain(), "government");
        assert_eq!(PiiType::Mrn.domain(), "medical");
        assert_eq!(PiiType::FingerprintId.domain(), "biometric");
        assert_eq!(PiiType::GpsCoordinates.domain(), "location");
        assert_eq!(PiiType::EmployeeId.domain(), "organizational");
        assert_eq!(PiiType::IpAddress.domain(), "network");
        assert_eq!(PiiType::ApiKey.domain(), "token");
    }

    #[test]
    fn test_high_risk() {
        // Financial
        assert!(PiiType::CreditCard.is_high_risk());
        assert!(PiiType::BankAccount.is_high_risk());
        // Government
        assert!(PiiType::Ssn.is_high_risk());
        assert!(PiiType::Passport.is_high_risk());
        // Medical
        assert!(PiiType::Mrn.is_high_risk());
        // Biometric
        assert!(PiiType::FingerprintId.is_high_risk());
        // Token/secrets
        assert!(PiiType::Password.is_high_risk());
        assert!(PiiType::ApiKey.is_high_risk());
        // Low risk
        assert!(!PiiType::Email.is_high_risk());
        assert!(!PiiType::Phone.is_high_risk());
        assert!(!PiiType::PostalCode.is_high_risk());
    }

    #[test]
    fn test_gdpr_protected() {
        assert!(PiiType::Email.is_gdpr_protected());
        assert!(PiiType::Phone.is_gdpr_protected());
        assert!(PiiType::IpAddress.is_gdpr_protected());
        assert!(PiiType::GpsCoordinates.is_gdpr_protected());
        assert!(PiiType::FingerprintId.is_gdpr_protected());
        // Not GDPR protected
        assert!(!PiiType::ApiKey.is_gdpr_protected());
        assert!(!PiiType::EmployeeId.is_gdpr_protected());
    }

    #[test]
    fn test_pci_protected() {
        assert!(PiiType::CreditCard.is_pci_protected());
        assert!(PiiType::BankAccount.is_pci_protected());
        assert!(PiiType::RoutingNumber.is_pci_protected());
        assert!(!PiiType::Email.is_pci_protected());
        assert!(!PiiType::Ssn.is_pci_protected());
    }

    #[test]
    fn test_hipaa_protected() {
        // Medical
        assert!(PiiType::Mrn.is_hipaa_protected());
        assert!(PiiType::Npi.is_hipaa_protected());
        assert!(PiiType::InsuranceNumber.is_hipaa_protected());
        // PHI identifiers
        assert!(PiiType::Ssn.is_hipaa_protected());
        assert!(PiiType::Name.is_hipaa_protected());
        assert!(PiiType::Birthdate.is_hipaa_protected());
        // Not HIPAA
        assert!(!PiiType::CreditCard.is_hipaa_protected());
        assert!(!PiiType::ApiKey.is_hipaa_protected());
    }

    #[test]
    fn test_is_secret() {
        assert!(PiiType::Password.is_secret());
        assert!(PiiType::ApiKey.is_secret());
        assert!(PiiType::Jwt.is_secret());
        assert!(PiiType::SessionId.is_secret());
        assert!(PiiType::SshKey.is_secret());
        // Not secrets
        assert!(!PiiType::Email.is_secret());
        assert!(!PiiType::Ssn.is_secret());
        assert!(!PiiType::CreditCard.is_secret());
    }

    #[test]
    fn test_national_id_classifications() {
        assert_eq!(PiiType::NationalId.name(), "national_id");
        assert_eq!(PiiType::NationalId.domain(), "government");
        assert!(PiiType::NationalId.is_high_risk());
        assert!(PiiType::NationalId.is_gdpr_protected());
        assert!(!PiiType::NationalId.is_pci_protected());
        assert!(!PiiType::NationalId.is_secret());
    }

    #[test]
    fn test_hostname_classifications() {
        assert_eq!(PiiType::Hostname.name(), "hostname");
        assert_eq!(PiiType::Hostname.domain(), "network");
        assert!(!PiiType::Hostname.is_high_risk());
        assert!(!PiiType::Hostname.is_gdpr_protected());
        assert!(!PiiType::Hostname.is_pci_protected());
        assert!(!PiiType::Hostname.is_secret());
    }

    #[test]
    fn test_port_classifications() {
        assert_eq!(PiiType::Port.name(), "port");
        assert_eq!(PiiType::Port.domain(), "network");
        assert!(!PiiType::Port.is_high_risk());
        assert!(!PiiType::Port.is_gdpr_protected());
        assert!(!PiiType::Port.is_pci_protected());
        assert!(!PiiType::Port.is_secret());
    }

    #[test]
    fn test_payment_token_classifications() {
        assert_eq!(PiiType::PaymentToken.name(), "payment_token");
        assert_eq!(PiiType::PaymentToken.domain(), "financial");
        assert!(PiiType::PaymentToken.is_high_risk());
        assert!(!PiiType::PaymentToken.is_gdpr_protected());
        assert!(PiiType::PaymentToken.is_pci_protected());
        assert!(PiiType::PaymentToken.is_secret());
    }

    #[test]
    fn test_scan_result_no_pii() {
        let result = PiiScanResult::no_pii("clean text".to_string());
        assert!(!result.contains_pii);
        assert!(result.pii_types.is_empty());
        assert_eq!(result.redacted, "clean text");
        assert!(!result.contains_phi);
    }

    #[test]
    fn test_scan_result_with_pii() {
        let result = PiiScanResult::with_pii(
            vec![PiiType::Email, PiiType::Ssn],
            "redacted text".to_string(),
        );
        assert!(result.contains_pii);
        assert_eq!(result.pii_types.len(), 2);
        assert_eq!(result.redacted, "redacted text");
        // Email and SSN are HIPAA-protected
        assert!(result.contains_phi);
    }

    #[test]
    fn test_scan_result_phi_detection() {
        // Medical record triggers PHI
        let result = PiiScanResult::with_pii(vec![PiiType::Mrn], "redacted".to_string());
        assert!(result.contains_phi);

        // Credit card alone does not trigger PHI
        let result = PiiScanResult::with_pii(vec![PiiType::CreditCard], "redacted".to_string());
        assert!(!result.contains_phi);
    }
}
