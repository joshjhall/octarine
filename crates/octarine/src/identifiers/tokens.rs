//! Redaction tokens for PII and sensitive data
//!
//! This module provides the public `RedactionToken` type for replacing
//! sensitive data with standardized placeholder tokens.
//!
//! # Token Format
//!
//! All tokens use square bracket format: `[TOKEN_NAME]`
//!
//! This format was chosen because:
//! - Visually distinct from normal text
//! - Unlikely to appear in legitimate data
//! - Easy to parse/search in logs
//! - Consistent with common logging conventions
//!
//! # Example
//!
//! ```
//! use octarine::identifiers::RedactionToken;
//!
//! let token = RedactionToken::Email;
//! assert_eq!(token.as_str(), "[EMAIL]");
//! assert_eq!(format!("{}", token), "[EMAIL]");
//!
//! // Get domain for compliance mapping
//! assert_eq!(token.domain(), "personal");
//! ```

use std::fmt;

/// Redaction tokens for replacing sensitive data
///
/// Each variant represents a type of sensitive data that can be redacted.
/// The `Display` implementation outputs the token in `[TOKEN_NAME]` format.
///
/// # Domains
///
/// Tokens are organized by domain for compliance mapping:
/// - `personal` - Email, phone, name, birthdate, username
/// - `financial` - Credit cards, bank accounts, routing numbers
/// - `government` - SSN, driver license, passport, VIN, EIN
/// - `medical` - Medical records, provider IDs, insurance info
/// - `biometric` - Fingerprints, facial data, voice prints
/// - `location` - GPS coordinates, addresses, postal codes
/// - `organizational` - Employee IDs, student IDs, badge numbers
/// - `network` - IP addresses, MAC addresses, hostnames
/// - `token` - API keys, JWTs, OAuth tokens
/// - `credentials` - Passwords, PINs, passphrases
/// - `path` - File paths, directories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedactionToken {
    // =========================================================================
    // Generic
    // =========================================================================
    /// Generic redacted content (when type is unknown or mixed)
    Redacted,

    // =========================================================================
    // Identifiers: Personal
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
    // Identifiers: Financial
    // =========================================================================
    /// Credit card number
    CreditCard,
    /// Bank account number
    BankAccount,
    /// Bank routing number
    RoutingNumber,
    /// Payment token (Stripe tok_, etc.)
    PaymentToken,

    // =========================================================================
    // Identifiers: Government
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

    // =========================================================================
    // Identifiers: Medical (PHI)
    // =========================================================================
    /// Medical Record Number
    MedicalRecord,
    /// National Provider Identifier
    ProviderId,
    /// Health insurance number
    InsuranceInfo,
    /// ICD diagnostic code
    MedicalCode,
    /// Prescription number
    Prescription,

    // =========================================================================
    // Identifiers: Biometric
    // =========================================================================
    /// Fingerprint template ID
    Fingerprint,
    /// Facial recognition data
    FacialData,
    /// Voice print data
    VoicePrint,
    /// Iris scan data
    IrisScan,
    /// DNA sequence/profile
    DnaSequence,
    /// Generic biometric template
    BiometricTemplate,

    // =========================================================================
    // Identifiers: Location
    // =========================================================================
    /// GPS coordinates
    GpsCoordinate,
    /// Street address
    Address,
    /// Postal/ZIP code
    PostalCode,

    // =========================================================================
    // Identifiers: Organizational
    // =========================================================================
    /// Employee ID
    EmployeeId,
    /// Student ID
    StudentId,
    /// Badge/access card number
    BadgeNumber,

    // =========================================================================
    // Identifiers: Network
    // =========================================================================
    /// IP address (v4 or v6)
    IpAddress,
    /// MAC address
    MacAddress,
    /// UUID/GUID
    Uuid,
    /// Hostname
    Hostname,
    /// URL
    Url,
    /// Port number
    Port,

    // =========================================================================
    // Identifiers: Tokens/Secrets (Something You HAVE - NIST Factor 2)
    // =========================================================================
    /// Generic API key
    ApiKey,
    /// Stripe-specific key
    StripeKey,
    /// AWS access key
    AwsKey,
    /// AWS session token (STS temporary credential)
    AwsSessionToken,
    /// GitHub token
    GithubToken,
    /// GCP key
    GcpKey,
    /// 1Password service account token
    OnePasswordToken,
    /// 1Password vault reference (op://vault/item/field)
    OnePasswordVaultRef,
    /// Bearer token (Authorization header)
    BearerToken,
    /// JSON Web Token
    Jwt,
    /// Session ID/token
    Session,
    /// OAuth token
    OAuthToken,
    /// SSH private key
    SshKey,
    /// SSH private key (generic)
    SshPrivateKey,
    /// RSA private key specifically
    RsaPrivateKey,
    /// OpenSSH private key format
    OpensshPrivateKey,
    /// SSH key fingerprint
    SshFingerprint,
    /// URL with embedded credentials
    UrlWithCredentials,

    // =========================================================================
    // Identifiers: Credentials (Something You KNOW - NIST Factor 1)
    // =========================================================================
    /// Password
    Password,
    /// PIN (Personal Identification Number)
    Pin,
    /// Security question answer
    SecurityAnswer,
    /// Passphrase (longer password-like secret)
    Passphrase,

    // =========================================================================
    // Paths
    // =========================================================================
    /// File path
    Path,
    /// Directory path
    Directory,
    /// Filename
    Filename,
}

impl RedactionToken {
    /// Returns the token as a static string slice in `[TOKEN_NAME]` format
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            // Generic
            Self::Redacted => "[REDACTED]",

            // Personal
            Self::Email => "[EMAIL]",
            Self::Phone => "[PHONE]",
            Self::Name => "[NAME]",
            Self::Birthdate => "[BIRTHDATE]",
            Self::Username => "[USERNAME]",

            // Financial
            Self::CreditCard => "[CREDIT_CARD]",
            Self::BankAccount => "[BANK_ACCOUNT]",
            Self::RoutingNumber => "[ROUTING_NUMBER]",
            Self::PaymentToken => "[PAYMENT_TOKEN]",

            // Government
            Self::Ssn => "[SSN]",
            Self::DriverLicense => "[DRIVER_LICENSE]",
            Self::Passport => "[PASSPORT]",
            Self::Vin => "[VIN]",
            Self::Ein => "[EIN]",
            Self::TaxId => "[TAX_ID]",

            // Medical
            Self::MedicalRecord => "[MEDICAL_RECORD]",
            Self::ProviderId => "[PROVIDER_ID]",
            Self::InsuranceInfo => "[INSURANCE_INFO]",
            Self::MedicalCode => "[MEDICAL_CODE]",
            Self::Prescription => "[PRESCRIPTION]",

            // Biometric
            Self::Fingerprint => "[FINGERPRINT]",
            Self::FacialData => "[FACIAL_DATA]",
            Self::VoicePrint => "[VOICE_PRINT]",
            Self::IrisScan => "[IRIS_SCAN]",
            Self::DnaSequence => "[DNA_SEQUENCE]",
            Self::BiometricTemplate => "[BIOMETRIC_TEMPLATE]",

            // Location
            Self::GpsCoordinate => "[GPS_COORDINATE]",
            Self::Address => "[ADDRESS]",
            Self::PostalCode => "[POSTAL_CODE]",

            // Organizational
            Self::EmployeeId => "[EMPLOYEE_ID]",
            Self::StudentId => "[STUDENT_ID]",
            Self::BadgeNumber => "[BADGE_NUMBER]",

            // Network
            Self::IpAddress => "[IP_ADDRESS]",
            Self::MacAddress => "[MAC_ADDRESS]",
            Self::Uuid => "[UUID]",
            Self::Hostname => "[HOSTNAME]",
            Self::Url => "[URL]",
            Self::Port => "[PORT]",

            // Tokens/Secrets
            Self::ApiKey => "[API_KEY]",
            Self::StripeKey => "[STRIPE_KEY]",
            Self::AwsKey => "[AWS_KEY]",
            Self::AwsSessionToken => "[AWS_SESSION_TOKEN]",
            Self::GithubToken => "[GITHUB_TOKEN]",
            Self::GcpKey => "[GCP_KEY]",
            Self::OnePasswordToken => "[1PASSWORD_TOKEN]",
            Self::OnePasswordVaultRef => "[1PASSWORD_VAULT_REF]",
            Self::BearerToken => "[BEARER_TOKEN]",
            Self::Jwt => "[JWT]",
            Self::Session => "[SESSION]",
            Self::OAuthToken => "[OAUTH_TOKEN]",
            Self::SshKey => "[SSH_KEY]",
            Self::SshPrivateKey => "[SSH_PRIVATE_KEY]",
            Self::RsaPrivateKey => "[RSA_PRIVATE_KEY]",
            Self::OpensshPrivateKey => "[OPENSSH_PRIVATE_KEY]",
            Self::SshFingerprint => "[SSH_FINGERPRINT]",
            Self::UrlWithCredentials => "[URL_WITH_CREDENTIALS]",

            // Credentials
            Self::Password => "[PASSWORD]",
            Self::Pin => "[PIN]",
            Self::SecurityAnswer => "[SECURITY_ANSWER]",
            Self::Passphrase => "[PASSPHRASE]",

            // Paths
            Self::Path => "[PATH]",
            Self::Directory => "[DIRECTORY]",
            Self::Filename => "[FILENAME]",
        }
    }

    /// Returns the token name without brackets (e.g., "EMAIL" not "\[EMAIL\]")
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            // Generic
            Self::Redacted => "REDACTED",

            // Personal
            Self::Email => "EMAIL",
            Self::Phone => "PHONE",
            Self::Name => "NAME",
            Self::Birthdate => "BIRTHDATE",
            Self::Username => "USERNAME",

            // Financial
            Self::CreditCard => "CREDIT_CARD",
            Self::BankAccount => "BANK_ACCOUNT",
            Self::RoutingNumber => "ROUTING_NUMBER",
            Self::PaymentToken => "PAYMENT_TOKEN",

            // Government
            Self::Ssn => "SSN",
            Self::DriverLicense => "DRIVER_LICENSE",
            Self::Passport => "PASSPORT",
            Self::Vin => "VIN",
            Self::Ein => "EIN",
            Self::TaxId => "TAX_ID",

            // Medical
            Self::MedicalRecord => "MEDICAL_RECORD",
            Self::ProviderId => "PROVIDER_ID",
            Self::InsuranceInfo => "INSURANCE_INFO",
            Self::MedicalCode => "MEDICAL_CODE",
            Self::Prescription => "PRESCRIPTION",

            // Biometric
            Self::Fingerprint => "FINGERPRINT",
            Self::FacialData => "FACIAL_DATA",
            Self::VoicePrint => "VOICE_PRINT",
            Self::IrisScan => "IRIS_SCAN",
            Self::DnaSequence => "DNA_SEQUENCE",
            Self::BiometricTemplate => "BIOMETRIC_TEMPLATE",

            // Location
            Self::GpsCoordinate => "GPS_COORDINATE",
            Self::Address => "ADDRESS",
            Self::PostalCode => "POSTAL_CODE",

            // Organizational
            Self::EmployeeId => "EMPLOYEE_ID",
            Self::StudentId => "STUDENT_ID",
            Self::BadgeNumber => "BADGE_NUMBER",

            // Network
            Self::IpAddress => "IP_ADDRESS",
            Self::MacAddress => "MAC_ADDRESS",
            Self::Uuid => "UUID",
            Self::Hostname => "HOSTNAME",
            Self::Url => "URL",
            Self::Port => "PORT",

            // Tokens/Secrets
            Self::ApiKey => "API_KEY",
            Self::StripeKey => "STRIPE_KEY",
            Self::AwsKey => "AWS_KEY",
            Self::AwsSessionToken => "AWS_SESSION_TOKEN",
            Self::GithubToken => "GITHUB_TOKEN",
            Self::GcpKey => "GCP_KEY",
            Self::OnePasswordToken => "1PASSWORD_TOKEN",
            Self::OnePasswordVaultRef => "1PASSWORD_VAULT_REF",
            Self::BearerToken => "BEARER_TOKEN",
            Self::Jwt => "JWT",
            Self::Session => "SESSION",
            Self::OAuthToken => "OAUTH_TOKEN",
            Self::SshKey => "SSH_KEY",
            Self::SshPrivateKey => "SSH_PRIVATE_KEY",
            Self::RsaPrivateKey => "RSA_PRIVATE_KEY",
            Self::OpensshPrivateKey => "OPENSSH_PRIVATE_KEY",
            Self::SshFingerprint => "SSH_FINGERPRINT",
            Self::UrlWithCredentials => "URL_WITH_CREDENTIALS",

            // Credentials
            Self::Password => "PASSWORD",
            Self::Pin => "PIN",
            Self::SecurityAnswer => "SECURITY_ANSWER",
            Self::Passphrase => "PASSPHRASE",

            // Paths
            Self::Path => "PATH",
            Self::Directory => "DIRECTORY",
            Self::Filename => "FILENAME",
        }
    }

    /// Returns the domain this token belongs to
    ///
    /// Domains help map tokens to compliance frameworks:
    /// - `personal` - GDPR Art. 4(1), CCPA Personal Info
    /// - `financial` - PCI-DSS Req 3, CCPA Financial Info
    /// - `medical` - HIPAA PHI, GDPR Art. 9
    /// - `biometric` - BIPA, GDPR Art. 9
    #[must_use]
    pub const fn domain(&self) -> &'static str {
        match self {
            Self::Redacted => "generic",

            Self::Email | Self::Phone | Self::Name | Self::Birthdate | Self::Username => "personal",

            Self::CreditCard | Self::BankAccount | Self::RoutingNumber | Self::PaymentToken => {
                "financial"
            }

            Self::Ssn
            | Self::DriverLicense
            | Self::Passport
            | Self::Vin
            | Self::Ein
            | Self::TaxId => "government",

            Self::MedicalRecord
            | Self::ProviderId
            | Self::InsuranceInfo
            | Self::MedicalCode
            | Self::Prescription => "medical",

            Self::Fingerprint
            | Self::FacialData
            | Self::VoicePrint
            | Self::IrisScan
            | Self::DnaSequence
            | Self::BiometricTemplate => "biometric",

            Self::GpsCoordinate | Self::Address | Self::PostalCode => "location",

            Self::EmployeeId | Self::StudentId | Self::BadgeNumber => "organizational",

            Self::IpAddress
            | Self::MacAddress
            | Self::Uuid
            | Self::Hostname
            | Self::Url
            | Self::Port => "network",

            Self::ApiKey
            | Self::StripeKey
            | Self::AwsKey
            | Self::AwsSessionToken
            | Self::GithubToken
            | Self::GcpKey
            | Self::OnePasswordToken
            | Self::OnePasswordVaultRef
            | Self::BearerToken
            | Self::Jwt
            | Self::Session
            | Self::OAuthToken
            | Self::SshKey
            | Self::SshPrivateKey
            | Self::RsaPrivateKey
            | Self::OpensshPrivateKey
            | Self::SshFingerprint
            | Self::UrlWithCredentials => "token",

            Self::Password | Self::Pin | Self::SecurityAnswer | Self::Passphrase => "credentials",

            Self::Path | Self::Directory | Self::Filename => "path",
        }
    }
}

impl fmt::Display for RedactionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Converts a RedactionToken to its String representation
impl From<RedactionToken> for String {
    fn from(token: RedactionToken) -> Self {
        token.as_str().to_string()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_token_format() {
        assert_eq!(RedactionToken::Email.as_str(), "[EMAIL]");
        assert_eq!(RedactionToken::CreditCard.as_str(), "[CREDIT_CARD]");
        assert_eq!(RedactionToken::IpAddress.as_str(), "[IP_ADDRESS]");
        assert_eq!(RedactionToken::Redacted.as_str(), "[REDACTED]");
    }

    #[test]
    fn test_token_display() {
        assert_eq!(format!("{}", RedactionToken::Email), "[EMAIL]");
        assert_eq!(format!("{}", RedactionToken::Ssn), "[SSN]");
    }

    #[test]
    fn test_token_name() {
        assert_eq!(RedactionToken::Email.name(), "EMAIL");
        assert_eq!(RedactionToken::CreditCard.name(), "CREDIT_CARD");
        assert_eq!(RedactionToken::IpAddress.name(), "IP_ADDRESS");
    }

    #[test]
    fn test_token_domain() {
        assert_eq!(RedactionToken::Email.domain(), "personal");
        assert_eq!(RedactionToken::CreditCard.domain(), "financial");
        assert_eq!(RedactionToken::Ssn.domain(), "government");
        assert_eq!(RedactionToken::MedicalRecord.domain(), "medical");
        assert_eq!(RedactionToken::Fingerprint.domain(), "biometric");
        assert_eq!(RedactionToken::GpsCoordinate.domain(), "location");
        assert_eq!(RedactionToken::EmployeeId.domain(), "organizational");
        assert_eq!(RedactionToken::IpAddress.domain(), "network");
        assert_eq!(RedactionToken::ApiKey.domain(), "token");
        assert_eq!(RedactionToken::Path.domain(), "path");
    }

    #[test]
    fn test_token_into_string() {
        let s: String = RedactionToken::Email.into();
        assert_eq!(s, "[EMAIL]");
    }
}
