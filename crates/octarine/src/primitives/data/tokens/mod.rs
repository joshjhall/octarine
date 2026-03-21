//! Centralized redaction tokens for consistent output across all primitives
//!
//! This module provides the internal redaction token type used by primitives.
//! For the public API, see `data::identifiers::RedactionToken`.
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

use std::fmt;

/// Internal redaction token type (primitives layer)
///
/// This is the internal representation. The public API is
/// `octarine::data::identifiers::RedactionToken`.
///
/// Each variant represents a type of sensitive data that can be redacted.
/// The `Display` implementation outputs the token in `[TOKEN_NAME]` format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)] // Not all variants used in primitives; public API uses all
pub(crate) enum RedactionTokenCore {
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
    // Paths (for future primitives/paths module)
    // =========================================================================
    /// File path
    Path,
    /// Directory path
    Directory,
    /// Filename
    Filename,
}

#[allow(dead_code)] // Internal API - not all methods used in primitives
impl RedactionTokenCore {
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

    /// Returns the token name without brackets (e.g., "EMAIL" not "[EMAIL]")
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

impl fmt::Display for RedactionTokenCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Converts a RedactionTokenCore to its String representation
impl From<RedactionTokenCore> for String {
    fn from(token: RedactionTokenCore) -> Self {
        token.as_str().to_string()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_token_format() {
        // All tokens should use [UPPER_SNAKE_CASE] format
        assert_eq!(RedactionTokenCore::Email.as_str(), "[EMAIL]");
        assert_eq!(RedactionTokenCore::CreditCard.as_str(), "[CREDIT_CARD]");
        assert_eq!(RedactionTokenCore::IpAddress.as_str(), "[IP_ADDRESS]");
        assert_eq!(RedactionTokenCore::Redacted.as_str(), "[REDACTED]");
    }

    #[test]
    fn test_token_display() {
        assert_eq!(format!("{}", RedactionTokenCore::Email), "[EMAIL]");
        assert_eq!(format!("{}", RedactionTokenCore::Ssn), "[SSN]");
    }

    #[test]
    fn test_token_name() {
        assert_eq!(RedactionTokenCore::Email.name(), "EMAIL");
        assert_eq!(RedactionTokenCore::CreditCard.name(), "CREDIT_CARD");
        assert_eq!(RedactionTokenCore::IpAddress.name(), "IP_ADDRESS");
    }

    #[test]
    fn test_token_domain() {
        assert_eq!(RedactionTokenCore::Email.domain(), "personal");
        assert_eq!(RedactionTokenCore::CreditCard.domain(), "financial");
        assert_eq!(RedactionTokenCore::Ssn.domain(), "government");
        assert_eq!(RedactionTokenCore::MedicalRecord.domain(), "medical");
        assert_eq!(RedactionTokenCore::Fingerprint.domain(), "biometric");
        assert_eq!(RedactionTokenCore::GpsCoordinate.domain(), "location");
        assert_eq!(RedactionTokenCore::EmployeeId.domain(), "organizational");
        assert_eq!(RedactionTokenCore::IpAddress.domain(), "network");
        assert_eq!(RedactionTokenCore::ApiKey.domain(), "token");
        assert_eq!(RedactionTokenCore::Path.domain(), "path");
    }

    #[test]
    fn test_token_into_string() {
        let s: String = RedactionTokenCore::Email.into();
        assert_eq!(s, "[EMAIL]");
    }

    #[test]
    fn test_all_tokens_have_brackets() {
        // Ensure consistent format
        let tokens = [
            RedactionTokenCore::Redacted,
            RedactionTokenCore::Email,
            RedactionTokenCore::Phone,
            RedactionTokenCore::CreditCard,
            RedactionTokenCore::Ssn,
            RedactionTokenCore::MedicalRecord,
            RedactionTokenCore::Fingerprint,
            RedactionTokenCore::GpsCoordinate,
            RedactionTokenCore::EmployeeId,
            RedactionTokenCore::IpAddress,
            RedactionTokenCore::ApiKey,
            RedactionTokenCore::Path,
        ];

        for token in tokens {
            let s = token.as_str();
            assert!(s.starts_with('['), "Token {} should start with [", s);
            assert!(s.ends_with(']'), "Token {} should end with ]", s);
        }
    }
}
