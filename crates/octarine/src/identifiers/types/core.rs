//! Core identifier types
//!
//! Contains the fundamental types used across all identifier operations:
//! - `IdentifierType` - Enumeration of all identifier categories
//! - `DetectionConfidence` - Confidence levels for detection
//! - `IdentifierMatch` - Result of finding an identifier in text
//! - `DetectionResult` - Result of detecting a specific identifier type

// ============================================================================
// Identifier Type
// ============================================================================

/// Types of identifiers that can be detected
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IdentifierType {
    // Personal identifiers
    /// Email address
    Email,
    /// Phone number
    PhoneNumber,
    /// Social Security Number
    Ssn,
    /// Personal name
    PersonalName,
    /// Birth date
    Birthdate,
    /// Username
    Username,

    // Credential identifiers
    /// Password
    Password,
    /// PIN code
    Pin,
    /// Security question answer
    SecurityAnswer,
    /// Passphrase
    Passphrase,

    // Network identifiers
    /// Universally Unique Identifier
    Uuid,
    /// IP address (v4 or v6)
    IpAddress,
    /// MAC address
    MacAddress,
    /// URL
    Url,
    /// Domain name
    Domain,
    /// Hostname
    Hostname,
    /// Port number
    Port,

    // Payment identifiers
    /// Credit card number
    CreditCard,
    /// Bank account number
    BankAccount,
    /// Bank routing number
    RoutingNumber,
    /// Payment token
    PaymentToken,

    // Token/Key identifiers
    /// GitHub personal access token
    GitHubToken,
    /// GitLab personal access token
    GitLabToken,
    /// AWS access key
    AwsAccessKey,
    /// JSON Web Token
    Jwt,
    /// Generic API key
    ApiKey,
    /// Session identifier
    SessionId,

    // Database identifiers
    /// Database connection string
    ConnectionString,

    // Government/Official identifiers
    /// Driver's license number
    DriverLicense,
    /// Passport number
    Passport,
    /// Tax identification number
    TaxId,
    /// National ID number
    NationalId,

    // Organizational identifiers
    /// Employee identifier
    EmployeeId,
    /// Student identifier
    StudentId,
    /// Badge number
    BadgeNumber,
    /// Vehicle identification number
    VehicleId,

    // Location identifiers
    /// GPS coordinate
    GPSCoordinate,
    /// Street address
    StreetAddress,
    /// Postal/ZIP code
    PostalCode,

    // Medical/Health identifiers (HIPAA PHI)
    /// Medical record number
    MedicalRecordNumber,
    /// Health insurance ID
    HealthInsurance,
    /// Prescription number
    Prescription,
    /// Healthcare provider ID (NPI)
    ProviderID,
    /// Medical code (ICD-10, CPT)
    MedicalCode,

    // Biometric identifiers (GDPR Article 9, BIPA)
    /// Fingerprint identifier
    Fingerprint,
    /// Facial recognition data
    FacialRecognition,
    /// Iris scan data
    IrisScan,
    /// Voice print data
    VoicePrint,
    /// DNA sequence
    DNASequence,
    /// Biometric template
    BiometricTemplate,

    // Generic/Unknown
    /// Unknown identifier type
    Unknown,
}

impl From<crate::primitives::identifiers::IdentifierType> for IdentifierType {
    fn from(t: crate::primitives::identifiers::IdentifierType) -> Self {
        use crate::primitives::identifiers::IdentifierType as P;
        match t {
            P::Email => Self::Email,
            P::PhoneNumber => Self::PhoneNumber,
            P::Ssn => Self::Ssn,
            P::PersonalName => Self::PersonalName,
            P::Birthdate => Self::Birthdate,
            P::Username => Self::Username,
            P::Password => Self::Password,
            P::Pin => Self::Pin,
            P::SecurityAnswer => Self::SecurityAnswer,
            P::Passphrase => Self::Passphrase,
            P::Uuid => Self::Uuid,
            P::IpAddress => Self::IpAddress,
            P::MacAddress => Self::MacAddress,
            P::Url => Self::Url,
            P::Domain => Self::Domain,
            P::Hostname => Self::Hostname,
            P::Port => Self::Port,
            P::CreditCard => Self::CreditCard,
            P::BankAccount => Self::BankAccount,
            P::RoutingNumber => Self::RoutingNumber,
            P::PaymentToken => Self::PaymentToken,
            P::GitHubToken => Self::GitHubToken,
            P::GitLabToken => Self::GitLabToken,
            P::AwsAccessKey => Self::AwsAccessKey,
            P::Jwt => Self::Jwt,
            P::ApiKey => Self::ApiKey,
            P::SessionId => Self::SessionId,
            P::ConnectionString => Self::ConnectionString,
            P::DriverLicense => Self::DriverLicense,
            P::Passport => Self::Passport,
            P::TaxId => Self::TaxId,
            P::NationalId => Self::NationalId,
            P::EmployeeId => Self::EmployeeId,
            P::StudentId => Self::StudentId,
            P::BadgeNumber => Self::BadgeNumber,
            P::VehicleId => Self::VehicleId,
            P::GPSCoordinate => Self::GPSCoordinate,
            P::StreetAddress => Self::StreetAddress,
            P::PostalCode => Self::PostalCode,
            P::MedicalRecordNumber => Self::MedicalRecordNumber,
            P::HealthInsurance => Self::HealthInsurance,
            P::Prescription => Self::Prescription,
            P::ProviderID => Self::ProviderID,
            P::MedicalCode => Self::MedicalCode,
            P::Fingerprint => Self::Fingerprint,
            P::FacialRecognition => Self::FacialRecognition,
            P::IrisScan => Self::IrisScan,
            P::VoicePrint => Self::VoicePrint,
            P::DNASequence => Self::DNASequence,
            P::BiometricTemplate => Self::BiometricTemplate,
            P::Unknown => Self::Unknown,
        }
    }
}

impl From<IdentifierType> for crate::primitives::identifiers::IdentifierType {
    fn from(t: IdentifierType) -> Self {
        match t {
            IdentifierType::Email => Self::Email,
            IdentifierType::PhoneNumber => Self::PhoneNumber,
            IdentifierType::Ssn => Self::Ssn,
            IdentifierType::PersonalName => Self::PersonalName,
            IdentifierType::Birthdate => Self::Birthdate,
            IdentifierType::Username => Self::Username,
            IdentifierType::Password => Self::Password,
            IdentifierType::Pin => Self::Pin,
            IdentifierType::SecurityAnswer => Self::SecurityAnswer,
            IdentifierType::Passphrase => Self::Passphrase,
            IdentifierType::Uuid => Self::Uuid,
            IdentifierType::IpAddress => Self::IpAddress,
            IdentifierType::MacAddress => Self::MacAddress,
            IdentifierType::Url => Self::Url,
            IdentifierType::Domain => Self::Domain,
            IdentifierType::Hostname => Self::Hostname,
            IdentifierType::Port => Self::Port,
            IdentifierType::CreditCard => Self::CreditCard,
            IdentifierType::BankAccount => Self::BankAccount,
            IdentifierType::RoutingNumber => Self::RoutingNumber,
            IdentifierType::PaymentToken => Self::PaymentToken,
            IdentifierType::GitHubToken => Self::GitHubToken,
            IdentifierType::GitLabToken => Self::GitLabToken,
            IdentifierType::AwsAccessKey => Self::AwsAccessKey,
            IdentifierType::Jwt => Self::Jwt,
            IdentifierType::ApiKey => Self::ApiKey,
            IdentifierType::SessionId => Self::SessionId,
            IdentifierType::ConnectionString => Self::ConnectionString,
            IdentifierType::DriverLicense => Self::DriverLicense,
            IdentifierType::Passport => Self::Passport,
            IdentifierType::TaxId => Self::TaxId,
            IdentifierType::NationalId => Self::NationalId,
            IdentifierType::EmployeeId => Self::EmployeeId,
            IdentifierType::StudentId => Self::StudentId,
            IdentifierType::BadgeNumber => Self::BadgeNumber,
            IdentifierType::VehicleId => Self::VehicleId,
            IdentifierType::GPSCoordinate => Self::GPSCoordinate,
            IdentifierType::StreetAddress => Self::StreetAddress,
            IdentifierType::PostalCode => Self::PostalCode,
            IdentifierType::MedicalRecordNumber => Self::MedicalRecordNumber,
            IdentifierType::HealthInsurance => Self::HealthInsurance,
            IdentifierType::Prescription => Self::Prescription,
            IdentifierType::ProviderID => Self::ProviderID,
            IdentifierType::MedicalCode => Self::MedicalCode,
            IdentifierType::Fingerprint => Self::Fingerprint,
            IdentifierType::FacialRecognition => Self::FacialRecognition,
            IdentifierType::IrisScan => Self::IrisScan,
            IdentifierType::VoicePrint => Self::VoicePrint,
            IdentifierType::DNASequence => Self::DNASequence,
            IdentifierType::BiometricTemplate => Self::BiometricTemplate,
            IdentifierType::Unknown => Self::Unknown,
        }
    }
}

// ============================================================================
// Detection Confidence
// ============================================================================

/// Confidence level for detection
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetectionConfidence {
    /// Low confidence detection
    Low,
    /// Medium confidence detection
    Medium,
    /// High confidence detection
    High,
}

impl From<crate::primitives::identifiers::DetectionConfidence> for DetectionConfidence {
    fn from(c: crate::primitives::identifiers::DetectionConfidence) -> Self {
        use crate::primitives::identifiers::DetectionConfidence as P;
        match c {
            P::Low => Self::Low,
            P::Medium => Self::Medium,
            P::High => Self::High,
        }
    }
}

impl From<DetectionConfidence> for crate::primitives::identifiers::DetectionConfidence {
    fn from(c: DetectionConfidence) -> Self {
        match c {
            DetectionConfidence::Low => Self::Low,
            DetectionConfidence::Medium => Self::Medium,
            DetectionConfidence::High => Self::High,
        }
    }
}

// ============================================================================
// Identifier Match
// ============================================================================

/// Result of finding an identifier pattern in text
#[derive(Debug, Clone)]
pub struct IdentifierMatch {
    /// Starting position in the text
    pub start: usize,
    /// Ending position in the text
    pub end: usize,
    /// The matched text
    pub matched_text: String,
    /// Type of identifier found
    pub identifier_type: IdentifierType,
    /// Confidence level of this match
    pub confidence: DetectionConfidence,
}

impl IdentifierMatch {
    /// Create a new identifier match
    pub fn new(
        start: usize,
        end: usize,
        matched_text: String,
        identifier_type: IdentifierType,
        confidence: DetectionConfidence,
    ) -> Self {
        Self {
            start,
            end,
            matched_text,
            identifier_type,
            confidence,
        }
    }

    /// Get the length of the matched text
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Check if the match is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl From<crate::primitives::identifiers::IdentifierMatch> for IdentifierMatch {
    fn from(m: crate::primitives::identifiers::IdentifierMatch) -> Self {
        Self {
            start: m.start,
            end: m.end,
            matched_text: m.matched_text,
            identifier_type: m.identifier_type.into(),
            confidence: m.confidence.into(),
        }
    }
}

impl From<IdentifierMatch> for crate::primitives::identifiers::IdentifierMatch {
    fn from(m: IdentifierMatch) -> Self {
        Self::new(
            m.start,
            m.end,
            m.matched_text,
            m.identifier_type.into(),
            m.confidence.into(),
        )
    }
}

// ============================================================================
// Detection Result
// ============================================================================

/// Result of detecting a specific identifier type
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// Type of identifier detected
    pub identifier_type: IdentifierType,
    /// Confidence level of the detection
    pub confidence: DetectionConfidence,
    /// Whether this identifier contains sensitive data
    pub is_sensitive: bool,
}

impl DetectionResult {
    /// Create a new detection result
    pub fn new(
        identifier_type: IdentifierType,
        confidence: DetectionConfidence,
        is_sensitive: bool,
    ) -> Self {
        Self {
            identifier_type,
            confidence,
            is_sensitive,
        }
    }
}

impl From<crate::primitives::identifiers::DetectionResult> for DetectionResult {
    fn from(r: crate::primitives::identifiers::DetectionResult) -> Self {
        Self {
            identifier_type: r.identifier_type.into(),
            confidence: r.confidence.into(),
            is_sensitive: r.is_sensitive,
        }
    }
}

impl From<DetectionResult> for crate::primitives::identifiers::DetectionResult {
    fn from(r: DetectionResult) -> Self {
        Self::new(
            r.identifier_type.into(),
            r.confidence.into(),
            r.is_sensitive,
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_identifier_type_conversion() {
        let public = IdentifierType::Email;
        let primitive: crate::primitives::identifiers::IdentifierType = public.clone().into();
        let back: IdentifierType = primitive.into();
        assert_eq!(public, back);
    }

    #[test]
    fn test_detection_confidence_ordering() {
        assert!(DetectionConfidence::Low < DetectionConfidence::Medium);
        assert!(DetectionConfidence::Medium < DetectionConfidence::High);
    }

    #[test]
    fn test_identifier_match() {
        let m = IdentifierMatch::new(
            0,
            16,
            "user@example.com".to_string(),
            IdentifierType::Email,
            DetectionConfidence::High,
        );
        assert_eq!(m.len(), 16);
        assert!(!m.is_empty());
    }
}
