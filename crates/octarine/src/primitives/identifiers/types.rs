//! Type definitions for identifier detection
//!
//! Pure type definitions with no dependencies on other rust-core modules.

// Variants use inline comments; adding full doc comments is tracked separately
#![allow(missing_docs)]

/// Types of identifiers that can be detected
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IdentifierType {
    // Personal identifiers
    Email,
    PhoneNumber,
    Ssn,          // Includes ITIN, EIN
    PersonalName, // Full names, first/last names
    Birthdate,    // Date of birth in various formats
    Username,

    // Credential identifiers (NIST 800-63 "something you know")
    Password,
    Pin,
    SecurityAnswer,
    Passphrase,

    // Network identifiers
    Uuid,
    IpAddress,
    MacAddress,
    Url,
    Domain,   // Domain name without protocol
    Hostname, // Hostname (internal network name)
    Port,     // Port number

    // Payment identifiers
    CreditCard,
    BankAccount,
    RoutingNumber,
    PaymentToken, // Stripe, PayPal tokens

    // Token/Key identifiers
    GitHubToken,
    GitLabToken,
    AwsAccessKey,
    AwsSessionToken,
    Jwt,
    ApiKey,
    SessionId,
    HighEntropyString, // Entropy-detected potential secrets

    // Database identifiers
    ConnectionString,

    // Government/Official identifiers
    DriverLicense,
    Passport,
    TaxId, // EIN, TIN, ITIN
    NationalId,

    // Organizational identifiers
    EmployeeId,
    StudentId,
    BadgeNumber, // Physical security badges, facility access IDs
    VehicleId,

    // Location identifiers
    GPSCoordinate,
    StreetAddress,
    PostalCode,

    // Medical/Health identifiers (HIPAA PHI)
    MedicalRecordNumber, // MRN, Patient ID
    HealthInsurance,     // Policy, Member, Group numbers
    Prescription,        // RX numbers
    ProviderID,          // NPI (National Provider Identifier)
    MedicalCode,         // ICD-10, CPT codes
    MedicalLicense,      // DEA numbers, state medical board licenses

    // Biometric identifiers (GDPR Article 9, BIPA)
    Fingerprint,       // Fingerprint hashes/identifiers
    FacialRecognition, // Face encodings, FaceID/TouchID
    IrisScan,          // IrisCode, iris templates
    VoicePrint,        // Voice/speaker identification
    DNASequence,       // Genetic information, STR markers
    BiometricTemplate, // ISO/IEC 19794 formats (FMR, FIR, FTR, IIR)

    // Generic/Unknown
    Unknown,
}

/// Confidence level for detection
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetectionConfidence {
    Low,    // Heuristic match
    Medium, // Pattern match only
    High,   // Pattern match + validation
}

impl DetectionConfidence {
    /// Boost confidence when contextual keywords are found near a match.
    ///
    /// When `context_present` is true, upgrades confidence one level:
    /// - Low → Medium
    /// - Medium → High
    /// - High → High (already maximum)
    ///
    /// When `context_present` is false, returns `self` unchanged.
    #[must_use]
    pub fn with_context_boost(self, context_present: bool) -> Self {
        if !context_present {
            return self;
        }
        match self {
            Self::Low => Self::Medium,
            Self::Medium | Self::High => Self::High,
        }
    }
}

/// Phone number region enumeration
///
/// Detected based on country code prefix in E.164 format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhoneRegion {
    /// North America (+1)
    NorthAmerica,
    /// United Kingdom (+44)
    Uk,
    /// Germany (+49)
    Germany,
    /// France (+33)
    France,
    /// Spain (+34)
    Spain,
    /// Italy (+39)
    Italy,
    /// Australia (+61)
    Australia,
    /// Japan (+81)
    Japan,
    /// China (+86)
    China,
    /// India (+91)
    India,
    /// Brazil (+55)
    Brazil,
    /// Russia (+7)
    Russia,
    /// Unknown or unrecognized region
    Unknown,
}

impl std::fmt::Display for PhoneRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NorthAmerica => write!(f, "North America (+1)"),
            Self::Uk => write!(f, "United Kingdom (+44)"),
            Self::Germany => write!(f, "Germany (+49)"),
            Self::France => write!(f, "France (+33)"),
            Self::Spain => write!(f, "Spain (+34)"),
            Self::Italy => write!(f, "Italy (+39)"),
            Self::Australia => write!(f, "Australia (+61)"),
            Self::Japan => write!(f, "Japan (+81)"),
            Self::China => write!(f, "China (+86)"),
            Self::India => write!(f, "India (+91)"),
            Self::Brazil => write!(f, "Brazil (+55)"),
            Self::Russia => write!(f, "Russia (+7)"),
            Self::Unknown => write!(f, "Unknown region"),
        }
    }
}

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

/// Result of detecting a specific identifier type
///
/// Used for detailed detection with confidence scoring.
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

/// Credit card brand/type enumeration
///
/// Detected based on BIN (Bank Identification Number) patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditCardType {
    /// Visa cards - starts with 4, 13/16/19 digits
    Visa,
    /// Mastercard - starts with 51-55 or 2221-2720, 16 digits
    Mastercard,
    /// American Express - starts with 34 or 37, 15 digits
    AmericanExpress,
    /// Discover - starts with 6011, 644-649, or 65, 16 digits
    Discover,
    /// JCB (Japan Credit Bureau) - starts with 3528-3589, 16 digits
    Jcb,
    /// Diners Club - starts with 300-305, 36, or 38, 14 digits
    DinersClub,
    /// Unknown or unsupported card type
    Unknown,
}

impl std::fmt::Display for CreditCardType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Visa => write!(f, "Visa"),
            Self::Mastercard => write!(f, "Mastercard"),
            Self::AmericanExpress => write!(f, "American Express"),
            Self::Discover => write!(f, "Discover"),
            Self::Jcb => write!(f, "JCB"),
            Self::DinersClub => write!(f, "Diners Club"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
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

    /// Create a high-confidence match
    pub fn high_confidence(
        start: usize,
        end: usize,
        matched_text: String,
        identifier_type: IdentifierType,
    ) -> Self {
        Self::new(
            start,
            end,
            matched_text,
            identifier_type,
            DetectionConfidence::High,
        )
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

// =============================================================================
// Credential-Specific Types
// =============================================================================

/// Types of credentials that can be detected
///
/// Credentials are "something you know" (NIST 800-63 Factor 1).
/// Unlike pattern-based identifiers (SSN, email), credentials are opaque
/// strings detected by context (labels like "password:", JSON keys, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialType {
    /// Password (text-based secret)
    Password,
    /// PIN (numeric secret, typically 4-8 digits)
    Pin,
    /// Security question answer
    SecurityAnswer,
    /// Passphrase (multi-word secret)
    Passphrase,
    /// Generic/unknown credential type
    Generic,
}

impl CredentialType {
    /// Returns the credential type name
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Pin => "pin",
            Self::SecurityAnswer => "security_answer",
            Self::Passphrase => "passphrase",
            Self::Generic => "credential",
        }
    }

    /// Convert to the corresponding IdentifierType
    #[must_use]
    pub const fn to_identifier_type(self) -> IdentifierType {
        match self {
            Self::Password => IdentifierType::Password,
            Self::Pin => IdentifierType::Pin,
            Self::SecurityAnswer => IdentifierType::SecurityAnswer,
            Self::Passphrase => IdentifierType::Passphrase,
            Self::Generic => IdentifierType::Unknown,
        }
    }
}

/// Result of finding a credential pattern in text
///
/// Unlike `IdentifierMatch`, credential matches include the label/key
/// that preceded the credential value (e.g., "password" in "password=secret").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialMatch {
    /// Start position of the credential VALUE (not the label)
    pub start: usize,
    /// End position of the credential value
    pub end: usize,
    /// The matched credential value
    pub value: String,
    /// Type of credential detected
    pub credential_type: CredentialType,
    /// The label/key that preceded this credential (e.g., "password")
    pub label: String,
}

impl CredentialMatch {
    /// Create a new credential match
    pub fn new(
        start: usize,
        end: usize,
        value: String,
        credential_type: CredentialType,
        label: String,
    ) -> Self {
        Self {
            start,
            end,
            value,
            credential_type,
            label,
        }
    }

    /// Get the length of the matched credential value
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Check if the match is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Convert to a generic IdentifierMatch (loses label information)
    pub fn into_identifier_match(self) -> IdentifierMatch {
        IdentifierMatch::new(
            self.start,
            self.end,
            self.value,
            self.credential_type.to_identifier_type(),
            DetectionConfidence::High,
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_context_boost_low_to_medium() {
        let boosted = DetectionConfidence::Low.with_context_boost(true);
        assert_eq!(boosted, DetectionConfidence::Medium);
    }

    #[test]
    fn test_context_boost_medium_to_high() {
        let boosted = DetectionConfidence::Medium.with_context_boost(true);
        assert_eq!(boosted, DetectionConfidence::High);
    }

    #[test]
    fn test_context_boost_high_stays_high() {
        let boosted = DetectionConfidence::High.with_context_boost(true);
        assert_eq!(boosted, DetectionConfidence::High);
    }

    #[test]
    fn test_context_boost_false_no_change() {
        assert_eq!(
            DetectionConfidence::Low.with_context_boost(false),
            DetectionConfidence::Low
        );
        assert_eq!(
            DetectionConfidence::Medium.with_context_boost(false),
            DetectionConfidence::Medium
        );
        assert_eq!(
            DetectionConfidence::High.with_context_boost(false),
            DetectionConfidence::High
        );
    }
}
