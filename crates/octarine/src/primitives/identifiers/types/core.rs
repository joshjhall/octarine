//! Core identifier type definitions
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
    PaymentToken,  // Stripe, PayPal tokens
    CryptoAddress, // Bitcoin, Ethereum wallet addresses
    Iban,          // International Bank Account Number

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
    Ein,   // Employer Identification Number (XX-XXXXXXX, IRS campus prefix)
    TaxId, // TIN, ITIN (EIN has its own variant)
    NationalId,
    KoreaRrn,        // South Korea Resident Registration Number
    AustraliaTfn,    // Australian Tax File Number
    AustraliaAbn,    // Australian Business Number
    IndiaAadhaar,    // Indian Aadhaar number (Verhoeff checksum)
    IndiaPan,        // Indian Permanent Account Number
    SingaporeNric,   // Singapore NRIC/FIN
    FinlandHetu,     // Finnish personal identity code
    PolandPesel,     // Polish personal identity number (PESEL)
    ItalyFiscalCode, // Italian Codice Fiscale
    SpainNif,        // Spanish NIF (Numero de Identificacion Fiscal)
    SpainNie,        // Spanish NIE (Numero de Identidad de Extranjero)

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
