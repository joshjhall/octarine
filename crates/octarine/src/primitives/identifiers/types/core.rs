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
    Ssn,          // US Social Security Number (area 001-665 and 667-899 only — 9xx are ITINs)
    PersonalName, // Full names, first/last names
    Birthdate,    // Date of birth in various formats
    Username,
    Age,                  // Age expression (HIPAA Safe Harbor: ages > 89 require aggregation)
    Nationality,          // Nationality / ethnic group (GDPR Article 9 special category)
    Religion,             // Religious belief (GDPR Article 9 special category)
    PoliticalAffiliation, // Political opinion / party (GDPR Article 9 special category)

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
    IndiaUpi,      // Indian UPI VPA (account@psp — NPCI PSP allowlist)

    // Token/Key identifiers
    GitHubToken,
    GitLabToken,
    AwsAccessKey,
    AwsSessionToken,
    Jwt,
    ApiKey,
    SessionId,
    OAuthToken,          // Generic OAuth 2.0 access/refresh tokens
    SshKey,              // SSH public/private keys and fingerprints
    OnePasswordToken,    // 1Password service account tokens (ops_...)
    OnePasswordVaultRef, // 1Password secret reference (op://vault/item/field)
    BearerToken,         // Authorization: Bearer <token>
    UrlWithCredentials,  // URL with embedded user:pass@host credentials
    HighEntropyString,   // Entropy-detected potential secrets

    // Database identifiers
    ConnectionString,

    // Government/Official identifiers
    DriverLicense,
    Passport,
    Ein,   // Employer Identification Number (XX-XXXXXXX, IRS campus prefix)
    Itin, // US Individual Taxpayer Identification Number (area 9XX, IRS middle group 50-65/70-88/90-92/94-99)
    Mbi, // US Medicare Beneficiary Identifier (11-char CMS layout C A AN N A AN N A A N N, letters exclude S/L/O/I/B/Z)
    TaxId, // Generic TIN — EIN and ITIN have their own variants
    NationalId,
    KoreaRrn,           // South Korea Resident Registration Number (citizens, gender 1-4)
    KoreaFrn,           // South Korea Foreign Registration Number (foreigners, gender 5-8)
    KoreaDriverLicense, // South Korea Driver License (NN-NN-NNNNNN-NN, regions 11-28)
    KoreaPassport,      // South Korea Passport (MRS prefix + 7-8 digits)
    KoreaBrn,           // South Korea Business Registration Number (NNN-NN-NNNNN, weighted mod-10)
    AustraliaTfn,       // Australian Tax File Number
    AustraliaAbn,       // Australian Business Number
    AustraliaMedicare,  // Australian Medicare number (10-digit, weighted mod-10 check)
    AustraliaAcn,       // Australian Company Number (9-digit, weighted mod-10 check)
    IndiaAadhaar,       // Indian Aadhaar number (Verhoeff checksum)
    IndiaPan,           // Indian Permanent Account Number
    IndiaGstin,         // Indian Goods and Services Tax Identification Number (MOD-36 checksum)
    IndiaVehicleReg,    // Indian vehicle registration (license plate)
    IndiaVoterId,       // Indian Voter ID (EPIC - Electors Photo Identity Card)
    IndiaPassport,      // Indian passport (P/S/D type indicator + 7 digits)
    BrazilCpf,          // Brazilian Cadastro de Pessoas Físicas (mod-11 dual check digits)
    BrazilCnpj,         // Brazilian Cadastro Nacional da Pessoa Jurídica (mod-11 dual check digits)
    MexicoCurp,         // Mexican Clave Única de Registro de Población (18 chars + check)
    NigeriaNin,         // Nigerian National Identification Number (11 digits)
    NigeriaBvn,         // Nigerian Bank Verification Number (11 digits, no public checksum)
    NigeriaVehicleReg,  // Nigerian vehicle registration (XXX-NNN-XX current, AA999-AAA legacy)
    ThailandTnin,       // Thai National Identification Number (13 digits, mod-11 check)
    TurkeyTckn,         // Turkey TCKN (T.C. Kimlik Numarası, 11 digits, NVI mod-10 dual check)
    TurkeyLicensePlate, // Turkey license plate (province 01-81 + 1-3 letters + 2-4 digits)
    SingaporeNric,      // Singapore NRIC/FIN
    SingaporeUen,       // Singapore Unique Entity Number (3 layout variants, opaque check letter)
    FinlandHetu,        // Finnish personal identity code
    PolandPesel,        // Polish personal identity number (PESEL)
    ItalyFiscalCode,    // Italian Codice Fiscale
    ItalyVat,           // Italian Partita IVA (11 digits, mod-10 Luhn-style)
    ItalyPassport,      // Italian passport (2 letters + 7 digits)
    ItalyIdentityCard,  // Italian Carta d'Identità (paper, CIE 2.0, CIE 3.0)
    ItalyDriverLicense, // Italian Patente di Guida (standard + U1 Carta Conducente)
    SpainNif,           // Spanish NIF (Numero de Identificacion Fiscal)
    SpainNie,           // Spanish NIE (Numero de Identidad de Extranjero)
    SpainPassport,      // Spanish passport (3 letters + 6 digits, no checksum)
    UkNi,               // UK National Insurance Number (NINO)
    UkNhs,              // UK NHS Number (10 digits, mod-11 weighted checksum)
    UkPassport,         // UK Passport (2 letters + 7 digits)
    UkDrivingLicence,   // UK DVLA Driving Licence (16-char DVLA structural format)
    SwedenPersonnummer, // Swedish personal identity number (YYMMDD/YYYYMMDD + NNN + Luhn)
    SwedenOrgnummer,    // Swedish organisationsnummer (10 digits, third digit >= 2, Luhn)
    GermanyTaxId,       // German Steuer-IdNr (11 digits, ISO 7064 mod-11,10 + structural rule)
    GermanyIdCard,      // German Personalausweis / nPA (ICAO Doc 9303 check digit)
    GermanyPassport,    // German Reisepass (ICAO Doc 9303 check digit)

    // Organizational identifiers
    EmployeeId,
    StudentId,
    BadgeNumber, // Physical security badges, facility access IDs
    VehicleId,

    // Location identifiers
    GPSCoordinate,
    StreetAddress,
    PostalCode,
    NamedLocation, // Free-text city / country / region names (gazetteer-detected)

    // Medical/Health identifiers (HIPAA PHI)
    MedicalRecordNumber, // MRN, Patient ID
    HealthInsurance,     // Policy, Member, Group numbers
    Prescription,        // RX numbers
    ProviderID,          // NPI (National Provider Identifier)
    MedicalCode,         // ICD-10, CPT codes
    MedicalLicense,      // DEA numbers, state medical board licenses
    UsClia, // US CLIA lab certificate (NNDNNNNNNN — SSA state code + literal D + 7 digits)

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

    /// Returns `true` if this span overlaps `other` by at least one position.
    ///
    /// Spans are half-open (`start` inclusive, `end` exclusive), so spans that
    /// merely touch — `[0, 5)` and `[5, 10)` — do **not** intersect.
    ///
    /// Mirrors [`PiiSpan::intersects`](crate::anonymize::PiiSpan::intersects).
    /// The definitions are intentionally duplicated rather than shared:
    /// `IdentifierMatch` is a Layer 1 primitive and `PiiSpan` is a Layer 3
    /// trait, so implementing it here would invert the layer architecture.
    #[must_use]
    pub fn intersects(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Returns `true` if this span fully encloses `other`.
    ///
    /// Containment is inclusive: a span contains itself, and contains any
    /// span with identical indices.
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    /// Returns `true` if this span is fully enclosed by `other`.
    ///
    /// The mirror of [`contains`](Self::contains): `a.contained_in(b)` is
    /// exactly `b.contains(a)`.
    #[must_use]
    pub fn contained_in(&self, other: &Self) -> bool {
        other.start <= self.start && self.end <= other.end
    }

    /// Returns `true` if both spans cover exactly the same range.
    ///
    /// Compares indices only — two matches with equal indices but different
    /// [`IdentifierType`] or [`DetectionConfidence`] still compare equal here.
    #[must_use]
    pub fn equal_indices(&self, other: &Self) -> bool {
        self.start == other.start && self.end == other.end
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

    // ------------------------------------------------------------------
    // Span helpers
    // ------------------------------------------------------------------

    /// Builds a match over `[start, end)` with a fixed type and confidence.
    fn span(start: usize, end: usize) -> IdentifierMatch {
        IdentifierMatch::new(
            start,
            end,
            "x".to_string(),
            IdentifierType::Email,
            DetectionConfidence::High,
        )
    }

    #[test]
    fn test_intersects_partial_overlap() {
        assert!(span(0, 10).intersects(&span(5, 15)));
        assert!(span(5, 15).intersects(&span(0, 10)));
    }

    #[test]
    fn test_intersects_touching_spans_do_not_overlap() {
        // Half-open: [0, 5) and [5, 10) share no position.
        assert!(!span(0, 5).intersects(&span(5, 10)));
        assert!(!span(5, 10).intersects(&span(0, 5)));
    }

    #[test]
    fn test_intersects_disjoint() {
        assert!(!span(0, 5).intersects(&span(10, 15)));
    }

    #[test]
    fn test_contains_strict_and_equal() {
        assert!(span(0, 20).contains(&span(5, 10)));
        // Containment is inclusive, so a span contains itself.
        assert!(span(0, 20).contains(&span(0, 20)));
        assert!(!span(5, 10).contains(&span(0, 20)));
    }

    #[test]
    fn test_contained_in_mirrors_contains() {
        let inner = span(5, 10);
        let outer = span(0, 20);
        assert!(inner.contained_in(&outer));
        assert_eq!(inner.contained_in(&outer), outer.contains(&inner));
        assert!(!outer.contained_in(&inner));
    }

    #[test]
    fn test_equal_indices_ignores_type_and_confidence() {
        let a = IdentifierMatch::new(
            3,
            9,
            "a".to_string(),
            IdentifierType::Email,
            DetectionConfidence::Low,
        );
        let b = IdentifierMatch::new(
            3,
            9,
            "b".to_string(),
            IdentifierType::PhoneNumber,
            DetectionConfidence::High,
        );
        assert!(a.equal_indices(&b));
        assert!(!a.equal_indices(&span(3, 10)));
    }

    #[test]
    fn test_empty_span_helpers() {
        let empty = span(5, 5);
        assert!(empty.is_empty());
        // A zero-width span strictly inside another still satisfies the
        // half-open overlap test (5 < 10 && 0 < 5), matching `PiiSpan`.
        // Zero-width matches are excluded by `ConflictResolution` instead.
        assert!(empty.intersects(&span(0, 10)));
        assert!(empty.contained_in(&span(0, 10)));
        // At the outer edge there is no overlap: [10,10) vs [0,10).
        assert!(!span(10, 10).intersects(&span(0, 10)));
    }
}
