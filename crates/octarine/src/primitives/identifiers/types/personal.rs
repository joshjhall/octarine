//! Personal identifier types (phone regions, credentials)

use super::core::{DetectionConfidence, IdentifierMatch, IdentifierType};

/// ISO 3166-1 alpha-2 country code (e.g. `US`, `NG`).
///
/// A `Copy` two-byte wrapper used by [`PhoneRegion::Other`] to represent any
/// ISO country without enumerating all ~250 of them as named variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    /// Build a country code from an ISO alpha-2 string.
    ///
    /// Returns `None` unless `iso` is exactly two ASCII alphabetic characters.
    /// The code is upper-cased for consistency.
    #[must_use]
    pub fn new(iso: &str) -> Option<Self> {
        match iso.as_bytes() {
            [a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => {
                Some(Self([a.to_ascii_uppercase(), b.to_ascii_uppercase()]))
            }
            _ => None,
        }
    }

    /// The ISO alpha-2 code as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // `new` guarantees both bytes are ASCII alphabetic, so the buffer is
        // always valid UTF-8; the fallback keeps this panic-free regardless.
        std::str::from_utf8(&self.0).unwrap_or("??")
    }
}

impl std::fmt::Display for CountryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Phone number region enumeration
///
/// Detected from the parsed country calling code (via libphonenumber). Named
/// variants cover the most common regions; any other recognised ISO country is
/// carried in [`PhoneRegion::Other`] for full ISO 3166-1 coverage.
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
    /// Israel (+972)
    Israel,
    /// South Korea (+82)
    SouthKorea,
    /// Mexico (+52)
    Mexico,
    /// Turkey (+90)
    Turkey,
    /// Nigeria (+234)
    Nigeria,
    /// South Africa (+27)
    SouthAfrica,
    /// Egypt (+20)
    Egypt,
    /// Kenya (+254)
    Kenya,
    /// Any other recognised ISO 3166-1 country, identified by alpha-2 code
    Other(CountryCode),
    /// Unknown or unrecognized region
    Unknown,
}

impl PhoneRegion {
    /// Map a libphonenumber country to a `PhoneRegion`.
    ///
    /// `code` is the numeric country calling code and `iso` the optional ISO
    /// alpha-2 region id. Named variants are matched by calling code first (so
    /// `+1` is always [`NorthAmerica`](Self::NorthAmerica) regardless of
    /// US/Canada disambiguation). Any other recognised ISO country becomes
    /// [`Other`](Self::Other); a missing or invalid id is
    /// [`Unknown`](Self::Unknown).
    #[must_use]
    pub fn from_country(code: u16, iso: Option<&str>) -> Self {
        match code {
            1 => Self::NorthAmerica,
            44 => Self::Uk,
            49 => Self::Germany,
            33 => Self::France,
            34 => Self::Spain,
            39 => Self::Italy,
            61 => Self::Australia,
            81 => Self::Japan,
            86 => Self::China,
            91 => Self::India,
            55 => Self::Brazil,
            7 => Self::Russia,
            972 => Self::Israel,
            82 => Self::SouthKorea,
            52 => Self::Mexico,
            90 => Self::Turkey,
            234 => Self::Nigeria,
            27 => Self::SouthAfrica,
            20 => Self::Egypt,
            254 => Self::Kenya,
            _ => iso
                .and_then(CountryCode::new)
                .map_or(Self::Unknown, Self::Other),
        }
    }
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
            Self::Israel => write!(f, "Israel (+972)"),
            Self::SouthKorea => write!(f, "South Korea (+82)"),
            Self::Mexico => write!(f, "Mexico (+52)"),
            Self::Turkey => write!(f, "Turkey (+90)"),
            Self::Nigeria => write!(f, "Nigeria (+234)"),
            Self::SouthAfrica => write!(f, "South Africa (+27)"),
            Self::Egypt => write!(f, "Egypt (+20)"),
            Self::Kenya => write!(f, "Kenya (+254)"),
            Self::Other(cc) => write!(f, "{cc}"),
            Self::Unknown => write!(f, "Unknown region"),
        }
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
