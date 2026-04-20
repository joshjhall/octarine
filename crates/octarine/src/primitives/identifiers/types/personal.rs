//! Personal identifier types (phone regions, credentials)

use super::core::{DetectionConfidence, IdentifierMatch, IdentifierType};

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
