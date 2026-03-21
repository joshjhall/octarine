//! Personal identifier types
//!
//! Types related to personal identifiers:
//! - `PhoneRegion` - Phone number regions
//! - `CredentialType` - Types of credentials
//! - `CredentialMatch` - Result of finding credentials in text

// ============================================================================
// Phone Region
// ============================================================================

/// Phone number region enumeration
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
    /// Unknown region
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

impl From<crate::primitives::identifiers::PhoneRegion> for PhoneRegion {
    fn from(r: crate::primitives::identifiers::PhoneRegion) -> Self {
        use crate::primitives::identifiers::PhoneRegion as P;
        match r {
            P::NorthAmerica => Self::NorthAmerica,
            P::Uk => Self::Uk,
            P::Germany => Self::Germany,
            P::France => Self::France,
            P::Spain => Self::Spain,
            P::Italy => Self::Italy,
            P::Australia => Self::Australia,
            P::Japan => Self::Japan,
            P::China => Self::China,
            P::India => Self::India,
            P::Brazil => Self::Brazil,
            P::Russia => Self::Russia,
            P::Unknown => Self::Unknown,
        }
    }
}

impl From<PhoneRegion> for crate::primitives::identifiers::PhoneRegion {
    fn from(r: PhoneRegion) -> Self {
        match r {
            PhoneRegion::NorthAmerica => Self::NorthAmerica,
            PhoneRegion::Uk => Self::Uk,
            PhoneRegion::Germany => Self::Germany,
            PhoneRegion::France => Self::France,
            PhoneRegion::Spain => Self::Spain,
            PhoneRegion::Italy => Self::Italy,
            PhoneRegion::Australia => Self::Australia,
            PhoneRegion::Japan => Self::Japan,
            PhoneRegion::China => Self::China,
            PhoneRegion::India => Self::India,
            PhoneRegion::Brazil => Self::Brazil,
            PhoneRegion::Russia => Self::Russia,
            PhoneRegion::Unknown => Self::Unknown,
        }
    }
}

// ============================================================================
// Credential Type
// ============================================================================

/// Types of credentials that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialType {
    /// Password credential
    Password,
    /// PIN code credential
    Pin,
    /// Security question answer
    SecurityAnswer,
    /// Passphrase credential
    Passphrase,
    /// Generic credential
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
}

impl From<crate::primitives::identifiers::CredentialType> for CredentialType {
    fn from(c: crate::primitives::identifiers::CredentialType) -> Self {
        use crate::primitives::identifiers::CredentialType as P;
        match c {
            P::Password => Self::Password,
            P::Pin => Self::Pin,
            P::SecurityAnswer => Self::SecurityAnswer,
            P::Passphrase => Self::Passphrase,
            P::Generic => Self::Generic,
        }
    }
}

impl From<CredentialType> for crate::primitives::identifiers::CredentialType {
    fn from(c: CredentialType) -> Self {
        match c {
            CredentialType::Password => Self::Password,
            CredentialType::Pin => Self::Pin,
            CredentialType::SecurityAnswer => Self::SecurityAnswer,
            CredentialType::Passphrase => Self::Passphrase,
            CredentialType::Generic => Self::Generic,
        }
    }
}

// ============================================================================
// Credential Match
// ============================================================================

/// Result of finding a credential pattern in text
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
}

impl From<crate::primitives::identifiers::CredentialMatch> for CredentialMatch {
    fn from(m: crate::primitives::identifiers::CredentialMatch) -> Self {
        Self {
            start: m.start,
            end: m.end,
            value: m.value,
            credential_type: m.credential_type.into(),
            label: m.label,
        }
    }
}

impl From<CredentialMatch> for crate::primitives::identifiers::CredentialMatch {
    fn from(m: CredentialMatch) -> Self {
        Self::new(m.start, m.end, m.value, m.credential_type.into(), m.label)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_phone_region_display() {
        assert_eq!(PhoneRegion::NorthAmerica.to_string(), "North America (+1)");
        assert_eq!(PhoneRegion::Uk.to_string(), "United Kingdom (+44)");
    }

    #[test]
    fn test_credential_type_name() {
        assert_eq!(CredentialType::Password.name(), "password");
        assert_eq!(CredentialType::Pin.name(), "pin");
    }

    #[test]
    fn test_credential_match() {
        let m = CredentialMatch::new(
            10,
            20,
            "secret123".to_string(),
            CredentialType::Password,
            "password".to_string(),
        );
        assert_eq!(m.len(), 10);
        assert!(!m.is_empty());
    }
}
