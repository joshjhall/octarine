//! GDPR Lawful Basis for processing personal data
//!
//! Every processing of personal data must have a lawful basis under Article 6.

use serde::{Deserialize, Serialize};

/// GDPR Article 6 - Lawful basis for processing personal data
///
/// Every processing of personal data must have a lawful basis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GdprBasis {
    /// Article 6(1)(a): Data subject has given consent
    Consent,

    /// Article 6(1)(b): Processing necessary for contract performance
    Contract,

    /// Article 6(1)(c): Processing necessary for legal obligation
    LegalObligation,

    /// Article 6(1)(d): Processing necessary to protect vital interests
    VitalInterests,

    /// Article 6(1)(e): Processing necessary for public interest/official authority
    PublicTask,

    /// Article 6(1)(f): Processing necessary for legitimate interests
    LegitimateInterests,
}

impl GdprBasis {
    /// Get the basis name
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Consent => "consent",
            Self::Contract => "contract",
            Self::LegalObligation => "legal_obligation",
            Self::VitalInterests => "vital_interests",
            Self::PublicTask => "public_task",
            Self::LegitimateInterests => "legitimate_interests",
        }
    }

    /// Get the GDPR article reference
    pub fn article(&self) -> &'static str {
        match self {
            Self::Consent => "Art. 6(1)(a)",
            Self::Contract => "Art. 6(1)(b)",
            Self::LegalObligation => "Art. 6(1)(c)",
            Self::VitalInterests => "Art. 6(1)(d)",
            Self::PublicTask => "Art. 6(1)(e)",
            Self::LegitimateInterests => "Art. 6(1)(f)",
        }
    }

    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::Consent => "Data subject has given consent",
            Self::Contract => "Necessary for contract performance",
            Self::LegalObligation => "Necessary for legal obligation",
            Self::VitalInterests => "Necessary to protect vital interests",
            Self::PublicTask => "Necessary for public interest",
            Self::LegitimateInterests => "Necessary for legitimate interests",
        }
    }
}

impl std::fmt::Display for GdprBasis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
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
    fn test_gdpr_basis_display() {
        assert_eq!(GdprBasis::Consent.to_string(), "consent");
        assert_eq!(GdprBasis::Consent.article(), "Art. 6(1)(a)");
    }

    #[test]
    fn test_gdpr_basis_description() {
        assert_eq!(
            GdprBasis::Contract.description(),
            "Necessary for contract performance"
        );
    }
}
