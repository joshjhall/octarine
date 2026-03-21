//! HIPAA Safeguard categories
//!
//! The HIPAA Security Rule requires three types of safeguards for PHI.

use serde::{Deserialize, Serialize};

/// HIPAA Safeguard categories
///
/// The HIPAA Security Rule requires three types of safeguards for PHI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum HipaaSafeguard {
    /// Administrative safeguards - policies, procedures, workforce training
    ///
    /// §164.308: Security management, workforce security, information access management
    Administrative,

    /// Physical safeguards - facility access, workstation security
    ///
    /// §164.310: Facility access controls, workstation use, device controls
    Physical,

    /// Technical safeguards - access control, audit, encryption
    ///
    /// §164.312: Access control, audit controls, integrity, transmission security
    Technical,
}

impl HipaaSafeguard {
    /// Get the safeguard name
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Administrative => "administrative",
            Self::Physical => "physical",
            Self::Technical => "technical",
        }
    }

    /// Get the HIPAA section reference
    pub fn section(&self) -> &'static str {
        match self {
            Self::Administrative => "§164.308",
            Self::Physical => "§164.310",
            Self::Technical => "§164.312",
        }
    }

    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::Administrative => "Policies, procedures, workforce security",
            Self::Physical => "Facility access, workstation security",
            Self::Technical => "Access control, audit, encryption",
        }
    }
}

impl std::fmt::Display for HipaaSafeguard {
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
    fn test_hipaa_safeguard_display() {
        assert_eq!(HipaaSafeguard::Technical.to_string(), "technical");
        assert_eq!(HipaaSafeguard::Technical.section(), "§164.312");
    }

    #[test]
    fn test_hipaa_safeguard_description() {
        assert_eq!(
            HipaaSafeguard::Administrative.description(),
            "Policies, procedures, workforce security"
        );
    }
}
