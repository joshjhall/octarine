//! PCI-DSS Requirements for cardholder data protection
//!
//! Relevant requirements from PCI-DSS v4.0 for logging and access control.

use serde::{Deserialize, Serialize};

/// PCI-DSS Requirements for cardholder data protection
///
/// Relevant requirements from PCI-DSS v4.0 for logging and access control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum PciDssRequirement {
    /// Req 1: Install and maintain network security controls
    #[serde(rename = "REQ_1")]
    Req1,

    /// Req 3: Protect stored account data
    ///
    /// Evidence: Encryption events, data access logs, masking
    #[serde(rename = "REQ_3")]
    Req3,

    /// Req 4: Protect cardholder data with strong cryptography during transmission
    #[serde(rename = "REQ_4")]
    Req4,

    /// Req 7: Restrict access to system components and cardholder data
    ///
    /// Evidence: Access control events, role assignments, permission checks
    #[serde(rename = "REQ_7")]
    Req7,

    /// Req 8: Identify users and authenticate access
    ///
    /// Evidence: Authentication events, MFA, password management
    #[serde(rename = "REQ_8")]
    Req8,

    /// Req 9: Restrict physical access to cardholder data
    #[serde(rename = "REQ_9")]
    Req9,

    /// Req 10: Log and monitor all access to system components and cardholder data
    ///
    /// Evidence: All audit logs, access trails
    #[serde(rename = "REQ_10")]
    Req10,

    /// Req 11: Test security of systems and networks regularly
    #[serde(rename = "REQ_11")]
    Req11,

    /// Req 12: Support information security with organizational policies and programs
    #[serde(rename = "REQ_12")]
    Req12,
}

impl PciDssRequirement {
    /// Get the requirement identifier
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Req1 => "Req 1",
            Self::Req3 => "Req 3",
            Self::Req4 => "Req 4",
            Self::Req7 => "Req 7",
            Self::Req8 => "Req 8",
            Self::Req9 => "Req 9",
            Self::Req10 => "Req 10",
            Self::Req11 => "Req 11",
            Self::Req12 => "Req 12",
        }
    }

    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::Req1 => "Network security controls",
            Self::Req3 => "Protect stored account data",
            Self::Req4 => "Cryptography during transmission",
            Self::Req7 => "Restrict access to cardholder data",
            Self::Req8 => "Identify and authenticate access",
            Self::Req9 => "Restrict physical access",
            Self::Req10 => "Log and monitor access",
            Self::Req11 => "Test security regularly",
            Self::Req12 => "Information security policies",
        }
    }
}

impl std::fmt::Display for PciDssRequirement {
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
    fn test_pci_dss_display() {
        assert_eq!(PciDssRequirement::Req10.to_string(), "Req 10");
    }

    #[test]
    fn test_pci_dss_description() {
        assert_eq!(
            PciDssRequirement::Req8.description(),
            "Identify and authenticate access"
        );
    }
}
