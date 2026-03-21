//! SOC2 Trust Service Criteria controls
//!
//! These map to the AICPA Trust Service Criteria used in SOC2 audits.

use serde::{Deserialize, Serialize};

/// SOC2 Trust Service Criteria controls
///
/// These map to the AICPA Trust Service Criteria used in SOC2 audits.
/// Events tagged with these controls provide audit evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum Soc2Control {
    // === Security (CC6) - Logical and Physical Access Controls ===
    /// CC6.1: Logical access security - authentication, access control
    ///
    /// Evidence: Login events, access grants/revocations, auth failures
    #[serde(rename = "CC6_1")]
    CC6_1,

    /// CC6.2: Registration and authorization of users
    ///
    /// Evidence: User provisioning, role assignments, access reviews
    #[serde(rename = "CC6_2")]
    CC6_2,

    /// CC6.3: User access removal upon termination
    ///
    /// Evidence: Account deactivation, access revocation events
    #[serde(rename = "CC6_3")]
    CC6_3,

    /// CC6.6: Protection against security threats
    ///
    /// Evidence: Security scans, threat detection, incident response
    #[serde(rename = "CC6_6")]
    CC6_6,

    /// CC6.7: Transmission security - data in transit
    ///
    /// Evidence: TLS/encryption events, secure channel establishment
    #[serde(rename = "CC6_7")]
    CC6_7,

    /// CC6.8: Malicious software prevention
    ///
    /// Evidence: Malware scans, injection detection, input validation
    #[serde(rename = "CC6_8")]
    CC6_8,

    // === Availability (CC7) - System Operations ===
    /// CC7.1: System monitoring and incident detection
    ///
    /// Evidence: Health checks, anomaly detection, alerts
    #[serde(rename = "CC7_1")]
    CC7_1,

    /// CC7.2: Incident response and recovery
    ///
    /// Evidence: Incident tickets, escalations, remediation actions
    #[serde(rename = "CC7_2")]
    CC7_2,

    /// CC7.3: System recovery and business continuity
    ///
    /// Evidence: Backup events, failover tests, recovery operations
    #[serde(rename = "CC7_3")]
    CC7_3,

    // === Confidentiality (CC8) - Data Protection ===
    /// CC8.1: Protection of confidential information
    ///
    /// Evidence: Encryption events, access to sensitive data, PII handling
    #[serde(rename = "CC8_1")]
    CC8_1,

    // === Processing Integrity (CC9) ===
    /// CC9.1: Complete, accurate, timely processing
    ///
    /// Evidence: Transaction logs, validation events, data integrity checks
    #[serde(rename = "CC9_1")]
    CC9_1,

    /// CC9.2: Error handling and correction
    ///
    /// Evidence: Error logs, retry events, data correction operations
    #[serde(rename = "CC9_2")]
    CC9_2,

    // === Change Management (CC3) ===
    /// CC3.1: Change management - infrastructure and software changes
    ///
    /// Evidence: Deployments, config changes, migrations
    #[serde(rename = "CC3_1")]
    CC3_1,

    /// CC3.2: Change testing and approval
    ///
    /// Evidence: Test runs, approval workflows, rollbacks
    #[serde(rename = "CC3_2")]
    CC3_2,

    // === Risk Assessment (CC4) ===
    /// CC4.1: Risk identification and assessment
    ///
    /// Evidence: Vulnerability scans, risk assessments, security reviews
    #[serde(rename = "CC4_1")]
    CC4_1,

    // === Monitoring (CC5) ===
    /// CC5.1: Control monitoring activities
    ///
    /// Evidence: Audit logs, compliance checks, control validations
    #[serde(rename = "CC5_1")]
    CC5_1,
}

impl Soc2Control {
    /// Get the control identifier string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CC6_1 => "CC6.1",
            Self::CC6_2 => "CC6.2",
            Self::CC6_3 => "CC6.3",
            Self::CC6_6 => "CC6.6",
            Self::CC6_7 => "CC6.7",
            Self::CC6_8 => "CC6.8",
            Self::CC7_1 => "CC7.1",
            Self::CC7_2 => "CC7.2",
            Self::CC7_3 => "CC7.3",
            Self::CC8_1 => "CC8.1",
            Self::CC9_1 => "CC9.1",
            Self::CC9_2 => "CC9.2",
            Self::CC3_1 => "CC3.1",
            Self::CC3_2 => "CC3.2",
            Self::CC4_1 => "CC4.1",
            Self::CC5_1 => "CC5.1",
        }
    }

    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::CC6_1 => "Logical access security",
            Self::CC6_2 => "User registration and authorization",
            Self::CC6_3 => "User access removal",
            Self::CC6_6 => "Security threat protection",
            Self::CC6_7 => "Transmission security",
            Self::CC6_8 => "Malicious software prevention",
            Self::CC7_1 => "System monitoring",
            Self::CC7_2 => "Incident response",
            Self::CC7_3 => "System recovery",
            Self::CC8_1 => "Confidential information protection",
            Self::CC9_1 => "Processing integrity",
            Self::CC9_2 => "Error handling",
            Self::CC3_1 => "Change management",
            Self::CC3_2 => "Change testing",
            Self::CC4_1 => "Risk assessment",
            Self::CC5_1 => "Control monitoring",
        }
    }
}

impl std::fmt::Display for Soc2Control {
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
    fn test_soc2_control_display() {
        assert_eq!(Soc2Control::CC6_1.to_string(), "CC6.1");
        assert_eq!(Soc2Control::CC8_1.as_str(), "CC8.1");
    }

    #[test]
    fn test_soc2_control_description() {
        assert_eq!(Soc2Control::CC6_1.description(), "Logical access security");
        assert_eq!(Soc2Control::CC7_2.description(), "Incident response");
    }
}
