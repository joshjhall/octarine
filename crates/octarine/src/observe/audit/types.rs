//! Audit type definitions.
//!
//! This module contains enums and types used across the audit module.

use serde::{Deserialize, Serialize};

// ============================================================================
// Authentication Types
// ============================================================================

/// Type of authentication event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    /// User login attempt.
    #[default]
    Login,
    /// User logout.
    Logout,
    /// Password change.
    PasswordChange,
    /// Password reset request.
    PasswordReset,
    /// Token refresh.
    TokenRefresh,
    /// Session created.
    SessionCreate,
    /// Session destroyed.
    SessionDestroy,
}

// ============================================================================
// Data Access Types
// ============================================================================

/// Type of data access operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessType {
    /// Read/query operation.
    #[default]
    Read,
    /// Create operation.
    Create,
    /// Update/write operation.
    Write,
    /// Delete operation.
    Delete,
    /// Export/download operation.
    Export,
    /// Bulk operation.
    Bulk,
}

/// Data classification level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    /// Public data - no restrictions.
    Public,
    /// Internal data - organization only.
    #[default]
    Internal,
    /// Confidential data - restricted access.
    Confidential,
    /// Restricted/sensitive data - highest protection.
    Restricted,
}

// ============================================================================
// Security Types
// ============================================================================

/// Threat severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatLevel {
    /// Low severity - informational.
    Low,
    /// Medium severity - needs attention.
    #[default]
    Medium,
    /// High severity - immediate action needed.
    High,
    /// Critical severity - emergency response.
    Critical,
}

/// Action taken in response to a security event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityAction {
    /// Event was logged only.
    #[default]
    Logged,
    /// Request/action was blocked.
    Blocked,
    /// Alert was sent.
    Alerted,
    /// Incident was escalated.
    Escalated,
    /// Request was allowed (after review).
    Allowed,
}

// ============================================================================
// Compliance Types
// ============================================================================

/// Compliance framework identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    /// SOC 2 Type II (Trust Service Criteria).
    Soc2,
    /// HIPAA (Health Insurance Portability and Accountability Act).
    Hipaa,
    /// GDPR (General Data Protection Regulation).
    Gdpr,
    /// PCI-DSS (Payment Card Industry Data Security Standard).
    PciDss,
    /// ISO 27001 (Information Security Management).
    Iso27001,
}

/// Result of a compliance check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceResult {
    /// Control passed.
    #[default]
    Passed,
    /// Control failed.
    Failed,
    /// Control not applicable.
    NotApplicable,
}

// ============================================================================
// Event Outcome
// ============================================================================

/// Outcome of an audited operation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Operation succeeded.
    #[default]
    Success,
    /// Operation failed with reason.
    Failure(String),
    /// Operation is pending/in-progress.
    Pending,
    /// Outcome is unknown/indeterminate.
    Unknown,
}

impl Outcome {
    /// Check if the outcome is a success.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    /// Check if the outcome is a failure.
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        matches!(self, Self::Failure(_))
    }

    /// Check if the outcome is pending.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Check if the outcome is unknown.
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// Get the failure reason if any.
    #[must_use]
    pub fn failure_reason(&self) -> Option<&str> {
        match self {
            Self::Failure(reason) => Some(reason),
            _ => None,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_type_serialization() {
        let auth_type = AuthType::Login;
        let json = serde_json::to_string(&auth_type).unwrap();
        assert_eq!(json, "\"login\"");
    }

    #[test]
    fn test_threat_level_ordering() {
        // ThreatLevel doesn't implement Ord, just Eq
        assert_eq!(ThreatLevel::Low, ThreatLevel::Low);
        assert_ne!(ThreatLevel::Low, ThreatLevel::Critical);
    }

    #[test]
    fn test_outcome_methods() {
        let success = Outcome::Success;
        assert!(success.is_success());
        assert!(!success.is_failure());
        assert!(success.failure_reason().is_none());

        let failure = Outcome::Failure("Invalid input".to_string());
        assert!(!failure.is_success());
        assert!(failure.is_failure());
        assert_eq!(failure.failure_reason(), Some("Invalid input"));
    }

    #[test]
    fn test_compliance_framework_serialization() {
        let framework = ComplianceFramework::Soc2;
        let json = serde_json::to_string(&framework).unwrap();
        assert_eq!(json, "\"soc2\"");

        let framework = ComplianceFramework::PciDss;
        let json = serde_json::to_string(&framework).unwrap();
        assert_eq!(json, "\"pci_dss\"");
    }
}
