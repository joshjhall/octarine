//! Administrative action audit builder.
//!
//! Provides a fluent API for auditing privileged administrative operations.

use crate::observe::audit::event::AuditEvent;
use crate::observe::audit::types::Outcome;
use crate::observe::compliance::{ComplianceTags, Iso27001Control, Soc2Control};
use crate::observe::types::EventType;

/// Builder for administrative action audit events.
///
/// Use this for privileged operations that require special tracking:
/// - Configuration changes
/// - User/role management
/// - Security policy changes
/// - System maintenance
///
/// # Example
///
/// ```ignore
/// use octarine::observe::audit::Audit;
///
/// Audit::admin("update_security_policy")
///     .target("security.toml")
///     .justification("CVE-2023-1234 mitigation")
///     .approved_by("security-team")
///     .success()
///     .emit();
/// ```
#[derive(Debug, Clone)]
pub struct AdminAuditBuilder {
    operation: String,
    target: Option<String>,
    justification: Option<String>,
    approved_by: Option<String>,
    previous_value: Option<String>,
    new_value: Option<String>,
}

impl AdminAuditBuilder {
    /// Create a new administrative action audit builder.
    pub fn new(operation: &str) -> Self {
        Self {
            operation: operation.to_string(),
            target: None,
            justification: None,
            approved_by: None,
            previous_value: None,
            new_value: None,
        }
    }

    /// Set the target of the administrative action.
    ///
    /// This could be a configuration file, user, role, or system component.
    #[must_use]
    pub fn target(mut self, target: &str) -> Self {
        self.target = Some(target.to_string());
        self
    }

    /// Set the justification for the administrative action.
    ///
    /// This should explain why the action was taken.
    #[must_use]
    pub fn justification(mut self, justification: &str) -> Self {
        self.justification = Some(justification.to_string());
        self
    }

    /// Set who approved the administrative action.
    ///
    /// For privileged operations requiring approval.
    #[must_use]
    pub fn approved_by(mut self, approver: &str) -> Self {
        self.approved_by = Some(approver.to_string());
        self
    }

    /// Set the previous value before the change.
    ///
    /// Useful for configuration changes to track what was modified.
    #[must_use]
    pub fn previous_value(mut self, value: &str) -> Self {
        self.previous_value = Some(value.to_string());
        self
    }

    /// Set the new value after the change.
    ///
    /// Useful for configuration changes to track what was modified.
    #[must_use]
    pub fn new_value(mut self, value: &str) -> Self {
        self.new_value = Some(value.to_string());
        self
    }

    /// Build a successful administrative action event.
    #[must_use]
    pub fn success(self) -> AuditEvent {
        self.build_event(Outcome::Success)
    }

    /// Build a failed administrative action event.
    #[must_use]
    pub fn failure(self, reason: &str) -> AuditEvent {
        self.build_event(Outcome::Failure(reason.to_string()))
    }

    /// Build a pending administrative action event.
    ///
    /// Use this for actions that require approval or are in progress.
    #[must_use]
    pub fn pending(self) -> AuditEvent {
        self.build_event(Outcome::Pending)
    }

    /// Build an administrative action event with unknown outcome.
    ///
    /// Use this when the action result cannot be determined.
    #[must_use]
    pub fn unknown(self) -> AuditEvent {
        self.build_event(Outcome::Unknown)
    }

    fn build_event(self, outcome: Outcome) -> AuditEvent {
        let operation = format!("admin.{}", self.operation);
        let target_info = self
            .target
            .as_ref()
            .map(|t| format!(" on {}", t))
            .unwrap_or_default();

        let message = match &outcome {
            Outcome::Success => {
                format!("Admin action '{}' succeeded{}", self.operation, target_info)
            }
            Outcome::Failure(reason) => {
                format!(
                    "Admin action '{}' failed{}: {}",
                    self.operation, target_info, reason
                )
            }
            Outcome::Pending => {
                format!("Admin action '{}' pending{}", self.operation, target_info)
            }
            Outcome::Unknown => {
                format!(
                    "Admin action '{}' outcome unknown{}",
                    self.operation, target_info
                )
            }
        };

        let event_type = match &outcome {
            Outcome::Success => EventType::ResourceUpdated,
            Outcome::Failure(_) => EventType::SystemError,
            Outcome::Pending | Outcome::Unknown => EventType::Info,
        };

        let mut event = AuditEvent::new(&operation, message, outcome, event_type)
            .with_metadata("admin.operation", serde_json::json!(&self.operation));

        if let Some(target) = &self.target {
            event = event.with_metadata("admin.target", serde_json::json!(target));
        }

        if let Some(justification) = &self.justification {
            event = event.with_metadata("admin.justification", serde_json::json!(justification));
        }

        if let Some(approver) = &self.approved_by {
            event = event.with_metadata("admin.approved_by", serde_json::json!(approver));
        }

        if let Some(prev) = &self.previous_value {
            event = event.with_metadata("admin.previous_value", serde_json::json!(prev));
        }

        if let Some(new) = &self.new_value {
            event = event.with_metadata("admin.new_value", serde_json::json!(new));
        }

        // Apply compliance tags for administrative actions
        let tags = ComplianceTags::new()
            .with_soc2(Soc2Control::CC6_3) // Privileged access management
            .with_soc2(Soc2Control::CC3_1) // Change management
            .with_iso27001(Iso27001Control::A5_18) // Access rights
            .with_iso27001(Iso27001Control::A8_9) // Configuration management
            .with_iso27001(Iso27001Control::A8_15) // Logging
            .as_evidence();

        event.with_compliance_tags(tags)
    }
}

impl Default for AdminAuditBuilder {
    fn default() -> Self {
        Self::new("")
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_success() {
        let event = AdminAuditBuilder::new("update_config")
            .target("database.toml")
            .success();

        assert_eq!(event.operation(), "admin.update_config");
        assert!(event.is_success());
        assert!(event.message().contains("database.toml"));
    }

    #[test]
    fn test_admin_failure() {
        let event = AdminAuditBuilder::new("delete_user")
            .target("admin_user")
            .failure("Cannot delete admin user");

        assert!(!event.is_success());
        assert!(event.message().contains("Cannot delete admin user"));
    }

    #[test]
    fn test_admin_with_justification() {
        let event = AdminAuditBuilder::new("disable_feature")
            .target("experimental_api")
            .justification("Security vulnerability CVE-2024-1234")
            .approved_by("security-team")
            .success();

        assert_eq!(
            event.metadata.get("admin.justification"),
            Some(&serde_json::json!("Security vulnerability CVE-2024-1234"))
        );
        assert_eq!(
            event.metadata.get("admin.approved_by"),
            Some(&serde_json::json!("security-team"))
        );
    }

    #[test]
    fn test_admin_with_values() {
        let event = AdminAuditBuilder::new("update_limit")
            .target("rate_limit")
            .previous_value("100")
            .new_value("200")
            .success();

        assert_eq!(
            event.metadata.get("admin.previous_value"),
            Some(&serde_json::json!("100"))
        );
        assert_eq!(
            event.metadata.get("admin.new_value"),
            Some(&serde_json::json!("200"))
        );
    }

    #[test]
    fn test_compliance_tags() {
        let event = AdminAuditBuilder::new("test").success();

        assert!(event.compliance_tags.soc2.contains(&Soc2Control::CC6_3));
        assert!(event.compliance_tags.soc2.contains(&Soc2Control::CC3_1));
        assert!(event.compliance_tags.is_evidence);
    }
}
