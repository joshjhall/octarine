//! Audit event type for structured audit logging.
//!
//! `AuditEvent` is the result of audit builders, containing all the
//! information needed to emit a compliance-ready audit event.

use crate::observe::compliance::ComplianceTags;
use crate::observe::problem::Problem;
use crate::observe::types::{Event, EventType};
use crate::observe::writers;
use std::collections::HashMap;

use super::types::Outcome;

/// A structured audit event ready to be emitted.
///
/// Created by audit builders via `.success()` or `.failure()` methods.
/// Call `.emit()` to dispatch the event to configured writers.
///
/// # Example
///
/// ```ignore
/// use octarine::observe::audit::Audit;
///
/// Audit::auth()
///     .login("user@example.com")
///     .success()
///     .emit();
/// ```
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// The operation being audited (e.g., "auth.login", "data.read")
    pub(super) operation: String,

    /// Human-readable message describing the event
    pub(super) message: String,

    /// Outcome of the operation (success or failure with reason)
    pub(super) outcome: Outcome,

    /// Structured metadata for the event
    pub(super) metadata: HashMap<String, serde_json::Value>,

    /// Compliance framework tags for audit reporting
    pub(super) compliance_tags: ComplianceTags,

    /// The event type to use when emitting
    pub(super) event_type: EventType,
}

impl AuditEvent {
    /// Create a new audit event.
    ///
    /// Typically called by builders, not directly.
    pub(super) fn new(
        operation: impl Into<String>,
        message: impl Into<String>,
        outcome: Outcome,
        event_type: EventType,
    ) -> Self {
        Self {
            operation: operation.into(),
            message: message.into(),
            outcome,
            metadata: HashMap::new(),
            compliance_tags: ComplianceTags::new(),
            event_type,
        }
    }

    /// Add metadata to the event.
    pub(super) fn with_metadata(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Set compliance tags for the event.
    pub(super) fn with_compliance_tags(mut self, tags: ComplianceTags) -> Self {
        self.compliance_tags = tags;
        self
    }

    /// Emit the audit event to configured writers.
    ///
    /// This is the terminal operation that dispatches the event.
    /// Context (WHO/WHAT/WHEN/WHERE) is automatically captured.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Audit::admin("config_change")
    ///     .target("security.toml")
    ///     .success()
    ///     .emit();
    /// ```
    pub fn emit(self) {
        let event = self.build_observe_event();
        writers::dispatch(event);
    }

    /// Emit the audit event, returning an error if the dispatcher is unhealthy.
    ///
    /// Unlike [`emit()`](Self::emit), this method checks dispatcher health before
    /// queueing and returns an error if the event may be dropped.
    ///
    /// # Errors
    ///
    /// Returns an error if the dispatcher is degraded or unhealthy, indicating
    /// that the event may not be reliably delivered to writers.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Audit::admin("config_change")
    ///     .target("security.toml")
    ///     .success()
    ///     .try_emit()?;
    /// ```
    pub fn try_emit(self) -> Result<(), Problem> {
        // Check dispatcher health before emitting
        if !writers::dispatcher_is_healthy() {
            let stats = writers::dispatcher_stats();
            return Err(Problem::operation_failed(format!(
                "Audit event dispatch may be unreliable: dispatcher is unhealthy \
                 (queue: {}/{}, dropped: {})",
                stats.current_size, stats.capacity, stats.total_dropped
            )));
        }

        let event = self.build_observe_event();
        writers::dispatch(event);
        Ok(())
    }

    /// Build the underlying observe Event from this audit event.
    fn build_observe_event(self) -> Event {
        // Create the base event with auto-captured context
        let mut event = Event::new(self.event_type, &self.message);

        // Set operation in context
        event.context.operation = self.operation.clone();

        // Apply compliance tags
        event.context.compliance = self.compliance_tags;

        // Mark as compliance evidence
        event.context.compliance.is_evidence = true;

        // Mark as security-relevant for audit trail
        event.context.security_relevant = true;

        // Add standard metadata
        event = event.with_metadata("audit.operation", serde_json::json!(self.operation));
        event = event.with_metadata("audit.outcome", serde_json::json!(self.outcome));

        // Add custom metadata
        for (key, value) in self.metadata {
            event = event.with_metadata(key, value);
        }

        event
    }

    /// Get the operation name.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Get the message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the outcome.
    #[must_use]
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// Check if the outcome is a success.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.outcome.is_success()
    }

    /// Get the compliance tags.
    #[must_use]
    pub fn compliance_tags(&self) -> &ComplianceTags {
        &self.compliance_tags
    }

    /// Get the metadata.
    #[must_use]
    pub fn metadata(&self) -> &HashMap<String, serde_json::Value> {
        &self.metadata
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::compliance::Soc2Control;

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            "auth.login",
            "User logged in",
            Outcome::Success,
            EventType::LoginSuccess,
        );

        assert_eq!(event.operation(), "auth.login");
        assert_eq!(event.message(), "User logged in");
        assert!(event.is_success());
    }

    #[test]
    fn test_audit_event_with_metadata() {
        let event = AuditEvent::new(
            "data.read",
            "Read user data",
            Outcome::Success,
            EventType::Info,
        )
        .with_metadata("records", 100)
        .with_metadata("table", "users");

        assert_eq!(event.metadata.len(), 2);
        assert_eq!(event.metadata.get("records"), Some(&serde_json::json!(100)));
    }

    #[test]
    fn test_audit_event_with_compliance_tags() {
        let tags = ComplianceTags::new().with_soc2(Soc2Control::CC6_1);

        let event = AuditEvent::new(
            "auth.login",
            "User logged in",
            Outcome::Success,
            EventType::LoginSuccess,
        )
        .with_compliance_tags(tags);

        assert!(event.compliance_tags.soc2.contains(&Soc2Control::CC6_1));
    }

    #[test]
    fn test_audit_event_failure() {
        let event = AuditEvent::new(
            "auth.login",
            "Login failed",
            Outcome::Failure("Invalid credentials".to_string()),
            EventType::LoginFailure,
        );

        assert!(!event.is_success());
        assert_eq!(
            event.outcome().failure_reason(),
            Some("Invalid credentials")
        );
    }
}
