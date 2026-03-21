//! Security event audit builder.
//!
//! Provides a fluent API for auditing security-related events.

use crate::observe::audit::event::AuditEvent;
use crate::observe::audit::types::{Outcome, SecurityAction, ThreatLevel};
use crate::observe::compliance::{
    ComplianceTags, HipaaSafeguard, Iso27001Control, PciDssRequirement, Soc2Control,
};
use crate::observe::types::EventType;

/// Builder for security event audit events.
///
/// Use this for security incidents, threat detection, and anomaly events.
///
/// # Example
///
/// ```ignore
/// use octarine::observe::audit::{Audit, SecurityAction, ThreatLevel};
///
/// Audit::security("anomaly_detected")
///     .threat_level(ThreatLevel::High)
///     .source_ip("203.0.113.50")
///     .action(SecurityAction::Blocked)
///     .failure("Blocked suspicious request")
///     .emit();
/// ```
#[derive(Debug, Clone)]
pub struct SecurityAuditBuilder {
    operation: String,
    threat_level: Option<ThreatLevel>,
    source_ip: Option<String>,
    action: SecurityAction,
    attack_type: Option<String>,
    affected_resource: Option<String>,
}

impl SecurityAuditBuilder {
    /// Create a new security event audit builder.
    pub fn new(operation: &str) -> Self {
        Self {
            operation: operation.to_string(),
            threat_level: None,
            source_ip: None,
            action: SecurityAction::Logged,
            attack_type: None,
            affected_resource: None,
        }
    }

    /// Set the threat level of the security event.
    #[must_use]
    pub fn threat_level(mut self, level: ThreatLevel) -> Self {
        self.threat_level = Some(level);
        self
    }

    /// Set the source IP address of the event.
    #[must_use]
    pub fn source_ip(mut self, ip: &str) -> Self {
        self.source_ip = Some(ip.to_string());
        self
    }

    /// Set the action taken in response to this security event.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::observe::audit::{Audit, SecurityAction};
    ///
    /// Audit::security("intrusion_attempt")
    ///     .action(SecurityAction::Escalated)
    ///     .failure("Escalated to security team")
    ///     .emit();
    /// ```
    #[must_use]
    pub fn action(mut self, action: SecurityAction) -> Self {
        self.action = action;
        self
    }

    /// Mark this event as blocked (convenience for `.action(SecurityAction::Blocked)`).
    #[must_use]
    pub fn blocked(mut self) -> Self {
        self.action = SecurityAction::Blocked;
        self
    }

    /// Mark this event as alerted (convenience for `.action(SecurityAction::Alerted)`).
    #[must_use]
    pub fn alerted(mut self) -> Self {
        self.action = SecurityAction::Alerted;
        self
    }

    /// Mark this event as escalated (convenience for `.action(SecurityAction::Escalated)`).
    #[must_use]
    pub fn escalated(mut self) -> Self {
        self.action = SecurityAction::Escalated;
        self
    }

    /// Set the type of attack (e.g., "sql_injection", "xss", "brute_force").
    #[must_use]
    pub fn attack_type(mut self, attack: &str) -> Self {
        self.attack_type = Some(attack.to_string());
        self
    }

    /// Set the affected resource.
    #[must_use]
    pub fn affected_resource(mut self, resource: &str) -> Self {
        self.affected_resource = Some(resource.to_string());
        self
    }

    /// Build a successful security event (threat handled/mitigated).
    #[must_use]
    pub fn success(self) -> AuditEvent {
        self.build_event(Outcome::Success)
    }

    /// Build a security event indicating a threat/incident.
    #[must_use]
    pub fn failure(self, reason: &str) -> AuditEvent {
        self.build_event(Outcome::Failure(reason.to_string()))
    }

    /// Build a pending security event.
    ///
    /// Use this for security events under investigation.
    #[must_use]
    pub fn pending(self) -> AuditEvent {
        self.build_event(Outcome::Pending)
    }

    /// Build a security event with unknown outcome.
    ///
    /// Use this when the security impact cannot be determined.
    #[must_use]
    pub fn unknown(self) -> AuditEvent {
        self.build_event(Outcome::Unknown)
    }

    fn build_event(self, outcome: Outcome) -> AuditEvent {
        let operation = format!("security.{}", self.operation);

        let threat_info = self
            .threat_level
            .as_ref()
            .map(|l| format!(" [{}]", threat_level_str(l)))
            .unwrap_or_default();

        let action_info = match self.action {
            SecurityAction::Logged => "",
            SecurityAction::Blocked => " (blocked)",
            SecurityAction::Alerted => " (alerted)",
            SecurityAction::Escalated => " (escalated)",
            SecurityAction::Allowed => " (allowed)",
        };

        let message = match &outcome {
            Outcome::Success => {
                format!(
                    "Security event '{}'{}{} - handled successfully",
                    self.operation, threat_info, action_info
                )
            }
            Outcome::Failure(reason) => {
                format!(
                    "Security event '{}'{}{}: {}",
                    self.operation, threat_info, action_info, reason
                )
            }
            Outcome::Pending => {
                format!(
                    "Security event '{}'{}{} - under investigation",
                    self.operation, threat_info, action_info
                )
            }
            Outcome::Unknown => {
                format!(
                    "Security event '{}'{}{} - impact unknown",
                    self.operation, threat_info, action_info
                )
            }
        };

        let event_type = match &outcome {
            Outcome::Success => EventType::Info,
            Outcome::Failure(_) => EventType::AuthorizationError,
            Outcome::Pending => EventType::Warning,
            Outcome::Unknown => EventType::Warning,
        };

        let mut event = AuditEvent::new(&operation, message, outcome, event_type)
            .with_metadata("security.operation", serde_json::json!(&self.operation))
            .with_metadata(
                "security.action",
                serde_json::json!(action_str(&self.action)),
            );

        if let Some(level) = &self.threat_level {
            event = event.with_metadata(
                "security.threat_level",
                serde_json::json!(threat_level_str(level)),
            );
        }

        if let Some(ip) = &self.source_ip {
            event = event.with_metadata("security.source_ip", serde_json::json!(ip));
        }

        if let Some(attack) = &self.attack_type {
            event = event.with_metadata("security.attack_type", serde_json::json!(attack));
        }

        if let Some(resource) = &self.affected_resource {
            event = event.with_metadata("security.affected_resource", serde_json::json!(resource));
        }

        // Apply compliance tags for security events
        let mut tags = ComplianceTags::new()
            .with_soc2(Soc2Control::CC6_6) // Security threat protection
            .with_soc2(Soc2Control::CC7_2) // Incident response
            .with_hipaa(HipaaSafeguard::Technical)
            .with_pci_dss(PciDssRequirement::Req10) // Logging
            .with_iso27001(Iso27001Control::A5_24) // Security incident planning
            .with_iso27001(Iso27001Control::A5_25) // Security event assessment
            .with_iso27001(Iso27001Control::A8_15) // Logging
            .as_evidence();

        // Add additional tags for high/critical threats
        if matches!(
            self.threat_level,
            Some(ThreatLevel::High) | Some(ThreatLevel::Critical)
        ) {
            tags = tags.with_soc2(Soc2Control::CC7_1); // System monitoring
        }

        event.with_compliance_tags(tags)
    }
}

fn threat_level_str(level: &ThreatLevel) -> &'static str {
    match level {
        ThreatLevel::Low => "low",
        ThreatLevel::Medium => "medium",
        ThreatLevel::High => "high",
        ThreatLevel::Critical => "critical",
    }
}

fn action_str(action: &SecurityAction) -> &'static str {
    match action {
        SecurityAction::Logged => "logged",
        SecurityAction::Blocked => "blocked",
        SecurityAction::Alerted => "alerted",
        SecurityAction::Escalated => "escalated",
        SecurityAction::Allowed => "allowed",
    }
}

impl Default for SecurityAuditBuilder {
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
    fn test_security_success() {
        let event = SecurityAuditBuilder::new("rate_limit_applied")
            .source_ip("192.0.2.1")
            .blocked()
            .success();

        assert_eq!(event.operation(), "security.rate_limit_applied");
        assert!(event.is_success());
        assert!(event.message().contains("blocked"));
    }

    #[test]
    fn test_security_failure() {
        let event = SecurityAuditBuilder::new("intrusion_attempt")
            .threat_level(ThreatLevel::Critical)
            .source_ip("203.0.113.50")
            .attack_type("sql_injection")
            .failure("SQL injection detected in login form");

        assert!(!event.is_success());
        assert!(event.message().contains("[critical]"));
        assert!(event.message().contains("SQL injection"));
    }

    #[test]
    fn test_security_with_resource() {
        let event = SecurityAuditBuilder::new("unauthorized_access")
            .threat_level(ThreatLevel::High)
            .affected_resource("/api/admin/users")
            .failure("Unauthorized API access attempt");

        assert_eq!(
            event.metadata.get("security.affected_resource"),
            Some(&serde_json::json!("/api/admin/users"))
        );
    }

    #[test]
    fn test_threat_levels() {
        let low = SecurityAuditBuilder::new("test")
            .threat_level(ThreatLevel::Low)
            .success();
        assert_eq!(
            low.metadata.get("security.threat_level"),
            Some(&serde_json::json!("low"))
        );

        let critical = SecurityAuditBuilder::new("test")
            .threat_level(ThreatLevel::Critical)
            .success();
        assert_eq!(
            critical.metadata.get("security.threat_level"),
            Some(&serde_json::json!("critical"))
        );
    }

    #[test]
    fn test_compliance_tags() {
        let event = SecurityAuditBuilder::new("test").success();

        assert!(event.compliance_tags.soc2.contains(&Soc2Control::CC6_6));
        assert!(event.compliance_tags.soc2.contains(&Soc2Control::CC7_2));
        assert!(event.compliance_tags.is_evidence);
    }

    #[test]
    fn test_high_threat_compliance() {
        let event = SecurityAuditBuilder::new("test")
            .threat_level(ThreatLevel::High)
            .success();

        // High threats should also have CC7.1 (System monitoring)
        assert!(event.compliance_tags.soc2.contains(&Soc2Control::CC7_1));
    }
}
