//! Compliance check audit builder.
//!
//! Provides a fluent API for auditing compliance-related events.

use crate::observe::audit::event::AuditEvent;
use crate::observe::audit::types::{ComplianceFramework, ComplianceResult, Outcome};
use crate::observe::compliance::{
    ComplianceTags, GdprBasis, HipaaSafeguard, Iso27001Control, PciDssRequirement, Soc2Control,
};
use crate::observe::types::EventType;

/// Builder for compliance check audit events.
///
/// Use this for compliance control checks, audits, and evidence collection.
///
/// # Example
///
/// ```ignore
/// use octarine::observe::audit::{Audit, ComplianceFramework};
///
/// Audit::compliance(ComplianceFramework::Soc2)
///     .control("CC6.1")
///     .evidence("access_review")
///     .passed()
///     .emit();
/// ```
#[derive(Debug, Clone)]
pub struct ComplianceAuditBuilder {
    framework: ComplianceFramework,
    control: Option<String>,
    evidence_type: Option<String>,
    description: Option<String>,
}

impl ComplianceAuditBuilder {
    /// Create a new compliance audit builder for a specific framework.
    pub fn new(framework: ComplianceFramework) -> Self {
        Self {
            framework,
            control: None,
            evidence_type: None,
            description: None,
        }
    }

    /// Set the specific control being checked.
    ///
    /// Examples: "CC6.1", "164.312(a)(1)", "Art. 32", "Req 8.3"
    #[must_use]
    pub fn control(mut self, control: &str) -> Self {
        self.control = Some(control.to_string());
        self
    }

    /// Set the type of evidence being collected.
    ///
    /// Examples: "access_review", "penetration_test", "audit_log"
    #[must_use]
    pub fn evidence(mut self, evidence_type: &str) -> Self {
        self.evidence_type = Some(evidence_type.to_string());
        self
    }

    /// Set a description of the compliance check.
    #[must_use]
    pub fn description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Build a passed compliance check event.
    #[must_use]
    pub fn passed(self) -> AuditEvent {
        self.build_event(ComplianceResult::Passed, None)
    }

    /// Build a failed compliance check event.
    #[must_use]
    pub fn failed(self, reason: &str) -> AuditEvent {
        self.build_event(ComplianceResult::Failed, Some(reason))
    }

    /// Build a not-applicable compliance check event.
    #[must_use]
    pub fn not_applicable(self, reason: &str) -> AuditEvent {
        self.build_event(ComplianceResult::NotApplicable, Some(reason))
    }

    /// Build a compliance check event that is pending review.
    ///
    /// Use this when the compliance check is still being evaluated.
    #[must_use]
    pub fn in_review(self) -> AuditEvent {
        self.build_pending_event()
    }

    /// Build a compliance check event with indeterminate outcome.
    ///
    /// Use this when the compliance status cannot be determined.
    #[must_use]
    pub fn indeterminate(self, reason: &str) -> AuditEvent {
        self.build_unknown_event(reason)
    }

    fn build_event(self, result: ComplianceResult, reason: Option<&str>) -> AuditEvent {
        let framework_str = framework_str(&self.framework);
        let operation = format!("compliance.{}", framework_str);

        let control_info = self
            .control
            .as_ref()
            .map(|c| format!(" control {}", c))
            .unwrap_or_default();

        let message = match (&result, reason) {
            (ComplianceResult::Passed, _) => {
                format!(
                    "{}{} compliance check passed",
                    framework_str.to_uppercase(),
                    control_info
                )
            }
            (ComplianceResult::Failed, Some(r)) => {
                format!(
                    "{}{} compliance check failed: {}",
                    framework_str.to_uppercase(),
                    control_info,
                    r
                )
            }
            (ComplianceResult::Failed, None) => {
                format!(
                    "{}{} compliance check failed",
                    framework_str.to_uppercase(),
                    control_info
                )
            }
            (ComplianceResult::NotApplicable, Some(r)) => {
                format!(
                    "{}{} compliance check not applicable: {}",
                    framework_str.to_uppercase(),
                    control_info,
                    r
                )
            }
            (ComplianceResult::NotApplicable, None) => {
                format!(
                    "{}{} compliance check not applicable",
                    framework_str.to_uppercase(),
                    control_info
                )
            }
        };

        let outcome = match (&result, reason) {
            (ComplianceResult::Passed, _) => Outcome::Success,
            (ComplianceResult::NotApplicable, _) => Outcome::Success,
            (ComplianceResult::Failed, Some(r)) => Outcome::Failure(r.to_string()),
            (ComplianceResult::Failed, None) => {
                Outcome::Failure("Compliance check failed".to_string())
            }
        };

        let event_type = match &result {
            ComplianceResult::Passed | ComplianceResult::NotApplicable => EventType::Info,
            ComplianceResult::Failed => EventType::Warning,
        };

        let mut event = AuditEvent::new(&operation, message, outcome, event_type)
            .with_metadata("compliance.framework", serde_json::json!(framework_str))
            .with_metadata("compliance.result", serde_json::json!(result_str(&result)));

        if let Some(control) = &self.control {
            event = event.with_metadata("compliance.control", serde_json::json!(control));
        }

        if let Some(evidence) = &self.evidence_type {
            event = event.with_metadata("compliance.evidence_type", serde_json::json!(evidence));
        }

        if let Some(desc) = &self.description {
            event = event.with_metadata("compliance.description", serde_json::json!(desc));
        }

        // Apply compliance tags based on framework
        let tags = self.build_compliance_tags();
        event.with_compliance_tags(tags)
    }

    fn build_pending_event(self) -> AuditEvent {
        let framework_str = framework_str(&self.framework);
        let operation = format!("compliance.{}", framework_str);

        let control_info = self
            .control
            .as_ref()
            .map(|c| format!(" control {}", c))
            .unwrap_or_default();

        let message = format!(
            "{}{} compliance check in review",
            framework_str.to_uppercase(),
            control_info
        );

        let mut event = AuditEvent::new(&operation, message, Outcome::Pending, EventType::Info)
            .with_metadata("compliance.framework", serde_json::json!(framework_str))
            .with_metadata("compliance.result", serde_json::json!("in_review"));

        if let Some(control) = &self.control {
            event = event.with_metadata("compliance.control", serde_json::json!(control));
        }

        if let Some(evidence) = &self.evidence_type {
            event = event.with_metadata("compliance.evidence_type", serde_json::json!(evidence));
        }

        if let Some(desc) = &self.description {
            event = event.with_metadata("compliance.description", serde_json::json!(desc));
        }

        let tags = self.build_compliance_tags();
        event.with_compliance_tags(tags)
    }

    fn build_unknown_event(self, reason: &str) -> AuditEvent {
        let framework_str = framework_str(&self.framework);
        let operation = format!("compliance.{}", framework_str);

        let control_info = self
            .control
            .as_ref()
            .map(|c| format!(" control {}", c))
            .unwrap_or_default();

        let message = format!(
            "{}{} compliance check indeterminate: {}",
            framework_str.to_uppercase(),
            control_info,
            reason
        );

        let mut event = AuditEvent::new(&operation, message, Outcome::Unknown, EventType::Warning)
            .with_metadata("compliance.framework", serde_json::json!(framework_str))
            .with_metadata("compliance.result", serde_json::json!("indeterminate"))
            .with_metadata("compliance.reason", serde_json::json!(reason));

        if let Some(control) = &self.control {
            event = event.with_metadata("compliance.control", serde_json::json!(control));
        }

        if let Some(evidence) = &self.evidence_type {
            event = event.with_metadata("compliance.evidence_type", serde_json::json!(evidence));
        }

        if let Some(desc) = &self.description {
            event = event.with_metadata("compliance.description", serde_json::json!(desc));
        }

        let tags = self.build_compliance_tags();
        event.with_compliance_tags(tags)
    }

    fn build_compliance_tags(&self) -> ComplianceTags {
        let mut tags = ComplianceTags::new().as_evidence();

        // Add framework-specific tags
        match self.framework {
            ComplianceFramework::Soc2 => {
                tags = tags
                    .with_soc2(Soc2Control::CC5_1) // Control monitoring
                    .with_iso27001(Iso27001Control::A8_15);
            }
            ComplianceFramework::Hipaa => {
                tags = tags
                    .with_hipaa(HipaaSafeguard::Administrative)
                    .with_hipaa(HipaaSafeguard::Technical)
                    .with_iso27001(Iso27001Control::A8_15);
            }
            ComplianceFramework::Gdpr => {
                tags = tags
                    .with_gdpr(GdprBasis::LegalObligation)
                    .with_iso27001(Iso27001Control::A8_15);
            }
            ComplianceFramework::PciDss => {
                tags = tags
                    .with_pci_dss(PciDssRequirement::Req12) // Security policies
                    .with_iso27001(Iso27001Control::A8_15);
            }
            ComplianceFramework::Iso27001 => {
                tags = tags
                    .with_iso27001(Iso27001Control::A5_28) // Collection of evidence
                    .with_iso27001(Iso27001Control::A8_15);
            }
        }

        tags
    }
}

fn framework_str(framework: &ComplianceFramework) -> &'static str {
    match framework {
        ComplianceFramework::Soc2 => "soc2",
        ComplianceFramework::Hipaa => "hipaa",
        ComplianceFramework::Gdpr => "gdpr",
        ComplianceFramework::PciDss => "pci_dss",
        ComplianceFramework::Iso27001 => "iso27001",
    }
}

fn result_str(result: &ComplianceResult) -> &'static str {
    match result {
        ComplianceResult::Passed => "passed",
        ComplianceResult::Failed => "failed",
        ComplianceResult::NotApplicable => "not_applicable",
    }
}

impl Default for ComplianceAuditBuilder {
    fn default() -> Self {
        Self::new(ComplianceFramework::Soc2)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_passed() {
        let event = ComplianceAuditBuilder::new(ComplianceFramework::Soc2)
            .control("CC6.1")
            .evidence("access_review")
            .passed();

        assert_eq!(event.operation(), "compliance.soc2");
        assert!(event.is_success());
        assert!(event.message().contains("CC6.1"));
        assert!(event.message().contains("passed"));
    }

    #[test]
    fn test_compliance_failed() {
        let event = ComplianceAuditBuilder::new(ComplianceFramework::Hipaa)
            .control("164.312(a)(1)")
            .evidence("encryption_check")
            .failed("Missing encryption on PHI storage");

        assert!(!event.is_success());
        assert!(event.message().contains("failed"));
        assert!(event.message().contains("Missing encryption"));
    }

    #[test]
    fn test_compliance_not_applicable() {
        let event = ComplianceAuditBuilder::new(ComplianceFramework::PciDss)
            .control("Req 3.4")
            .not_applicable("No cardholder data stored");

        assert!(event.is_success()); // N/A is not a failure
        assert!(event.message().contains("not applicable"));
    }

    #[test]
    fn test_compliance_with_description() {
        let event = ComplianceAuditBuilder::new(ComplianceFramework::Gdpr)
            .control("Art. 32")
            .description("Annual security assessment")
            .passed();

        assert_eq!(
            event.metadata.get("compliance.description"),
            Some(&serde_json::json!("Annual security assessment"))
        );
    }

    #[test]
    fn test_soc2_compliance_tags() {
        let event = ComplianceAuditBuilder::new(ComplianceFramework::Soc2)
            .control("CC6.1")
            .passed();

        assert!(event.compliance_tags.soc2.contains(&Soc2Control::CC5_1));
        assert!(event.compliance_tags.is_evidence);
    }

    #[test]
    fn test_hipaa_compliance_tags() {
        let event = ComplianceAuditBuilder::new(ComplianceFramework::Hipaa)
            .control("164.312")
            .passed();

        assert!(
            event
                .compliance_tags
                .hipaa
                .contains(&HipaaSafeguard::Technical)
        );
        assert!(
            event
                .compliance_tags
                .hipaa
                .contains(&HipaaSafeguard::Administrative)
        );
    }

    #[test]
    fn test_gdpr_compliance_tags() {
        let event = ComplianceAuditBuilder::new(ComplianceFramework::Gdpr)
            .control("Art. 6")
            .passed();

        assert_eq!(
            event.compliance_tags.gdpr_basis,
            Some(GdprBasis::LegalObligation)
        );
    }
}
