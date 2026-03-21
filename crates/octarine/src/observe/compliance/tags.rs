//! Compliance tags collection and auto-tagging rules
//!
//! Provides the ComplianceTags type and automatic tagging based on event types.

use super::{GdprBasis, HipaaSafeguard, Iso27001Control, PciDssRequirement, Soc2Control};
use crate::observe::EventType;
use serde::{Deserialize, Serialize};

/// Collection of compliance tags for an event
///
/// Events can have multiple tags from different compliance frameworks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceTags {
    /// SOC2 controls this event provides evidence for
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub soc2: Vec<Soc2Control>,

    /// HIPAA safeguards this event relates to
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hipaa: Vec<HipaaSafeguard>,

    /// GDPR lawful basis for data processing in this event
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gdpr_basis: Option<GdprBasis>,

    /// PCI-DSS requirements this event provides evidence for
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pci_dss: Vec<PciDssRequirement>,

    /// ISO 27001:2022 Annex A controls this event provides evidence for
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub iso27001: Vec<Iso27001Control>,

    /// Whether this event is compliance evidence (should be retained)
    #[serde(default)]
    pub is_evidence: bool,
}

impl ComplianceTags {
    /// Create empty compliance tags
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any compliance tags are set
    pub fn is_empty(&self) -> bool {
        self.soc2.is_empty()
            && self.hipaa.is_empty()
            && self.gdpr_basis.is_none()
            && self.pci_dss.is_empty()
            && self.iso27001.is_empty()
    }

    /// Add a SOC2 control
    pub fn with_soc2(mut self, control: Soc2Control) -> Self {
        if !self.soc2.contains(&control) {
            self.soc2.push(control);
        }
        self
    }

    /// Add a HIPAA safeguard
    pub fn with_hipaa(mut self, safeguard: HipaaSafeguard) -> Self {
        if !self.hipaa.contains(&safeguard) {
            self.hipaa.push(safeguard);
        }
        self
    }

    /// Set the GDPR lawful basis
    pub fn with_gdpr(mut self, basis: GdprBasis) -> Self {
        self.gdpr_basis = Some(basis);
        self
    }

    /// Add a PCI-DSS requirement
    pub fn with_pci_dss(mut self, requirement: PciDssRequirement) -> Self {
        if !self.pci_dss.contains(&requirement) {
            self.pci_dss.push(requirement);
        }
        self
    }

    /// Add an ISO 27001 control
    pub fn with_iso27001(mut self, control: Iso27001Control) -> Self {
        if !self.iso27001.contains(&control) {
            self.iso27001.push(control);
        }
        self
    }

    /// Mark as compliance evidence
    pub fn as_evidence(mut self) -> Self {
        self.is_evidence = true;
        self
    }
}

/// Get default compliance tags for an event type
///
/// Provides automatic tagging based on event type semantics.
/// These are sensible defaults that can be overridden by explicit tags.
pub fn default_tags_for_event_type(event_type: EventType) -> ComplianceTags {
    let mut tags = ComplianceTags::new();

    match event_type {
        // Authentication events
        EventType::LoginSuccess | EventType::LoginFailure => {
            tags.soc2.push(Soc2Control::CC6_1);
            tags.hipaa.push(HipaaSafeguard::Technical);
            tags.pci_dss.push(PciDssRequirement::Req8);
            tags.iso27001.push(Iso27001Control::A8_5); // Secure authentication
            tags.iso27001.push(Iso27001Control::A8_15); // Logging
            tags.is_evidence = true;
        }

        // Authentication/authorization errors
        EventType::AuthenticationError | EventType::AuthorizationError => {
            tags.soc2.push(Soc2Control::CC6_1);
            tags.soc2.push(Soc2Control::CC6_6);
            tags.hipaa.push(HipaaSafeguard::Technical);
            tags.pci_dss.push(PciDssRequirement::Req10);
            tags.iso27001.push(Iso27001Control::A5_25); // Assessment of security events
            tags.iso27001.push(Iso27001Control::A8_15); // Logging
            tags.is_evidence = true;
        }

        // Authentication success
        EventType::AuthenticationSuccess => {
            tags.soc2.push(Soc2Control::CC6_1);
            tags.hipaa.push(HipaaSafeguard::Technical);
            tags.pci_dss.push(PciDssRequirement::Req8);
            tags.iso27001.push(Iso27001Control::A8_5); // Secure authentication
            tags.iso27001.push(Iso27001Control::A8_15); // Logging
            tags.is_evidence = true;
        }

        // Resource operations (data access events)
        EventType::ResourceCreated | EventType::ResourceUpdated | EventType::ResourceDeleted => {
            tags.soc2.push(Soc2Control::CC8_1);
            tags.hipaa.push(HipaaSafeguard::Technical);
            tags.pci_dss.push(PciDssRequirement::Req10);
            tags.iso27001.push(Iso27001Control::A8_3); // Information access restriction
            tags.iso27001.push(Iso27001Control::A8_15); // Logging
            tags.is_evidence = true;
        }

        // System events
        EventType::SystemStartup | EventType::SystemShutdown => {
            tags.soc2.push(Soc2Control::CC7_1);
            tags.soc2.push(Soc2Control::CC3_1);
            tags.iso27001.push(Iso27001Control::A8_9); // Configuration management
            tags.iso27001.push(Iso27001Control::A8_15); // Logging
            tags.is_evidence = true;
        }

        // Health check
        EventType::HealthCheck => {
            tags.soc2.push(Soc2Control::CC7_1);
            tags.iso27001.push(Iso27001Control::A8_16); // Monitoring activities
        }

        // Validation events (processing integrity)
        EventType::ValidationError => {
            tags.soc2.push(Soc2Control::CC9_1);
            tags.soc2.push(Soc2Control::CC9_2);
            tags.iso27001.push(Iso27001Control::A8_26); // Application security requirements
        }

        EventType::ValidationSuccess => {
            tags.soc2.push(Soc2Control::CC9_1);
        }

        // Conversion/sanitization errors
        EventType::ConversionError | EventType::SanitizationError => {
            tags.soc2.push(Soc2Control::CC9_2);
            tags.iso27001.push(Iso27001Control::A8_26); // Application security requirements
        }

        // System errors
        EventType::SystemError => {
            tags.soc2.push(Soc2Control::CC7_2);
            tags.iso27001.push(Iso27001Control::A5_25); // Assessment of security events
            tags.iso27001.push(Iso27001Control::A8_15); // Logging
            tags.is_evidence = true;
        }

        // Threshold events (monitoring)
        EventType::ThresholdWarning | EventType::ThresholdCritical => {
            tags.soc2.push(Soc2Control::CC7_2); // System monitoring
            tags.iso27001.push(Iso27001Control::A8_16); // Monitoring activities
            tags.is_evidence = true;
        }

        EventType::ThresholdRecovered => {
            tags.soc2.push(Soc2Control::CC7_2);
            tags.iso27001.push(Iso27001Control::A8_16); // Monitoring activities
        }

        // General events - no automatic tagging
        EventType::Info | EventType::Warning | EventType::Debug => {}
    }

    tags
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_tags_builder() {
        let tags = ComplianceTags::new()
            .with_soc2(Soc2Control::CC6_1)
            .with_soc2(Soc2Control::CC8_1)
            .with_hipaa(HipaaSafeguard::Technical)
            .with_gdpr(GdprBasis::Consent)
            .with_pci_dss(PciDssRequirement::Req8)
            .with_iso27001(Iso27001Control::A8_5)
            .with_iso27001(Iso27001Control::A8_15)
            .as_evidence();

        assert_eq!(tags.soc2.len(), 2);
        assert_eq!(tags.hipaa.len(), 1);
        assert_eq!(tags.gdpr_basis, Some(GdprBasis::Consent));
        assert_eq!(tags.pci_dss.len(), 1);
        assert_eq!(tags.iso27001.len(), 2);
        assert!(tags.is_evidence);
    }

    #[test]
    fn test_compliance_tags_no_duplicates() {
        let tags = ComplianceTags::new()
            .with_soc2(Soc2Control::CC6_1)
            .with_soc2(Soc2Control::CC6_1)
            .with_soc2(Soc2Control::CC6_1);

        assert_eq!(tags.soc2.len(), 1);
    }

    #[test]
    fn test_iso27001_no_duplicates() {
        let tags = ComplianceTags::new()
            .with_iso27001(Iso27001Control::A8_5)
            .with_iso27001(Iso27001Control::A8_5)
            .with_iso27001(Iso27001Control::A8_5);

        assert_eq!(tags.iso27001.len(), 1);
    }

    #[test]
    fn test_default_tags_for_login() {
        let tags = default_tags_for_event_type(EventType::LoginSuccess);

        assert!(tags.soc2.contains(&Soc2Control::CC6_1));
        assert!(tags.hipaa.contains(&HipaaSafeguard::Technical));
        assert!(tags.pci_dss.contains(&PciDssRequirement::Req8));
        assert!(tags.iso27001.contains(&Iso27001Control::A8_5)); // Secure authentication
        assert!(tags.iso27001.contains(&Iso27001Control::A8_15)); // Logging
        assert!(tags.is_evidence);
    }

    #[test]
    fn test_compliance_tags_serialization() {
        let tags = ComplianceTags::new()
            .with_soc2(Soc2Control::CC6_1)
            .with_hipaa(HipaaSafeguard::Technical)
            .with_gdpr(GdprBasis::Contract);

        let json = serde_json::to_string(&tags).expect("serialize");
        assert!(json.contains("CC6_1"));
        assert!(json.contains("technical"));
        assert!(json.contains("contract"));
    }
}
