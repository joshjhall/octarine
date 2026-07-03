//! Compliance tagging extensions for ObserveBuilder
//!
//! Adds methods to tag events with compliance framework controls.

use super::ObserveBuilder;
use crate::observe::compliance::{
    ComplianceTags, GdprBasis, HipaaSafeguard, Iso27001Control, PciDssRequirement, Soc2Control,
};

/// Compliance tagging methods for ObserveBuilder
impl ObserveBuilder {
    /// Add a SOC2 control tag
    ///
    /// # Example
    /// Pre-existing example - ignored at compile until adapted.
    /// ```ignore
    /// ObserveBuilder::for_operation("user.login")
    ///     .message("User authenticated")
    ///     .soc2_control(Soc2Control::CC6_1)
    ///     .info();
    /// ```
    pub fn soc2_control(mut self, control: Soc2Control) -> Self {
        self.compliance_tags = self.compliance_tags.with_soc2(control);
        self
    }

    /// Add multiple SOC2 control tags
    pub fn soc2_controls(mut self, controls: impl IntoIterator<Item = Soc2Control>) -> Self {
        for control in controls {
            self.compliance_tags = self.compliance_tags.with_soc2(control);
        }
        self
    }

    /// Add a HIPAA safeguard tag
    ///
    /// # Example
    /// Pre-existing example - ignored at compile until adapted.
    /// ```ignore
    /// ObserveBuilder::for_operation("phi.access")
    ///     .message("Accessed patient record")
    ///     .hipaa_safeguard(HipaaSafeguard::Technical)
    ///     .info();
    /// ```
    pub fn hipaa_safeguard(mut self, safeguard: HipaaSafeguard) -> Self {
        self.compliance_tags = self.compliance_tags.with_hipaa(safeguard);
        self
    }

    /// Add multiple HIPAA safeguard tags
    pub fn hipaa_safeguards(
        mut self,
        safeguards: impl IntoIterator<Item = HipaaSafeguard>,
    ) -> Self {
        for safeguard in safeguards {
            self.compliance_tags = self.compliance_tags.with_hipaa(safeguard);
        }
        self
    }

    /// Set the GDPR lawful basis for data processing
    ///
    /// # Example
    /// Pre-existing example - ignored at compile until adapted.
    /// ```ignore
    /// ObserveBuilder::for_operation("user.data.export")
    ///     .message("Exported user data")
    ///     .gdpr_basis(GdprBasis::Consent)
    ///     .info();
    /// ```
    pub fn gdpr_basis(mut self, basis: GdprBasis) -> Self {
        self.compliance_tags = self.compliance_tags.with_gdpr(basis);
        self
    }

    /// Add a PCI-DSS requirement tag
    ///
    /// # Example
    /// Pre-existing example - ignored at compile until adapted.
    /// ```ignore
    /// ObserveBuilder::for_operation("card.access")
    ///     .message("Accessed cardholder data")
    ///     .pci_dss_requirement(PciDssRequirement::Req3)
    ///     .info();
    /// ```
    pub fn pci_dss_requirement(mut self, requirement: PciDssRequirement) -> Self {
        self.compliance_tags = self.compliance_tags.with_pci_dss(requirement);
        self
    }

    /// Add multiple PCI-DSS requirement tags
    pub fn pci_dss_requirements(
        mut self,
        requirements: impl IntoIterator<Item = PciDssRequirement>,
    ) -> Self {
        for requirement in requirements {
            self.compliance_tags = self.compliance_tags.with_pci_dss(requirement);
        }
        self
    }

    /// Add an ISO 27001 control tag
    ///
    /// # Example
    /// Pre-existing example - ignored at compile until adapted.
    /// ```ignore
    /// ObserveBuilder::for_operation("user.login")
    ///     .message("User authenticated")
    ///     .iso27001_control(Iso27001Control::A8_5)
    ///     .info();
    /// ```
    pub fn iso27001_control(mut self, control: Iso27001Control) -> Self {
        self.compliance_tags = self.compliance_tags.with_iso27001(control);
        self
    }

    /// Add multiple ISO 27001 control tags
    pub fn iso27001_controls(
        mut self,
        controls: impl IntoIterator<Item = Iso27001Control>,
    ) -> Self {
        for control in controls {
            self.compliance_tags = self.compliance_tags.with_iso27001(control);
        }
        self
    }

    /// Mark this event as compliance evidence
    ///
    /// Evidence events should be retained for audit purposes.
    pub fn compliance_evidence(mut self) -> Self {
        self.compliance_tags = self.compliance_tags.as_evidence();
        self
    }

    /// Set all compliance tags at once
    ///
    /// This replaces any existing compliance tags.
    pub fn compliance(mut self, tags: ComplianceTags) -> Self {
        self.compliance_tags = tags;
        self
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::observe::compliance::{
        GdprBasis, HipaaSafeguard, Iso27001Control, PciDssRequirement, Soc2Control,
    };

    fn base() -> ObserveBuilder {
        ObserveBuilder::for_operation("test.op")
    }

    #[test]
    fn test_soc2_single_and_multiple() {
        // Single control is recorded.
        let b = base().soc2_control(Soc2Control::CC6_1);
        assert!(b.compliance_tags.soc2.contains(&Soc2Control::CC6_1));

        // Multiple controls accumulate; duplicates are deduplicated by
        // ComplianceTags::with_soc2.
        let b = base().soc2_controls([Soc2Control::CC6_1, Soc2Control::CC8_1, Soc2Control::CC6_1]);
        assert_eq!(b.compliance_tags.soc2.len(), 2);
        assert!(b.compliance_tags.soc2.contains(&Soc2Control::CC8_1));
    }

    #[test]
    fn test_hipaa_single_and_multiple() {
        let b = base().hipaa_safeguard(HipaaSafeguard::Technical);
        assert!(b.compliance_tags.hipaa.contains(&HipaaSafeguard::Technical));

        let b = base().hipaa_safeguards([
            HipaaSafeguard::Technical,
            HipaaSafeguard::Administrative,
            HipaaSafeguard::Technical,
        ]);
        assert_eq!(b.compliance_tags.hipaa.len(), 2);
    }

    #[test]
    fn test_gdpr_basis_sets_option() {
        let b = base().gdpr_basis(GdprBasis::Consent);
        assert_eq!(b.compliance_tags.gdpr_basis, Some(GdprBasis::Consent));
        // Setting again replaces the basis.
        let b = b.gdpr_basis(GdprBasis::LegalObligation);
        assert_eq!(
            b.compliance_tags.gdpr_basis,
            Some(GdprBasis::LegalObligation)
        );
    }

    #[test]
    fn test_pci_dss_single_and_multiple() {
        let b = base().pci_dss_requirement(PciDssRequirement::Req3);
        assert!(b.compliance_tags.pci_dss.contains(&PciDssRequirement::Req3));

        let b = base().pci_dss_requirements([
            PciDssRequirement::Req3,
            PciDssRequirement::Req8,
            PciDssRequirement::Req3,
        ]);
        assert_eq!(b.compliance_tags.pci_dss.len(), 2);
    }

    #[test]
    fn test_iso27001_single_and_multiple() {
        let b = base().iso27001_control(Iso27001Control::A8_5);
        assert!(b.compliance_tags.iso27001.contains(&Iso27001Control::A8_5));

        let b = base().iso27001_controls([
            Iso27001Control::A8_5,
            Iso27001Control::A8_15,
            Iso27001Control::A8_5,
        ]);
        assert_eq!(b.compliance_tags.iso27001.len(), 2);
    }

    #[test]
    fn test_compliance_evidence_flag() {
        let b = base();
        assert!(!b.compliance_tags.is_evidence);
        let b = b.compliance_evidence();
        assert!(b.compliance_tags.is_evidence);
    }

    #[test]
    fn test_compliance_replaces_all_tags() {
        // Start with some tags, then replace wholesale.
        let b = base()
            .soc2_control(Soc2Control::CC6_1)
            .iso27001_control(Iso27001Control::A8_5);
        assert!(!b.compliance_tags.is_empty());

        let replacement = ComplianceTags::new().with_gdpr(GdprBasis::Consent);
        let b = b.compliance(replacement);
        // Prior SOC2/ISO tags are gone; only the GDPR basis remains.
        assert!(b.compliance_tags.soc2.is_empty());
        assert!(b.compliance_tags.iso27001.is_empty());
        assert_eq!(b.compliance_tags.gdpr_basis, Some(GdprBasis::Consent));
    }

    #[test]
    fn test_chained_builders_compose() {
        // The fluent chain merges tags from every framework into one set.
        let b = base()
            .soc2_control(Soc2Control::CC6_1)
            .hipaa_safeguard(HipaaSafeguard::Technical)
            .gdpr_basis(GdprBasis::Consent)
            .pci_dss_requirement(PciDssRequirement::Req8)
            .iso27001_control(Iso27001Control::A8_15)
            .compliance_evidence();
        let tags = &b.compliance_tags;
        assert_eq!(tags.soc2.len(), 1);
        assert_eq!(tags.hipaa.len(), 1);
        assert!(tags.gdpr_basis.is_some());
        assert_eq!(tags.pci_dss.len(), 1);
        assert_eq!(tags.iso27001.len(), 1);
        assert!(tags.is_evidence);
        assert!(!tags.is_empty());
    }
}
