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
