//! Compliance extensions for ContextBuilder
//!
//! Extends ContextBuilder with compliance-specific methods.
//! NO business logic here - only delegation to implementation.

use super::ContextBuilder;

// Import ONLY the compliance functions we're delegating to
use super::super::compliance::{is_phi_present, is_pii_present};

/// Extensions for ContextBuilder related to compliance
impl ContextBuilder {
    /// Check text for PII/PHI and set flags accordingly
    pub fn with_compliance_check(mut self, text: &str) -> Self {
        if is_pii_present(text) {
            self.contains_pii = true;
        }
        if is_phi_present(text) {
            self.contains_phi = true;
        }
        self
    }

    // Mark context as containing PII (already implemented in mod.rs)
    // pub fn with_pii_detected(mut self) -> Self - already exists

    // Mark context as containing PHI (already implemented in mod.rs)
    // pub fn with_phi_detected(mut self) -> Self - already exists

    /// Scan text for PII and set flag if found
    pub fn scan_for_pii(mut self, text: &str) -> Self {
        if is_pii_present(text) {
            self.contains_pii = true;
        }
        self
    }

    /// Scan text for PHI and set flag if found
    pub fn scan_for_phi(mut self, text: &str) -> Self {
        if is_phi_present(text) {
            self.contains_phi = true;
        }
        self
    }
}
