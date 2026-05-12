//! Driver's License methods.

use super::*;

impl GovernmentBuilder {
    /// Check if value is a driver's license
    #[must_use]
    pub fn is_driver_license(&self, value: &str) -> bool {
        self.inner.is_driver_license(value)
    }

    /// Find all driver's licenses in text
    #[must_use]
    pub fn find_driver_licenses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_driver_licenses_in_text(text)
    }

    /// Validate driver's license format for a specific state
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the license format is invalid for the specified state
    pub fn validate_driver_license(&self, license: &str, state: &str) -> Result<(), Problem> {
        self.inner.validate_driver_license(license, state)
    }

    /// Redact a driver's license with explicit strategy
    #[must_use]
    pub fn redact_driver_license_with_strategy(
        &self,
        license: &str,
        strategy: DriverLicenseRedactionStrategy,
    ) -> String {
        self.inner
            .redact_driver_license_with_strategy(license, strategy)
    }

    /// Redact all driver's licenses in text with explicit strategy
    #[must_use]
    pub fn redact_driver_licenses_in_text_with_strategy(
        &self,
        text: &str,
        strategy: DriverLicenseRedactionStrategy,
    ) -> String {
        self.inner
            .redact_driver_licenses_in_text_with_strategy(text, strategy)
    }

    /// Normalize a driver's license (uppercase, remove formatting)
    #[must_use]
    pub fn normalize_driver_license(&self, license: &str) -> String {
        self.inner.normalize_driver_license(license)
    }

    /// Sanitize a driver's license (normalize + validate)
    pub fn sanitize_driver_license(&self, license: &str, state: &str) -> Result<String, Problem> {
        self.inner.sanitize_driver_license(license, state)
    }
}
