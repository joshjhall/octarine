//! Driver's license operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches driver's license format
    #[must_use]
    pub fn is_driver_license(&self, value: &str) -> bool {
        detection::is_driver_license(value)
    }

    /// Find all driver's licenses in text
    #[must_use]
    pub fn find_driver_licenses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_driver_licenses_in_text(text)
    }

    /// Validate driver's license format for a specific state
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the license format is invalid for the specified state
    pub fn validate_driver_license(&self, license: &str, state: &str) -> Result<(), Problem> {
        validation::validate_driver_license(license, state)
    }

    /// Redact driver's license with explicit strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, DriverLicenseRedactionStrategy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    /// let result = builder.redact_driver_license_with_strategy(
    ///     "D1234567",
    ///     DriverLicenseRedactionStrategy::Token,
    /// );
    /// assert_eq!(result, "[DRIVER_LICENSE]");
    /// ```
    #[must_use]
    pub fn redact_driver_license_with_strategy(
        &self,
        license: &str,
        strategy: DriverLicenseRedactionStrategy,
    ) -> String {
        sanitization::redact_driver_license_with_strategy(license, strategy)
    }

    /// Redact all driver's licenses in text with explicit strategy
    #[must_use]
    pub fn redact_driver_licenses_in_text_with_strategy(
        &self,
        text: &str,
        strategy: DriverLicenseRedactionStrategy,
    ) -> String {
        sanitization::redact_driver_licenses_in_text_with_strategy(text, strategy).into_owned()
    }

    /// Normalize driver's license to alphanumeric only
    #[must_use]
    pub fn normalize_driver_license(&self, license: &str) -> String {
        conversion::normalize_driver_license(license)
    }

    /// Sanitize driver's license strict (normalize + validate)
    ///
    /// Combines normalization and validation in one step.
    /// Returns normalized license if valid, error otherwise.
    pub fn sanitize_driver_license(&self, license: &str, state: &str) -> Result<String, Problem> {
        sanitization::sanitize_driver_license_strict(license, state)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    fn builder() -> GovernmentIdentifierBuilder {
        GovernmentIdentifierBuilder::new()
    }

    #[test]
    fn test_driver_license_operations() {
        let gov = builder();
        assert!(gov.is_driver_license("A1234567"));
        assert!(gov.validate_driver_license("A1234567", "CA").is_ok());
        assert_eq!(
            gov.redact_driver_license_with_strategy(
                "A1234567",
                DriverLicenseRedactionStrategy::Token
            ),
            "[DRIVER_LICENSE]"
        );
    }
}
