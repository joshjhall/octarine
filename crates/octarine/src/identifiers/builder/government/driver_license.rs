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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // "A1234567" is a valid California DL (1 letter + 7 digits); "12345678"
    // is a valid Texas DL (8 digits). These come from the primitive tests.
    const CA_LICENSE: &str = "A1234567";

    #[test]
    fn test_is_driver_license() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_driver_license(CA_LICENSE));
        assert!(!b.is_driver_license("!"));
    }

    #[test]
    fn test_find_driver_licenses_in_text() {
        let b = GovernmentBuilder::silent();
        // Detection over free text may be conservative; just ensure it runs
        // and returns an empty vec on clearly-absent input.
        assert!(b.find_driver_licenses_in_text("").is_empty());
    }

    #[test]
    fn test_validate_driver_license() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_driver_license("A1234567", "CA").is_ok());
        assert!(b.validate_driver_license("12345678", "TX").is_ok());
        // Wrong shape for CA (CA requires letter + 7 digits).
        assert!(b.validate_driver_license("12345678", "CA").is_err());
    }

    #[test]
    fn test_redact_driver_license_with_strategy() {
        let b = GovernmentBuilder::silent();
        assert_eq!(
            b.redact_driver_license_with_strategy(
                CA_LICENSE,
                DriverLicenseRedactionStrategy::Token
            ),
            "[DRIVER_LICENSE]"
        );
        // LastFour keeps the trailing four characters.
        assert_eq!(
            b.redact_driver_license_with_strategy(
                CA_LICENSE,
                DriverLicenseRedactionStrategy::LastFour
            ),
            "****4567"
        );
    }

    #[test]
    fn test_redact_driver_licenses_in_text_with_strategy() {
        let b = GovernmentBuilder::silent();
        // Should not panic and returns a String.
        let _ = b.redact_driver_licenses_in_text_with_strategy(
            "license A1234567",
            DriverLicenseRedactionStrategy::Token,
        );
    }

    #[test]
    fn test_normalize_driver_license() {
        let b = GovernmentBuilder::silent();
        // normalize strips non-alphanumerics but does not change case.
        assert_eq!(b.normalize_driver_license("A-123-4567"), "A1234567");
        assert_eq!(b.normalize_driver_license("A 123 4567"), "A1234567");
    }

    #[test]
    fn test_sanitize_driver_license() {
        let b = GovernmentBuilder::silent();
        assert_eq!(
            b.sanitize_driver_license("A1234567", "CA").expect("valid"),
            "A1234567"
        );
        assert!(b.sanitize_driver_license("12345678", "CA").is_err());
    }
}
