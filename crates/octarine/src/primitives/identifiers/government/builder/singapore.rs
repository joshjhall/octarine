//! Singapore NRIC/FIN and UEN operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches Singapore NRIC/FIN format
    #[must_use]
    pub fn is_singapore_nric(&self, value: &str) -> bool {
        detection::is_singapore_nric(value)
    }

    /// Find all Singapore NRIC/FIN numbers in text
    #[must_use]
    pub fn find_singapore_nrics_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_singapore_nrics_in_text(text)
    }

    /// Validate Singapore NRIC/FIN format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NRIC/FIN format is invalid
    pub fn validate_singapore_nric(&self, nric: &str) -> Result<(), Problem> {
        validation::validate_singapore_nric(nric)
    }

    /// Validate Singapore NRIC/FIN with weighted checksum and check letter
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NRIC/FIN format is invalid or checksum fails
    pub fn validate_singapore_nric_with_checksum(&self, nric: &str) -> Result<(), Problem> {
        validation::validate_singapore_nric_with_checksum(nric)
    }

    /// Check if a Singapore NRIC/FIN is a test/dummy pattern
    #[must_use]
    pub fn is_test_singapore_nric(&self, nric: &str) -> bool {
        validation::is_test_singapore_nric(nric)
    }

    /// Check if value matches a Singapore UEN layout
    #[must_use]
    pub fn is_singapore_uen(&self, value: &str) -> bool {
        detection::is_singapore_uen(value)
    }

    /// Find all Singapore UEN values in text
    #[must_use]
    pub fn find_singapore_uens_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_singapore_uens_in_text(text)
    }

    /// Validate Singapore UEN layout
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the UEN does not match any published layout.
    pub fn validate_singapore_uen(&self, uen: &str) -> Result<(), Problem> {
        validation::validate_singapore_uen(uen)
    }

    /// Validate Singapore UEN with its layout-specific weighted mod-11 checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the UEN layout, registration year, entity type, or
    /// check letter is invalid.
    pub fn validate_singapore_uen_with_checksum(&self, uen: &str) -> Result<(), Problem> {
        validation::validate_singapore_uen_with_checksum(uen)
    }

    /// Check if a Singapore UEN is a test/dummy pattern
    #[must_use]
    pub fn is_test_singapore_uen(&self, uen: &str) -> bool {
        validation::is_test_singapore_uen(uen)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_singapore_uen_with_checksum_delegates() {
        let b = GovernmentIdentifierBuilder::new();
        // Checksum-correct values for each of the three layouts.
        assert!(b.validate_singapore_uen_with_checksum("12345678M").is_ok());
        assert!(b.validate_singapore_uen_with_checksum("201912345R").is_ok());
        assert!(b.validate_singapore_uen_with_checksum("T12LL1234C").is_ok());
        // Layout-valid but the check letter does not verify.
        assert!(b.validate_singapore_uen_with_checksum("12345678K").is_err());
    }

    #[test]
    fn test_validate_singapore_uen_format_only_is_lenient() {
        let b = GovernmentIdentifierBuilder::new();
        // The format-only variant still accepts a bad check letter.
        assert!(b.validate_singapore_uen("12345678K").is_ok());
        assert!(b.validate_singapore_uen("not a uen").is_err());
    }
}
