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

    /// Check if a Singapore UEN is a test/dummy pattern
    #[must_use]
    pub fn is_test_singapore_uen(&self, uen: &str) -> bool {
        validation::is_test_singapore_uen(uen)
    }
}
