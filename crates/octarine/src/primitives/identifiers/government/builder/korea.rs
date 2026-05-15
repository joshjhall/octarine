//! South Korea RRN operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches South Korea RRN format
    #[must_use]
    pub fn is_korea_rrn(&self, value: &str) -> bool {
        detection::is_korea_rrn(value)
    }

    /// Find all Korea RRNs in text
    #[must_use]
    pub fn find_korea_rrns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_korea_rrns_in_text(text)
    }

    /// Validate Korea RRN format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the RRN format is invalid
    pub fn validate_korea_rrn(&self, rrn: &str) -> Result<(), Problem> {
        validation::validate_korea_rrn(rrn)
    }

    /// Validate Korea RRN with weighted checksum verification
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the RRN format is invalid or checksum fails
    pub fn validate_korea_rrn_with_checksum(&self, rrn: &str) -> Result<(), Problem> {
        validation::validate_korea_rrn_with_checksum(rrn)
    }

    /// Check if a Korea RRN is a test/dummy pattern
    #[must_use]
    pub fn is_test_korea_rrn(&self, rrn: &str) -> bool {
        validation::is_test_korea_rrn(rrn)
    }
}
