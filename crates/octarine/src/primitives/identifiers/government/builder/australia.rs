//! Australia TFN and ABN operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches Australian TFN format
    #[must_use]
    pub fn is_australia_tfn(&self, value: &str) -> bool {
        detection::is_australia_tfn(value)
    }

    /// Find all Australian TFNs in text
    #[must_use]
    pub fn find_australia_tfns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_australia_tfns_in_text(text)
    }

    /// Validate Australian TFN format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the TFN format is invalid
    pub fn validate_australia_tfn(&self, tfn: &str) -> Result<(), Problem> {
        validation::validate_australia_tfn(tfn)
    }

    /// Validate Australian TFN with mod-11 weighted checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the TFN format is invalid or checksum fails
    pub fn validate_australia_tfn_with_checksum(&self, tfn: &str) -> Result<(), Problem> {
        validation::validate_australia_tfn_with_checksum(tfn)
    }

    /// Check if an Australian TFN is a test/dummy pattern
    #[must_use]
    pub fn is_test_australia_tfn(&self, tfn: &str) -> bool {
        validation::is_test_australia_tfn(tfn)
    }

    /// Check if value matches Australian ABN format
    #[must_use]
    pub fn is_australia_abn(&self, value: &str) -> bool {
        detection::is_australia_abn(value)
    }

    /// Find all Australian ABNs in text
    #[must_use]
    pub fn find_australia_abns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_australia_abns_in_text(text)
    }

    /// Validate Australian ABN format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the ABN format is invalid
    pub fn validate_australia_abn(&self, abn: &str) -> Result<(), Problem> {
        validation::validate_australia_abn(abn)
    }

    /// Validate Australian ABN with mod-89 weighted checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the ABN format is invalid or checksum fails
    pub fn validate_australia_abn_with_checksum(&self, abn: &str) -> Result<(), Problem> {
        validation::validate_australia_abn_with_checksum(abn)
    }

    /// Check if an Australian ABN is a test/dummy pattern
    #[must_use]
    pub fn is_test_australia_abn(&self, abn: &str) -> bool {
        validation::is_test_australia_abn(abn)
    }
}
