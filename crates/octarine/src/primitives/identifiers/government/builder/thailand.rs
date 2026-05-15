//! Thailand TNIN operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches Thailand TNIN format
    #[must_use]
    pub fn is_thailand_tnin(&self, value: &str) -> bool {
        detection::is_thailand_tnin(value)
    }

    /// Find all Thailand TNINs in text
    #[must_use]
    pub fn find_thailand_tnins_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_thailand_tnins_in_text(text)
    }

    /// Validate Thailand TNIN format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the TNIN format is invalid
    pub fn validate_thailand_tnin(&self, tnin: &str) -> Result<(), Problem> {
        validation::validate_thailand_tnin(tnin)
    }

    /// Validate Thailand TNIN with mod-11 check digit verification
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the TNIN format or checksum is invalid
    pub fn validate_thailand_tnin_with_checksum(&self, tnin: &str) -> Result<(), Problem> {
        validation::validate_thailand_tnin_with_checksum(tnin)
    }

    /// Check if a Thailand TNIN is a test/dummy pattern
    #[must_use]
    pub fn is_test_thailand_tnin(&self, tnin: &str) -> bool {
        validation::is_test_thailand_tnin(tnin)
    }
}
