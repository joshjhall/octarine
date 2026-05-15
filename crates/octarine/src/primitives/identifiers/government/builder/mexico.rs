//! Mexico CURP operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches Mexico CURP format
    #[must_use]
    pub fn is_mexico_curp(&self, value: &str) -> bool {
        detection::is_mexico_curp(value)
    }

    /// Find all Mexico CURPs in text
    #[must_use]
    pub fn find_mexico_curps_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_mexico_curps_in_text(text)
    }

    /// Validate Mexico CURP format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the CURP format is invalid
    pub fn validate_mexico_curp(&self, curp: &str) -> Result<(), Problem> {
        validation::validate_mexico_curp(curp)
    }

    /// Validate Mexico CURP with check digit verification
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the CURP format or checksum is invalid
    pub fn validate_mexico_curp_with_checksum(&self, curp: &str) -> Result<(), Problem> {
        validation::validate_mexico_curp_with_checksum(curp)
    }

    /// Check if a Mexico CURP is a test/dummy pattern
    #[must_use]
    pub fn is_test_mexico_curp(&self, curp: &str) -> bool {
        validation::is_test_mexico_curp(curp)
    }
}
