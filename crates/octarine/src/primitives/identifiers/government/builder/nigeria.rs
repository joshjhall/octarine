//! Nigeria NIN operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches Nigeria NIN format
    #[must_use]
    pub fn is_nigeria_nin(&self, value: &str) -> bool {
        detection::is_nigeria_nin(value)
    }

    /// Find all Nigeria NINs in text (labeled occurrences only — see pattern docs)
    #[must_use]
    pub fn find_nigeria_nins_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_nigeria_nins_in_text(text)
    }

    /// Validate Nigeria NIN format (no checksum algorithm exists)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NIN format is invalid
    pub fn validate_nigeria_nin(&self, nin: &str) -> Result<(), Problem> {
        validation::validate_nigeria_nin(nin)
    }

    /// Check if a Nigeria NIN is a test/dummy pattern
    #[must_use]
    pub fn is_test_nigeria_nin(&self, nin: &str) -> bool {
        validation::is_test_nigeria_nin(nin)
    }
}
