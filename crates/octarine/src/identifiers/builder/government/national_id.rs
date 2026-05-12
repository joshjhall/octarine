//! National ID methods (generic + UK NI + Canada SIN validators).

use super::*;

impl GovernmentBuilder {
    /// Check if value is a national ID
    #[must_use]
    pub fn is_national_id(&self, value: &str) -> bool {
        self.inner.is_national_id(value)
    }

    /// Find all national IDs in text
    #[must_use]
    pub fn find_national_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_national_ids_in_text(text)
    }

    /// Validate national ID format (auto-detects UK NI, Canada SIN, or generic)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the national ID format is invalid
    pub fn validate_national_id(&self, national_id: &str) -> Result<(), Problem> {
        let result = self.inner.validate_national_id(national_id);

        if self.emit_events && result.is_err() {
            observe::warn(
                "national_id_validation_failed",
                "Invalid national ID format",
            );
        }

        result
    }

    /// Validate UK National Insurance Number
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NI number format is invalid
    pub fn validate_uk_ni(&self, ni: &str) -> Result<(), Problem> {
        self.inner.validate_uk_ni(ni)
    }

    /// Validate Canadian Social Insurance Number with Luhn checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the SIN format is invalid or checksum fails
    pub fn validate_canada_sin(&self, sin: &str) -> Result<(), Problem> {
        self.inner.validate_canada_sin(sin)
    }

    /// Redact a national ID with explicit strategy
    #[must_use]
    pub fn redact_national_id_with_strategy(
        &self,
        national_id: &str,
        strategy: NationalIdRedactionStrategy,
    ) -> String {
        self.inner
            .redact_national_id_with_strategy(national_id, strategy)
    }

    /// Redact all national IDs in text with explicit strategy
    #[must_use]
    pub fn redact_national_ids_in_text_with_strategy(
        &self,
        text: &str,
        strategy: NationalIdRedactionStrategy,
    ) -> String {
        self.inner
            .redact_national_ids_in_text_with_strategy(text, strategy)
    }
}
