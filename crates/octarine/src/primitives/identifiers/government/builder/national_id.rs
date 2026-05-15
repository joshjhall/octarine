//! National ID operations (generic + UK NI + Canada SIN) on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches national ID format
    #[must_use]
    pub fn is_national_id(&self, value: &str) -> bool {
        detection::is_national_id(value)
    }

    /// Find all national IDs in text
    #[must_use]
    pub fn find_national_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_national_ids_in_text(text)
    }

    /// Validate national ID format (auto-detects UK NI, Canada SIN, or generic)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the national ID format is invalid
    pub fn validate_national_id(&self, national_id: &str) -> Result<(), Problem> {
        validation::validate_national_id(national_id)
    }

    /// Validate UK National Insurance Number
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NI number format is invalid
    pub fn validate_uk_ni(&self, ni: &str) -> Result<(), Problem> {
        validation::validate_uk_ni(ni)
    }

    /// Validate Canadian Social Insurance Number with Luhn checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the SIN format is invalid or checksum fails
    pub fn validate_canada_sin(&self, sin: &str) -> Result<(), Problem> {
        validation::validate_canada_sin(sin)
    }

    /// Redact national ID with explicit strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, NationalIdRedactionStrategy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    /// let result = builder.redact_national_id_with_strategy(
    ///     "AB123456C",
    ///     NationalIdRedactionStrategy::Token,
    /// );
    /// assert_eq!(result, "[NATIONAL_ID]");
    /// ```
    #[must_use]
    pub fn redact_national_id_with_strategy(
        &self,
        national_id: &str,
        strategy: NationalIdRedactionStrategy,
    ) -> String {
        sanitization::redact_national_id_with_strategy(national_id, strategy)
    }

    /// Redact all national IDs in text with explicit strategy
    #[must_use]
    pub fn redact_national_ids_in_text_with_strategy(
        &self,
        text: &str,
        strategy: NationalIdRedactionStrategy,
    ) -> String {
        sanitization::redact_national_ids_in_text_with_strategy(text, strategy).into_owned()
    }
}
