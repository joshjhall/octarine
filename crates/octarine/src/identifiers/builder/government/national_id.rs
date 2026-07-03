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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // "AB123456C" is a valid UK NINO (valid prefix, suffix A-D).
    // "046-454-286" is a valid Canadian SIN (passes Luhn).
    const UK_NINO: &str = "AB123456C";
    const CANADA_SIN: &str = "046-454-286";

    #[test]
    fn test_is_national_id() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_national_id(UK_NINO));
        assert!(!b.is_national_id("!!!"));
    }

    #[test]
    fn test_validate_national_id_dispatch() {
        let b = GovernmentBuilder::silent();
        // Auto-detect dispatch: UK NINO and Canada SIN both validate.
        assert!(b.validate_national_id(UK_NINO).is_ok());
        assert!(b.validate_national_id(CANADA_SIN).is_ok());
        assert!(b.validate_national_id("!!!").is_err());
    }

    #[test]
    fn test_validate_national_id_events_enabled() {
        let b = GovernmentBuilder::new();
        assert!(b.validate_national_id(UK_NINO).is_ok());
        assert!(b.validate_national_id("!!!").is_err());
    }

    #[test]
    fn test_validate_uk_ni() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_uk_ni(UK_NINO).is_ok());
        // Prefix "BG" is a disallowed NINO prefix.
        assert!(b.validate_uk_ni("BG123456C").is_err());
    }

    #[test]
    fn test_validate_canada_sin() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_canada_sin(CANADA_SIN).is_ok());
        // Break the Luhn checksum.
        assert!(b.validate_canada_sin("046-454-287").is_err());
    }

    #[test]
    fn test_find_national_ids_in_text() {
        let b = GovernmentBuilder::silent();
        // Empty input yields no matches; the call path is exercised.
        assert!(b.find_national_ids_in_text("").is_empty());
    }

    #[test]
    fn test_redact_national_id_with_strategy() {
        let b = GovernmentBuilder::silent();
        assert_eq!(
            b.redact_national_id_with_strategy(UK_NINO, NationalIdRedactionStrategy::Token),
            "[NATIONAL_ID]"
        );
        assert_eq!(
            b.redact_national_id_with_strategy(UK_NINO, NationalIdRedactionStrategy::LastFour),
            "****456C"
        );
    }

    #[test]
    fn test_redact_national_ids_in_text_with_strategy() {
        let b = GovernmentBuilder::silent();
        // Exercise the call path; must not panic.
        let _ = b.redact_national_ids_in_text_with_strategy(
            "NI AB123456C",
            NationalIdRedactionStrategy::Token,
        );
    }
}
