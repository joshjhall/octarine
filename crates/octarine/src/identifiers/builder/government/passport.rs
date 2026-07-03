//! Passport methods.

use super::*;

impl GovernmentBuilder {
    /// Check if value is a passport number
    #[must_use]
    pub fn is_passport(&self, value: &str) -> bool {
        self.inner.is_passport(value)
    }

    /// Find all passport numbers in text
    #[must_use]
    pub fn find_passports_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_passports_in_text(text)
    }

    /// Validate passport number format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the passport number format is invalid
    pub fn validate_passport(&self, passport: &str) -> Result<(), Problem> {
        let result = self.inner.validate_passport(passport);

        if self.emit_events && result.is_err() {
            observe::warn(
                "passport_validation_failed",
                "Invalid passport number format",
            );
        }

        result
    }

    /// Redact a passport number with explicit strategy
    #[must_use]
    pub fn redact_passport_with_strategy(
        &self,
        passport: &str,
        strategy: PassportRedactionStrategy,
    ) -> String {
        self.inner.redact_passport_with_strategy(passport, strategy)
    }

    /// Redact all passport numbers in text with explicit strategy
    #[must_use]
    pub fn redact_passports_in_text_with_strategy(
        &self,
        text: &str,
        strategy: PassportRedactionStrategy,
    ) -> String {
        self.inner
            .redact_passports_in_text_with_strategy(text, strategy)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // "L83726159" is a valid generic passport number (letter + 8 digits)
    // per the primitive validation tests.
    const VALID_PASSPORT: &str = "L83726159";

    #[test]
    fn test_is_passport() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_passport(VALID_PASSPORT));
        assert!(!b.is_passport("!!!"));
    }

    #[test]
    fn test_find_passports_in_text() {
        let b = GovernmentBuilder::silent();
        let matches = b.find_passports_in_text("passport L83726159 issued");
        assert!(!matches.is_empty());
        assert!(b.find_passports_in_text("no passport").is_empty());
    }

    #[test]
    fn test_validate_passport() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_passport(VALID_PASSPORT).is_ok());
        // Too short / non-conforming.
        assert!(b.validate_passport("!!!").is_err());
    }

    #[test]
    fn test_validate_passport_events_enabled() {
        let b = GovernmentBuilder::new();
        assert!(b.validate_passport(VALID_PASSPORT).is_ok());
        assert!(b.validate_passport("!!!").is_err());
    }

    #[test]
    fn test_redact_passport_with_strategy() {
        let b = GovernmentBuilder::silent();
        assert_eq!(
            b.redact_passport_with_strategy(VALID_PASSPORT, PassportRedactionStrategy::Token),
            "[PASSPORT]"
        );
        // ShowCountry keeps the first two characters, masks the rest.
        assert_eq!(
            b.redact_passport_with_strategy(VALID_PASSPORT, PassportRedactionStrategy::ShowCountry),
            "L8*******"
        );
    }

    #[test]
    fn test_redact_passports_in_text_with_strategy() {
        let b = GovernmentBuilder::silent();
        let out = b.redact_passports_in_text_with_strategy(
            "passport L83726159",
            PassportRedactionStrategy::Token,
        );
        assert!(out.contains("[PASSPORT]"));
        assert!(!out.contains("L83726159"));
    }
}
