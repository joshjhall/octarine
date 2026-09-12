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

    /// Validate a US passport number (lenient)
    ///
    /// Accepts both US layouts — 9 digits (legacy) and 1 letter + 8 digits
    /// (Next Generation) — and does not reject test patterns. Use
    /// [`Self::validate_us_passport_strict`] to reject those.
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the number matches neither US layout
    pub fn validate_us_passport(&self, passport: &str) -> Result<(), Problem> {
        let result = self.inner.validate_us_passport(passport);

        if self.emit_events && result.is_err() {
            observe::warn(
                "us_passport_validation_failed",
                "Invalid US passport number format",
            );
        }

        result
    }

    /// Validate a US passport number, rejecting known test patterns (strict)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the format is invalid or the number is a test pattern
    pub fn validate_us_passport_strict(&self, passport: &str) -> Result<(), Problem> {
        let result = self.inner.validate_us_passport_strict(passport);

        if self.emit_events && result.is_err() {
            observe::warn(
                "us_passport_validation_failed",
                "Invalid or test US passport number",
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
    fn test_validate_us_passport_accepts_both_layouts() {
        let b = GovernmentBuilder::silent();
        // Legacy 9-digit book — rejected by the generic ICAO validator.
        assert!(b.validate_us_passport("123456789").is_ok());
        assert!(b.validate_passport("123456789").is_err());
        // Next Generation letter + 8 digits.
        assert!(b.validate_us_passport("A83726159").is_ok());
        // Neither layout.
        assert!(b.validate_us_passport("AB1234567").is_err());
    }

    #[test]
    fn test_validate_us_passport_strict_rejects_test_patterns() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_us_passport("A12345678").is_ok());
        assert!(b.validate_us_passport_strict("A12345678").is_err());
        assert!(b.validate_us_passport_strict("A83726159").is_ok());
    }

    #[test]
    fn test_validate_us_passport_events_enabled() {
        let b = GovernmentBuilder::new();
        assert!(b.validate_us_passport("123456789").is_ok());
        assert!(b.validate_us_passport("!!!").is_err());
        assert!(b.validate_us_passport_strict("A11111111").is_err());
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
