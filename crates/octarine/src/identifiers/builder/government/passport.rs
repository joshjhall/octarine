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
