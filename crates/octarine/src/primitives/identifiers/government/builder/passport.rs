//! Passport operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches passport format
    #[must_use]
    pub fn is_passport(&self, value: &str) -> bool {
        detection::is_passport(value)
    }

    /// Find all passports in text
    #[must_use]
    pub fn find_passports_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_passports_in_text(text)
    }

    /// Validate passport number format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the passport number format is invalid
    pub fn validate_passport(&self, passport: &str) -> Result<(), Problem> {
        validation::validate_passport(passport)
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
        validation::validate_us_passport(passport)
    }

    /// Validate a US passport number, rejecting known test patterns (strict)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the format is invalid or the number is a test pattern
    pub fn validate_us_passport_strict(&self, passport: &str) -> Result<(), Problem> {
        validation::validate_us_passport_strict(passport)
    }

    /// Redact passport with explicit strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, PassportRedactionStrategy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    /// let result = builder.redact_passport_with_strategy(
    ///     "US1234567",
    ///     PassportRedactionStrategy::Token,
    /// );
    /// assert_eq!(result, "[PASSPORT]");
    /// ```
    #[must_use]
    pub fn redact_passport_with_strategy(
        &self,
        passport: &str,
        strategy: PassportRedactionStrategy,
    ) -> String {
        sanitization::redact_passport_with_strategy(passport, strategy)
    }

    /// Redact all passports in text with explicit strategy
    #[must_use]
    pub fn redact_passports_in_text_with_strategy(
        &self,
        text: &str,
        strategy: PassportRedactionStrategy,
    ) -> String {
        sanitization::redact_passports_in_text_with_strategy(text, strategy).into_owned()
    }
}
