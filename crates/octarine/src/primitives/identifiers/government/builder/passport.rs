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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_passport_operations() {
        let gov = GovernmentIdentifierBuilder::new();
        assert!(gov.is_passport("C12345678"));
        assert!(gov.validate_passport("L83726159").is_ok());
        assert!(gov.validate_passport("!!!").is_err());
    }

    #[test]
    fn test_us_passport_operations() {
        let gov = GovernmentIdentifierBuilder::new();
        // Legacy 9-digit books are accepted here but not by the generic ICAO
        // validator — so this delegation is doing something distinct.
        assert!(gov.validate_us_passport("123456789").is_ok());
        assert!(gov.validate_passport("123456789").is_err());
        assert!(gov.validate_us_passport("A83726159").is_ok());
        assert!(gov.validate_us_passport("AB1234567").is_err());
    }

    #[test]
    fn test_us_passport_strict_operations() {
        let gov = GovernmentIdentifierBuilder::new();
        // The strict/lenient split must survive the builder delegation.
        assert!(gov.validate_us_passport("A12345678").is_ok());
        assert!(gov.validate_us_passport_strict("A12345678").is_err());
        assert!(gov.validate_us_passport_strict("A83726159").is_ok());
    }

    #[test]
    fn test_redact_passport_with_strategy() {
        let gov = GovernmentIdentifierBuilder::new();
        assert_eq!(
            gov.redact_passport_with_strategy("L83726159", PassportRedactionStrategy::Token),
            "[PASSPORT]"
        );
    }
}
