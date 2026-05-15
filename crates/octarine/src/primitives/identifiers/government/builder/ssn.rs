//! SSN operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches SSN format
    #[must_use]
    pub fn is_ssn(&self, value: &str) -> bool {
        detection::is_ssn(value)
    }

    /// Find all SSNs in text
    #[must_use]
    pub fn find_ssns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_ssns_in_text(text)
    }

    /// Validate SSN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the SSN format is invalid
    pub fn validate_ssn(&self, ssn: &str) -> Result<(), Problem> {
        validation::validate_ssn(ssn)
    }

    /// Check if SSN area code indicates ITIN
    #[must_use]
    pub fn is_itin_area(&self, ssn: &str) -> bool {
        common::is_itin_area(ssn)
    }

    /// Redact SSN with explicit strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, SsnRedactionStrategy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    /// let result = builder.redact_ssn_with_strategy("900-00-0001", SsnRedactionStrategy::Token);
    /// assert_eq!(result, "[SSN]");
    /// ```
    #[must_use]
    pub fn redact_ssn_with_strategy(&self, ssn: &str, strategy: SsnRedactionStrategy) -> String {
        sanitization::redact_ssn_with_strategy(ssn, strategy)
    }

    /// Redact all SSNs in text with explicit strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, SsnRedactionStrategy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    /// let result = builder.redact_ssns_in_text_with_strategy(
    ///     "SSN: 900-00-0001",
    ///     SsnRedactionStrategy::LastFour,
    /// );
    /// assert!(result.contains("***-**-0001"));
    /// ```
    #[must_use]
    pub fn redact_ssns_in_text_with_strategy(
        &self,
        text: &str,
        strategy: SsnRedactionStrategy,
    ) -> String {
        sanitization::redact_ssns_in_text_with_strategy(text, strategy).into_owned()
    }

    /// Normalize SSN to digits only
    #[must_use]
    pub fn normalize_ssn(&self, ssn: &str) -> String {
        conversion::normalize_ssn(ssn)
    }

    /// Convert SSN to standard hyphenated format
    #[must_use]
    pub fn to_ssn_with_hyphens(self, ssn: &str) -> String {
        conversion::to_ssn_with_hyphens(ssn)
    }

    /// Convert SSN to safe display format (masked)
    #[must_use]
    pub fn to_ssn_display(self, ssn: &str) -> String {
        conversion::to_ssn_display(ssn)
    }

    /// Sanitize SSN strict (normalize + validate)
    ///
    /// Combines normalization and validation in one step.
    /// Returns formatted SSN if valid, error otherwise.
    pub fn sanitize_ssn(&self, ssn: &str) -> Result<String, Problem> {
        sanitization::sanitize_ssn_strict(ssn)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    fn builder() -> GovernmentIdentifierBuilder {
        GovernmentIdentifierBuilder::new()
    }

    #[test]
    fn test_ssn_detection() {
        let gov = builder();
        assert!(gov.is_ssn("517-29-8346"));
        assert!(!gov.is_ssn("invalid"));
    }

    #[test]
    fn test_ssn_validation() {
        let gov = builder();
        assert!(gov.validate_ssn("517-29-8346").is_ok());
        assert!(gov.validate_ssn("123-45-6789").is_err()); // Test pattern
        assert!(gov.validate_ssn("000-12-3456").is_err()); // Invalid area
    }

    #[test]
    fn test_ssn_sanitization() {
        let gov = builder();
        assert_eq!(
            gov.redact_ssn_with_strategy("517-29-8346", SsnRedactionStrategy::Token),
            "[SSN]"
        );
        assert_eq!(
            gov.redact_ssn_with_strategy("517-29-8346", SsnRedactionStrategy::LastFour),
            "***-**-8346"
        );
    }

    #[test]
    fn test_ssn_conversion() {
        let gov = builder();
        assert_eq!(gov.normalize_ssn("123-45-6789"), "123456789");
        assert_eq!(gov.to_ssn_with_hyphens("123456789"), "123-45-6789");
    }
}
