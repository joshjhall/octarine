//! Tax ID (EIN, TIN, ITIN) operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches tax ID format (EIN, TIN, ITIN)
    #[must_use]
    pub fn is_tax_id(&self, value: &str) -> bool {
        detection::is_tax_id(value)
    }

    /// Find all tax IDs in text
    #[must_use]
    pub fn find_tax_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_tax_ids_in_text(text)
    }

    /// Check if value is a valid EIN (Employer Identification Number)
    ///
    /// Validates both the `XX-XXXXXXX` format and the IRS campus code prefix.
    #[must_use]
    pub fn is_ein(&self, value: &str) -> bool {
        detection::is_ein(value)
    }

    /// Find all valid EINs in text
    #[must_use]
    pub fn find_eins_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_eins_in_text(text)
    }

    /// Validate EIN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the EIN format is invalid
    pub fn validate_ein(&self, ein: &str) -> Result<(), Problem> {
        validation::validate_ein(ein)
    }

    /// Redact tax ID with explicit strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, TaxIdRedactionStrategy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    /// let result = builder.redact_tax_id_with_strategy("12-3456789", TaxIdRedactionStrategy::Token);
    /// assert_eq!(result, "[TAX_ID]");
    /// ```
    #[must_use]
    pub fn redact_tax_id_with_strategy(
        &self,
        tax_id: &str,
        strategy: TaxIdRedactionStrategy,
    ) -> String {
        sanitization::redact_tax_id_with_strategy(tax_id, strategy)
    }

    /// Redact all tax IDs in text with explicit strategy
    #[must_use]
    pub fn redact_tax_ids_in_text_with_strategy(
        &self,
        text: &str,
        strategy: TaxIdRedactionStrategy,
    ) -> String {
        sanitization::redact_tax_ids_in_text_with_strategy(text, strategy).into_owned()
    }

    /// Normalize EIN to digits only
    #[must_use]
    pub fn normalize_ein(&self, ein: &str) -> String {
        conversion::normalize_ein(ein)
    }

    /// Convert EIN to standard hyphenated format
    #[must_use]
    pub fn to_ein_with_hyphen(self, ein: &str) -> String {
        conversion::to_ein_with_hyphen(ein)
    }

    /// Sanitize EIN strict (normalize + validate)
    ///
    /// Combines normalization and validation in one step.
    /// Returns formatted EIN if valid, error otherwise.
    pub fn sanitize_ein(&self, ein: &str) -> Result<String, Problem> {
        sanitization::sanitize_ein_strict(ein)
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
    fn test_tax_id_operations() {
        let gov = builder();
        assert!(gov.is_tax_id("00-0000001"));
        assert_eq!(
            gov.redact_tax_id_with_strategy("00-0000001", TaxIdRedactionStrategy::Token),
            "[TAX_ID]"
        );
        assert_eq!(gov.to_ein_with_hyphen("123456789"), "12-3456789");
    }
}
