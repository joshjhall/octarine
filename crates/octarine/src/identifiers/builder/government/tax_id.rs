//! Tax ID and EIN methods.

use super::*;

impl GovernmentBuilder {
    /// Check if value is a tax ID
    #[must_use]
    pub fn is_tax_id(&self, value: &str) -> bool {
        self.inner.is_tax_id(value)
    }

    /// Find all tax IDs in text
    #[must_use]
    pub fn find_tax_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_tax_ids_in_text(text)
    }

    /// Check if value is a valid EIN (Employer Identification Number)
    ///
    /// Validates both the `XX-XXXXXXX` format and the IRS campus code prefix.
    #[must_use]
    pub fn is_ein(&self, value: &str) -> bool {
        self.inner.is_ein(value)
    }

    /// Find all valid EINs in text
    #[must_use]
    pub fn find_eins_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_eins_in_text(text)
    }

    /// Validate EIN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the EIN format is invalid
    pub fn validate_ein(&self, ein: &str) -> Result<(), Problem> {
        self.inner.validate_ein(ein)
    }

    /// Redact a tax ID with explicit strategy
    #[must_use]
    pub fn redact_tax_id_with_strategy(
        &self,
        tax_id: &str,
        strategy: TaxIdRedactionStrategy,
    ) -> String {
        self.inner.redact_tax_id_with_strategy(tax_id, strategy)
    }

    /// Redact all tax IDs in text with explicit strategy
    #[must_use]
    pub fn redact_tax_ids_in_text_with_strategy(
        &self,
        text: &str,
        strategy: TaxIdRedactionStrategy,
    ) -> String {
        self.inner
            .redact_tax_ids_in_text_with_strategy(text, strategy)
    }

    /// Normalize an EIN (remove formatting)
    #[must_use]
    pub fn normalize_ein(&self, ein: &str) -> String {
        self.inner.normalize_ein(ein)
    }

    /// Convert EIN to standard hyphenated format
    #[must_use]
    pub fn to_ein_with_hyphen(&self, ein: &str) -> String {
        self.inner.to_ein_with_hyphen(ein)
    }

    /// Sanitize an EIN (normalize + validate)
    pub fn sanitize_ein(&self, ein: &str) -> Result<String, Problem> {
        self.inner.sanitize_ein(ein)
    }

    /// Check if value is a valid ITIN (Individual Taxpayer Identification Number)
    ///
    /// Strict — requires `XXX-XX-XXXX` layout, area `9XX`, and a middle group
    /// in `{50-65, 70-88, 90-92, 94-99}` per IRS Publication 1915.
    #[must_use]
    pub fn is_itin(&self, value: &str) -> bool {
        self.inner.is_itin(value)
    }

    /// Find all valid ITINs in text
    #[must_use]
    pub fn find_itins_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_itins_in_text(text)
    }

    /// Validate ITIN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the ITIN format, area, middle group, or serial
    /// is invalid.
    pub fn validate_itin(&self, itin: &str) -> Result<(), Problem> {
        self.inner.validate_itin(itin)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::identifiers::types::IdentifierType;

    // "12-3456789" is a valid EIN (IRS Brookhaven campus prefix 12).
    // "900-70-0001" is a valid ITIN (area 9XX, middle group 70 in 70-88).
    const VALID_EIN: &str = "12-3456789";
    const INVALID_EIN: &str = "00-0000000";
    const VALID_ITIN: &str = "900-70-0001";

    #[test]
    fn test_is_tax_id() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_tax_id(VALID_EIN));
        assert!(!b.is_tax_id("not-a-tax-id"));
    }

    #[test]
    fn test_find_tax_ids_in_text() {
        let b = GovernmentBuilder::silent();
        let matches = b.find_tax_ids_in_text("EIN: 12-3456789");
        assert!(!matches.is_empty());
        assert!(b.find_tax_ids_in_text("nothing").is_empty());
    }

    #[test]
    fn test_is_ein_valid_invalid() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_ein(VALID_EIN));
        // Prefix 00 is not a valid IRS campus code.
        assert!(!b.is_ein(INVALID_EIN));
    }

    #[test]
    fn test_find_eins_in_text() {
        let b = GovernmentBuilder::silent();
        let matches = b.find_eins_in_text("company EIN 12-3456789 filed");
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("one match").identifier_type,
            IdentifierType::Ein
        );
    }

    #[test]
    fn test_validate_ein() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_ein(VALID_EIN).is_ok());
        assert!(b.validate_ein(INVALID_EIN).is_err());
    }

    #[test]
    fn test_redact_tax_id_with_strategy() {
        let b = GovernmentBuilder::silent();
        assert_eq!(
            b.redact_tax_id_with_strategy(VALID_EIN, TaxIdRedactionStrategy::Token),
            "[TAX_ID]"
        );
        assert_eq!(
            b.redact_tax_id_with_strategy(VALID_EIN, TaxIdRedactionStrategy::ShowPrefix),
            "12-*******"
        );
    }

    #[test]
    fn test_redact_tax_ids_in_text_with_strategy() {
        let b = GovernmentBuilder::silent();
        let out =
            b.redact_tax_ids_in_text_with_strategy("EIN 12-3456789", TaxIdRedactionStrategy::Token);
        assert!(out.contains("[TAX_ID]"));
        assert!(!out.contains("12-3456789"));
    }

    #[test]
    fn test_normalize_and_convert_ein() {
        let b = GovernmentBuilder::silent();
        assert_eq!(b.normalize_ein("12-3456789"), "123456789");
        assert_eq!(b.to_ein_with_hyphen("123456789"), "12-3456789");
    }

    #[test]
    fn test_sanitize_ein() {
        let b = GovernmentBuilder::silent();
        assert_eq!(b.sanitize_ein("12-3456789").expect("valid"), "12-3456789");
        assert!(b.sanitize_ein(INVALID_EIN).is_err());
    }

    #[test]
    fn test_is_itin_valid_invalid() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_itin(VALID_ITIN));
        // group 01 is not in a valid ITIN middle-group range.
        assert!(!b.is_itin("900-01-0001"));
    }

    #[test]
    fn test_find_itins_in_text() {
        let b = GovernmentBuilder::silent();
        let matches = b.find_itins_in_text("ITIN 900-70-0001 on file");
        assert!(!matches.is_empty());
        assert!(b.find_itins_in_text("no itin").is_empty());
    }

    #[test]
    fn test_validate_itin() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_itin(VALID_ITIN).is_ok());
        assert!(b.validate_itin("900-01-0001").is_err());
    }
}
