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
