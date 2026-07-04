//! US Medicare Beneficiary Identifier (MBI) operations on
//! `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value is a valid US Medicare Beneficiary Identifier (MBI)
    ///
    /// Strict — enforces the 11-character CMS layout
    /// (`C A AN N A AN N A A N N`) and the letter alphabet
    /// `ACDEFGHJKMNPQRTUVWXY` (excluding `S, L, O, I, B, Z`). Accepts both the
    /// bare and dashed `XXXX-XXX-XXXX` forms.
    #[must_use]
    pub fn is_us_mbi(&self, value: &str) -> bool {
        detection::is_us_mbi(value)
    }

    /// Find all valid US MBIs in text
    ///
    /// Dashed matches get `High` confidence; bare 11-character matches get
    /// `Medium`. Only structurally valid MBIs are returned.
    #[must_use]
    pub fn find_us_mbis_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_us_mbis_in_text(text)
    }

    /// Validate a US MBI
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the MBI length, dash grouping, positional layout,
    /// or letter alphabet is invalid.
    pub fn validate_us_mbi(&self, mbi: &str) -> Result<(), Problem> {
        validation::validate_us_mbi(mbi)
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
    fn test_us_mbi_operations() {
        let gov = builder();
        assert!(gov.is_us_mbi("1EG4TE5MK73"));
        assert!(gov.is_us_mbi("1EG4-TE5-MK73"));
        assert!(!gov.is_us_mbi("1AB2C3D4EF5")); // excluded letter / bad layout
        assert!(gov.validate_us_mbi("1EG4TE5MK73").is_ok());
        assert!(gov.validate_us_mbi("").is_err());
        assert!(!gov.find_us_mbis_in_text("MBI: 1EG4-TE5-MK73").is_empty());
    }
}
