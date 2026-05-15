//! UK National Insurance Number (NINO) operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value is a valid UK National Insurance Number (NINO)
    ///
    /// Applies HMRC prefix/suffix rules on top of the format check, so
    /// matches like `BG123456A` (invalid prefix) return false.
    #[must_use]
    pub fn is_uk_ni(&self, value: &str) -> bool {
        detection::is_uk_ni(value)
    }

    /// Find all UK NINOs in text (with validation filtering)
    #[must_use]
    pub fn find_uk_nis_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_uk_nis_in_text(text)
    }

    /// Redact a UK NINO with explicit strategy
    ///
    /// Delegates to the shared national-ID redaction since NINOs share the
    /// 9-character shape expected by that redactor.
    #[must_use]
    pub fn redact_uk_ni_with_strategy(
        &self,
        ni: &str,
        strategy: NationalIdRedactionStrategy,
    ) -> String {
        sanitization::redact_national_id_with_strategy(ni, strategy)
    }

    /// Redact all UK NINOs in text with explicit strategy
    ///
    /// Scans for UK-specific NINO patterns (filtered by prefix/suffix rules),
    /// then redacts only the NINO value — preserving any label prefix
    /// ("NI: ", "NINO ", ...) around it. Invalid NINOs (bad prefix or
    /// suffix) are left unchanged.
    #[must_use]
    pub fn redact_uk_nis_in_text_with_strategy(
        &self,
        text: &str,
        strategy: NationalIdRedactionStrategy,
    ) -> String {
        sanitization::redact_uk_nis_in_text_with_strategy(text, strategy).into_owned()
    }
}
