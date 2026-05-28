//! UK identifier operations on `GovernmentIdentifierBuilder` — National
//! Insurance Number (NINO), NHS Number, Passport, Driving Licence (DVLA).

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

    // ------------------------------------------------------------------
    // UK NHS Number — 10 digits, mod-11 weighted checksum
    // ------------------------------------------------------------------

    /// Check if value matches the UK NHS Number format (10 digits)
    #[must_use]
    pub fn is_uk_nhs(&self, value: &str) -> bool {
        detection::is_uk_nhs(value)
    }

    /// Find all UK NHS Numbers in text (label-anchored or grouped form)
    #[must_use]
    pub fn find_uk_nhs_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_uk_nhs_in_text(text)
    }

    /// Validate UK NHS Number format
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the value is not 10 decimal digits
    /// after stripping spaces or hyphens.
    pub fn validate_uk_nhs(&self, value: &str) -> Result<(), Problem> {
        validation::validate_uk_nhs(value)
    }

    /// Validate UK NHS Number including the mod-11 weighted checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the format check fails, the value
    /// is a placeholder pattern, or the checksum does not match.
    pub fn validate_uk_nhs_with_checksum(&self, value: &str) -> Result<(), Problem> {
        validation::validate_uk_nhs_with_checksum(value)
    }

    // ------------------------------------------------------------------
    // UK Passport — 2 letters + 7 digits
    // ------------------------------------------------------------------

    /// Check if value matches the UK passport format
    #[must_use]
    pub fn is_uk_passport(&self, value: &str) -> bool {
        detection::is_uk_passport(value)
    }

    /// Find all UK passport patterns in text (label-anchored)
    #[must_use]
    pub fn find_uk_passports_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_uk_passports_in_text(text)
    }

    /// Validate UK passport format
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the value is not 2 letters + 7 digits.
    pub fn validate_uk_passport(&self, value: &str) -> Result<(), Problem> {
        validation::validate_uk_passport(value)
    }

    // ------------------------------------------------------------------
    // UK Driving Licence (DVLA) — 16-char structural shape
    // ------------------------------------------------------------------

    /// Check if value matches the UK DVLA driving licence format
    #[must_use]
    pub fn is_uk_driving_licence(&self, value: &str) -> bool {
        detection::is_uk_driving_licence(value)
    }

    /// Find all UK DVLA driving licence patterns in text (label-anchored)
    #[must_use]
    pub fn find_uk_driving_licences_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_uk_driving_licences_in_text(text)
    }

    /// Validate UK DVLA driving licence shape
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the value does not match the
    /// 16-character structural shape, or if the surname is the all-9
    /// placeholder.
    pub fn validate_uk_driving_licence(&self, value: &str) -> Result<(), Problem> {
        validation::validate_uk_driving_licence(value)
    }
}
