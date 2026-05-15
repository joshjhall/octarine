//! European national identifier operations on `GovernmentIdentifierBuilder`.
//!
//! Covers Finland HETU, Spain NIF and NIE, Italy Codice Fiscale, and Poland PESEL.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches Finland HETU format
    #[must_use]
    pub fn is_finland_hetu(&self, value: &str) -> bool {
        detection::is_finland_hetu(value)
    }

    /// Find all Finland HETUs in text
    #[must_use]
    pub fn find_finland_hetus_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_finland_hetus_in_text(text)
    }

    /// Validate Finland HETU format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the HETU format is invalid
    pub fn validate_finland_hetu(&self, hetu: &str) -> Result<(), Problem> {
        validation::validate_finland_hetu(hetu)
    }

    /// Validate Finland HETU with mod-31 checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the HETU format is invalid or checksum fails
    pub fn validate_finland_hetu_with_checksum(&self, hetu: &str) -> Result<(), Problem> {
        validation::validate_finland_hetu_with_checksum(hetu)
    }

    /// Check if a Finland HETU is a test/dummy pattern
    #[must_use]
    pub fn is_test_finland_hetu(&self, hetu: &str) -> bool {
        validation::is_test_finland_hetu(hetu)
    }

    /// Check if value matches Spain NIF format
    #[must_use]
    pub fn is_spain_nif(&self, value: &str) -> bool {
        detection::is_spain_nif(value)
    }

    /// Find all Spain NIFs in text
    #[must_use]
    pub fn find_spain_nifs_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_spain_nifs_in_text(text)
    }

    /// Validate Spain NIF format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NIF format is invalid
    pub fn validate_spain_nif(&self, nif: &str) -> Result<(), Problem> {
        validation::validate_spain_nif(nif)
    }

    /// Validate Spain NIF with mod-23 checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NIF format is invalid or checksum fails
    pub fn validate_spain_nif_with_checksum(&self, nif: &str) -> Result<(), Problem> {
        validation::validate_spain_nif_with_checksum(nif)
    }

    /// Check if a Spain NIF is a test/dummy pattern
    #[must_use]
    pub fn is_test_spain_nif(&self, nif: &str) -> bool {
        validation::is_test_spain_nif(nif)
    }

    /// Check if value matches Spain NIE format
    #[must_use]
    pub fn is_spain_nie(&self, value: &str) -> bool {
        detection::is_spain_nie(value)
    }

    /// Find all Spain NIEs in text
    #[must_use]
    pub fn find_spain_nies_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_spain_nies_in_text(text)
    }

    /// Validate Spain NIE format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NIE format is invalid
    pub fn validate_spain_nie(&self, nie: &str) -> Result<(), Problem> {
        validation::validate_spain_nie(nie)
    }

    /// Validate Spain NIE with mod-23 checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NIE format is invalid or checksum fails
    pub fn validate_spain_nie_with_checksum(&self, nie: &str) -> Result<(), Problem> {
        validation::validate_spain_nie_with_checksum(nie)
    }

    /// Check if a Spain NIE is a test/dummy pattern
    #[must_use]
    pub fn is_test_spain_nie(&self, nie: &str) -> bool {
        validation::is_test_spain_nie(nie)
    }

    /// Check if value matches Italy Codice Fiscale format
    #[must_use]
    pub fn is_italy_fiscal_code(&self, value: &str) -> bool {
        detection::is_italy_fiscal_code(value)
    }

    /// Find all Italy Codice Fiscale patterns in text
    #[must_use]
    pub fn find_italy_fiscal_codes_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_italy_fiscal_codes_in_text(text)
    }

    /// Validate Italy Codice Fiscale format (without check character)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the Codice Fiscale format is invalid
    pub fn validate_italy_fiscal_code(&self, cf: &str) -> Result<(), Problem> {
        validation::validate_italy_fiscal_code(cf)
    }

    /// Validate Italy Codice Fiscale with check character
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the Codice Fiscale format is invalid or check character fails
    pub fn validate_italy_fiscal_code_with_checksum(&self, cf: &str) -> Result<(), Problem> {
        validation::validate_italy_fiscal_code_with_checksum(cf)
    }

    /// Check if an Italy Codice Fiscale is a test/dummy pattern
    #[must_use]
    pub fn is_test_italy_fiscal_code(&self, cf: &str) -> bool {
        validation::is_test_italy_fiscal_code(cf)
    }

    /// Check if value matches Poland PESEL format
    #[must_use]
    pub fn is_poland_pesel(&self, value: &str) -> bool {
        detection::is_poland_pesel(value)
    }

    /// Find all Poland PESELs in text
    #[must_use]
    pub fn find_poland_pesels_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_poland_pesels_in_text(text)
    }

    /// Validate Poland PESEL format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the PESEL format is invalid
    pub fn validate_poland_pesel(&self, pesel: &str) -> Result<(), Problem> {
        validation::validate_poland_pesel(pesel)
    }

    /// Validate Poland PESEL with weighted checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the PESEL format is invalid or checksum fails
    pub fn validate_poland_pesel_with_checksum(&self, pesel: &str) -> Result<(), Problem> {
        validation::validate_poland_pesel_with_checksum(pesel)
    }

    /// Check if a Poland PESEL is a test/dummy pattern
    #[must_use]
    pub fn is_test_poland_pesel(&self, pesel: &str) -> bool {
        validation::is_test_poland_pesel(pesel)
    }
}
