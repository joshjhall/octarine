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

    // ---- Italy Partita IVA (VAT) ---------------------------------------------

    /// Check if value matches Italy VAT format
    #[must_use]
    pub fn is_italy_vat(&self, value: &str) -> bool {
        detection::is_italy_vat(value)
    }

    /// Find all Italy VAT patterns in text
    #[must_use]
    pub fn find_italy_vats_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_italy_vats_in_text(text)
    }

    /// Validate Italy VAT format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the VAT format is invalid
    pub fn validate_italy_vat(&self, vat: &str) -> Result<(), Problem> {
        validation::validate_italy_vat(vat)
    }

    /// Validate Italy VAT with mod-10 Luhn-style checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the VAT format is invalid or checksum fails
    pub fn validate_italy_vat_with_checksum(&self, vat: &str) -> Result<(), Problem> {
        validation::validate_italy_vat_with_checksum(vat)
    }

    /// Check if an Italy VAT is a test/dummy pattern
    #[must_use]
    pub fn is_test_italy_vat(&self, vat: &str) -> bool {
        validation::is_test_italy_vat(vat)
    }

    // ---- Italy Passport ------------------------------------------------------

    /// Check if value matches Italy passport format
    #[must_use]
    pub fn is_italy_passport(&self, value: &str) -> bool {
        detection::is_italy_passport(value)
    }

    /// Find all Italy passport patterns in text
    #[must_use]
    pub fn find_italy_passports_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_italy_passports_in_text(text)
    }

    /// Validate Italy passport format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the passport format is invalid
    pub fn validate_italy_passport(&self, passport: &str) -> Result<(), Problem> {
        validation::validate_italy_passport(passport)
    }

    /// Check if an Italy passport is a test/dummy pattern
    #[must_use]
    pub fn is_test_italy_passport(&self, passport: &str) -> bool {
        validation::is_test_italy_passport(passport)
    }

    // ---- Italy Identity Card (Carta d'Identità) ------------------------------

    /// Check if value matches any Italy identity card format
    #[must_use]
    pub fn is_italy_identity_card(&self, value: &str) -> bool {
        detection::is_italy_identity_card(value)
    }

    /// Find all Italy identity card patterns in text
    #[must_use]
    pub fn find_italy_identity_cards_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_italy_identity_cards_in_text(text)
    }

    /// Validate Italy identity card format (paper, CIE 2.0, or CIE 3.0)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the identity card matches none of the three
    /// supported layouts.
    pub fn validate_italy_identity_card(&self, card: &str) -> Result<(), Problem> {
        validation::validate_italy_identity_card(card)
    }

    /// Check if an Italy identity card is a test/dummy pattern
    #[must_use]
    pub fn is_test_italy_identity_card(&self, card: &str) -> bool {
        validation::is_test_italy_identity_card(card)
    }

    // ---- Italy Driver License (Patente di Guida) -----------------------------

    /// Check if value matches Italy driver license format
    #[must_use]
    pub fn is_italy_driver_license(&self, value: &str) -> bool {
        detection::is_italy_driver_license(value)
    }

    /// Find all Italy driver license patterns in text
    #[must_use]
    pub fn find_italy_driver_licenses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_italy_driver_licenses_in_text(text)
    }

    /// Validate Italy driver license format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the format matches neither the standard
    /// `[A-Z]{2}\d{7}[A-Z]` form nor the legacy `U1` Carta Conducente
    /// form.
    pub fn validate_italy_driver_license(&self, license: &str) -> Result<(), Problem> {
        validation::validate_italy_driver_license(license)
    }

    /// Check if an Italy driver license is a test/dummy pattern
    #[must_use]
    pub fn is_test_italy_driver_license(&self, license: &str) -> bool {
        validation::is_test_italy_driver_license(license)
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
