//! German identifier operations on `GovernmentIdentifierBuilder` —
//! Steuer-IdNr (tax ID), Personalausweis (nPA), Reisepass (passport).

use super::*;

impl GovernmentIdentifierBuilder {
    // ------------------------------------------------------------------
    // Steuer-IdNr — 11 digits, ISO 7064 mod-11,10 + structural rule
    // ------------------------------------------------------------------

    /// Check if value is a valid German Steuer-IdNr
    #[must_use]
    pub fn is_germany_tax_id(&self, value: &str) -> bool {
        detection::is_germany_tax_id(value)
    }

    /// Find all German Steuer-IdNr patterns in text (label-anchored)
    #[must_use]
    pub fn find_germany_tax_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_germany_tax_ids_in_text(text)
    }

    /// Validate German Steuer-IdNr format (structural + checksum rules)
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the value is not a valid Steuer-IdNr.
    pub fn validate_germany_tax_id(&self, value: &str) -> Result<(), Problem> {
        validation::validate_germany_tax_id(value)
    }

    /// Validate German Steuer-IdNr including the ISO 7064 mod-11,10 checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the format, structural rule, or
    /// checksum is invalid.
    pub fn validate_germany_tax_id_with_checksum(&self, value: &str) -> Result<(), Problem> {
        validation::validate_germany_tax_id_with_checksum(value)
    }

    // ------------------------------------------------------------------
    // Personalausweis (nPA) — ICAO Doc 9303 check digit
    // ------------------------------------------------------------------

    /// Check if value is a valid German Personalausweis (nPA) number
    #[must_use]
    pub fn is_germany_id_card(&self, value: &str) -> bool {
        detection::is_germany_id_card(value)
    }

    /// Find all German Personalausweis patterns in text (label-anchored)
    #[must_use]
    pub fn find_germany_id_cards_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_germany_id_cards_in_text(text)
    }

    /// Validate German Personalausweis format
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the value is not a valid nPA number.
    pub fn validate_germany_id_card(&self, value: &str) -> Result<(), Problem> {
        validation::validate_germany_id_card(value)
    }

    /// Validate German Personalausweis including the ICAO Doc 9303 check digit
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the format or check digit is invalid.
    pub fn validate_germany_id_card_with_checksum(&self, value: &str) -> Result<(), Problem> {
        validation::validate_germany_id_card_with_checksum(value)
    }

    // ------------------------------------------------------------------
    // Reisepass (passport) — ICAO Doc 9303 check digit
    // ------------------------------------------------------------------

    /// Check if value is a valid German Reisepass (passport) number
    #[must_use]
    pub fn is_germany_passport(&self, value: &str) -> bool {
        detection::is_germany_passport(value)
    }

    /// Find all German Reisepass patterns in text (label-anchored)
    #[must_use]
    pub fn find_germany_passports_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_germany_passports_in_text(text)
    }

    /// Validate German Reisepass format
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the value is not a valid passport
    /// number.
    pub fn validate_germany_passport(&self, value: &str) -> Result<(), Problem> {
        validation::validate_germany_passport(value)
    }

    /// Validate German Reisepass including the ICAO Doc 9303 check digit
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the format or check digit is invalid.
    pub fn validate_germany_passport_with_checksum(&self, value: &str) -> Result<(), Problem> {
        validation::validate_germany_passport_with_checksum(value)
    }
}
