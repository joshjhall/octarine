//! South Korea identifier operations on `GovernmentIdentifierBuilder`.
//!
//! Covers: RRN (citizens, gender 1-4), FRN (foreigners, gender 5-8),
//! Driver License (NN-NN-NNNNNN-NN, regions 11-28), Passport (MRS prefix +
//! 7-8 digits), and BRN (Business Registration Number, weighted mod-10).

use super::*;

impl GovernmentIdentifierBuilder {
    // =========================================================================
    // RRN — Resident Registration Number (citizens)
    // =========================================================================

    /// Check if value matches South Korea RRN format
    #[must_use]
    pub fn is_korea_rrn(&self, value: &str) -> bool {
        detection::is_korea_rrn(value)
    }

    /// Find all Korea RRNs in text
    #[must_use]
    pub fn find_korea_rrns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_korea_rrns_in_text(text)
    }

    /// Validate Korea RRN format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the RRN format is invalid
    pub fn validate_korea_rrn(&self, rrn: &str) -> Result<(), Problem> {
        validation::validate_korea_rrn(rrn)
    }

    /// Validate Korea RRN with weighted checksum verification
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the RRN format is invalid or checksum fails
    pub fn validate_korea_rrn_with_checksum(&self, rrn: &str) -> Result<(), Problem> {
        validation::validate_korea_rrn_with_checksum(rrn)
    }

    /// Check if a Korea RRN is a test/dummy pattern
    #[must_use]
    pub fn is_test_korea_rrn(&self, rrn: &str) -> bool {
        validation::is_test_korea_rrn(rrn)
    }

    // =========================================================================
    // FRN — Foreign Registration Number
    // =========================================================================

    /// Check if value matches South Korea FRN format
    #[must_use]
    pub fn is_korea_frn(&self, value: &str) -> bool {
        detection::is_korea_frn(value)
    }

    /// Find all Korea FRNs in text
    #[must_use]
    pub fn find_korea_frns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_korea_frns_in_text(text)
    }

    /// Validate Korea FRN format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the FRN format is invalid
    pub fn validate_korea_frn(&self, frn: &str) -> Result<(), Problem> {
        validation::validate_korea_frn(frn)
    }

    /// Validate Korea FRN with weighted checksum verification
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the FRN format is invalid or checksum fails
    pub fn validate_korea_frn_with_checksum(&self, frn: &str) -> Result<(), Problem> {
        validation::validate_korea_frn_with_checksum(frn)
    }

    /// Check if a Korea FRN is a test/dummy pattern
    #[must_use]
    pub fn is_test_korea_frn(&self, frn: &str) -> bool {
        validation::is_test_korea_frn(frn)
    }

    // =========================================================================
    // Driver License
    // =========================================================================

    /// Check if value matches South Korea Driver License format
    #[must_use]
    pub fn is_korea_driver_license(&self, value: &str) -> bool {
        detection::is_korea_driver_license(value)
    }

    /// Find all Korea Driver Licenses in text
    #[must_use]
    pub fn find_korea_driver_licenses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_korea_driver_licenses_in_text(text)
    }

    /// Validate Korea Driver License format and region
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the license format or region is invalid
    pub fn validate_korea_driver_license(&self, dl: &str) -> Result<(), Problem> {
        validation::validate_korea_driver_license(dl)
    }

    /// Check if a Korea Driver License is a test/dummy pattern
    #[must_use]
    pub fn is_test_korea_driver_license(&self, dl: &str) -> bool {
        validation::is_test_korea_driver_license(dl)
    }

    // =========================================================================
    // Passport
    // =========================================================================

    /// Check if value matches South Korea Passport format
    #[must_use]
    pub fn is_korea_passport(&self, value: &str) -> bool {
        detection::is_korea_passport(value)
    }

    /// Find all Korea passports in text
    #[must_use]
    pub fn find_korea_passports_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_korea_passports_in_text(text)
    }

    /// Validate Korea Passport format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the passport format is invalid
    pub fn validate_korea_passport(&self, passport: &str) -> Result<(), Problem> {
        validation::validate_korea_passport(passport)
    }

    /// Check if a Korea Passport is a test/dummy pattern
    #[must_use]
    pub fn is_test_korea_passport(&self, passport: &str) -> bool {
        validation::is_test_korea_passport(passport)
    }

    // =========================================================================
    // BRN — Business Registration Number
    // =========================================================================

    /// Check if value matches South Korea BRN format
    #[must_use]
    pub fn is_korea_brn(&self, value: &str) -> bool {
        detection::is_korea_brn(value)
    }

    /// Find all Korea BRNs in text
    #[must_use]
    pub fn find_korea_brns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_korea_brns_in_text(text)
    }

    /// Validate Korea BRN format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the BRN format is invalid
    pub fn validate_korea_brn(&self, brn: &str) -> Result<(), Problem> {
        validation::validate_korea_brn(brn)
    }

    /// Validate Korea BRN with weighted mod-10 checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the BRN format or checksum is invalid
    pub fn validate_korea_brn_with_checksum(&self, brn: &str) -> Result<(), Problem> {
        validation::validate_korea_brn_with_checksum(brn)
    }

    /// Check if a Korea BRN is a test/dummy pattern
    #[must_use]
    pub fn is_test_korea_brn(&self, brn: &str) -> bool {
        validation::is_test_korea_brn(brn)
    }
}
