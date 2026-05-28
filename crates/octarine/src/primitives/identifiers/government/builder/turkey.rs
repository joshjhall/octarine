//! Turkey TCKN + license plate operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches Turkey TCKN format
    #[must_use]
    pub fn is_turkey_tckn(&self, value: &str) -> bool {
        detection::is_turkey_tckn(value)
    }

    /// Find all Turkey TCKNs in text (label-anchored only)
    #[must_use]
    pub fn find_turkey_tckns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_turkey_tckns_in_text(text)
    }

    /// Validate Turkey TCKN format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the TCKN format is invalid
    pub fn validate_turkey_tckn(&self, tckn: &str) -> Result<(), Problem> {
        validation::validate_turkey_tckn(tckn)
    }

    /// Validate Turkey TCKN with NVI mod-10 dual-check-digit verification
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the TCKN format or either check digit is invalid
    pub fn validate_turkey_tckn_with_checksum(&self, tckn: &str) -> Result<(), Problem> {
        validation::validate_turkey_tckn_with_checksum(tckn)
    }

    /// Check if a Turkey TCKN is a test/dummy pattern (all-same-digit)
    #[must_use]
    pub fn is_test_turkey_tckn(&self, tckn: &str) -> bool {
        validation::is_test_turkey_tckn(tckn)
    }

    /// Check if value matches Turkey license plate format
    #[must_use]
    pub fn is_turkey_license_plate(&self, value: &str) -> bool {
        detection::is_turkey_license_plate(value)
    }

    /// Find all Turkey license plates in text
    #[must_use]
    pub fn find_turkey_license_plates_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_turkey_license_plates_in_text(text)
    }

    /// Validate Turkey license plate format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the plate format is invalid
    pub fn validate_turkey_license_plate(&self, plate: &str) -> Result<(), Problem> {
        validation::validate_turkey_license_plate(plate)
    }
}
