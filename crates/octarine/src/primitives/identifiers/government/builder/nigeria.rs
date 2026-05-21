//! Nigeria identifier operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    // ---- NIN ----------------------------------------------------------------

    /// Check if value matches Nigeria NIN format
    #[must_use]
    pub fn is_nigeria_nin(&self, value: &str) -> bool {
        detection::is_nigeria_nin(value)
    }

    /// Find all Nigeria NINs in text (labeled occurrences only — see pattern docs)
    #[must_use]
    pub fn find_nigeria_nins_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_nigeria_nins_in_text(text)
    }

    /// Validate Nigeria NIN format (no checksum algorithm exists)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NIN format is invalid
    pub fn validate_nigeria_nin(&self, nin: &str) -> Result<(), Problem> {
        validation::validate_nigeria_nin(nin)
    }

    /// Check if a Nigeria NIN is a test/dummy pattern
    #[must_use]
    pub fn is_test_nigeria_nin(&self, nin: &str) -> bool {
        validation::is_test_nigeria_nin(nin)
    }

    // ---- BVN ----------------------------------------------------------------

    /// Check if value matches Nigeria BVN format
    #[must_use]
    pub fn is_nigeria_bvn(&self, value: &str) -> bool {
        detection::is_nigeria_bvn(value)
    }

    /// Find all Nigeria BVNs in text (labeled occurrences only — see pattern docs)
    #[must_use]
    pub fn find_nigeria_bvns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_nigeria_bvns_in_text(text)
    }

    /// Validate Nigeria BVN format (no checksum algorithm exists)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the BVN format is invalid
    pub fn validate_nigeria_bvn(&self, bvn: &str) -> Result<(), Problem> {
        validation::validate_nigeria_bvn(bvn)
    }

    /// Check if a Nigeria BVN is a test/dummy pattern
    #[must_use]
    pub fn is_test_nigeria_bvn(&self, bvn: &str) -> bool {
        validation::is_test_nigeria_bvn(bvn)
    }

    // ---- Vehicle Registration -----------------------------------------------

    /// Check if value matches a Nigerian vehicle registration plate
    #[must_use]
    pub fn is_nigeria_vehicle_registration(&self, value: &str) -> bool {
        detection::is_nigeria_vehicle_registration(value)
    }

    /// Find all Nigerian vehicle registration plates in text
    #[must_use]
    pub fn find_nigeria_vehicle_registrations_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_nigeria_vehicle_registrations_in_text(text)
    }

    /// Validate a Nigerian vehicle registration plate
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the plate format does not match the current
    /// or legacy layout.
    pub fn validate_nigeria_vehicle_registration(&self, reg: &str) -> Result<(), Problem> {
        validation::validate_nigeria_vehicle_registration(reg)
    }

    /// Check if a vehicle registration plate is a test/dummy pattern
    #[must_use]
    pub fn is_test_nigeria_vehicle_registration(&self, reg: &str) -> bool {
        validation::is_test_nigeria_vehicle_registration(reg)
    }
}
