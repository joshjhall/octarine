//! India identifier operations on `GovernmentIdentifierBuilder`.
//!
//! Covers Aadhaar, PAN, GSTIN, vehicle registration, Voter ID (EPIC), and passport.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches India Aadhaar format
    #[must_use]
    pub fn is_india_aadhaar(&self, value: &str) -> bool {
        detection::is_india_aadhaar(value)
    }

    /// Find all India Aadhaar numbers in text
    #[must_use]
    pub fn find_india_aadhaars_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_india_aadhaars_in_text(text)
    }

    /// Validate India Aadhaar format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the Aadhaar format is invalid
    pub fn validate_india_aadhaar(&self, aadhaar: &str) -> Result<(), Problem> {
        validation::validate_india_aadhaar(aadhaar)
    }

    /// Validate India Aadhaar with Verhoeff checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the Aadhaar format is invalid or checksum fails
    pub fn validate_india_aadhaar_with_checksum(&self, aadhaar: &str) -> Result<(), Problem> {
        validation::validate_india_aadhaar_with_checksum(aadhaar)
    }

    /// Check if an India Aadhaar is a test/dummy pattern
    #[must_use]
    pub fn is_test_india_aadhaar(&self, aadhaar: &str) -> bool {
        validation::is_test_india_aadhaar(aadhaar)
    }

    /// Check if value matches India PAN format
    #[must_use]
    pub fn is_india_pan(&self, value: &str) -> bool {
        detection::is_india_pan(value)
    }

    /// Find all India PAN numbers in text
    #[must_use]
    pub fn find_india_pans_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_india_pans_in_text(text)
    }

    /// Validate India PAN format and holder type
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the PAN format or holder type is invalid
    pub fn validate_india_pan(&self, pan: &str) -> Result<(), Problem> {
        validation::validate_india_pan(pan)
    }

    /// Check if an India PAN is a test/dummy pattern
    #[must_use]
    pub fn is_test_india_pan(&self, pan: &str) -> bool {
        validation::is_test_india_pan(pan)
    }

    /// Check if value matches India GSTIN format
    #[must_use]
    pub fn is_india_gstin(&self, value: &str) -> bool {
        detection::is_india_gstin(value)
    }

    /// Find all India GSTINs in text
    #[must_use]
    pub fn find_india_gstins_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_india_gstins_in_text(text)
    }

    /// Validate India GSTIN format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the GSTIN format is invalid
    pub fn validate_india_gstin(&self, gstin: &str) -> Result<(), Problem> {
        validation::validate_india_gstin(gstin)
    }

    /// Validate India GSTIN with MOD-36 checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the GSTIN format is invalid or checksum fails
    pub fn validate_india_gstin_with_checksum(&self, gstin: &str) -> Result<(), Problem> {
        validation::validate_india_gstin_with_checksum(gstin)
    }

    /// Check if an India GSTIN is a test/dummy pattern
    #[must_use]
    pub fn is_test_india_gstin(&self, gstin: &str) -> bool {
        validation::is_test_india_gstin(gstin)
    }

    /// Check if value matches India vehicle registration format
    #[must_use]
    pub fn is_india_vehicle_registration(&self, value: &str) -> bool {
        detection::is_india_vehicle_registration(value)
    }

    /// Find all India vehicle registrations in text
    #[must_use]
    pub fn find_india_vehicle_registrations_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_india_vehicle_registrations_in_text(text)
    }

    /// Validate India vehicle registration format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the vehicle registration format is invalid
    pub fn validate_india_vehicle_registration(&self, reg: &str) -> Result<(), Problem> {
        validation::validate_india_vehicle_registration(reg)
    }

    /// Check if a vehicle registration is a test/dummy pattern
    #[must_use]
    pub fn is_test_india_vehicle_registration(&self, reg: &str) -> bool {
        validation::is_test_india_vehicle_registration(reg)
    }

    /// Check if value matches India Voter ID format
    #[must_use]
    pub fn is_india_voter_id(&self, value: &str) -> bool {
        detection::is_india_voter_id(value)
    }

    /// Find all India Voter IDs in text
    #[must_use]
    pub fn find_india_voter_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_india_voter_ids_in_text(text)
    }

    /// Validate India Voter ID format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the Voter ID format is invalid
    pub fn validate_india_voter_id(&self, voter_id: &str) -> Result<(), Problem> {
        validation::validate_india_voter_id(voter_id)
    }

    /// Check if a Voter ID is a test/dummy pattern
    #[must_use]
    pub fn is_test_india_voter_id(&self, voter_id: &str) -> bool {
        validation::is_test_india_voter_id(voter_id)
    }

    /// Check if value matches Indian passport format (P/S/D + 7 digits)
    #[must_use]
    pub fn is_india_passport(&self, value: &str) -> bool {
        detection::is_india_passport(value)
    }

    /// Find all Indian passport numbers in text (label-gated)
    #[must_use]
    pub fn find_india_passports_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_india_passports_in_text(text)
    }

    /// Validate Indian passport format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the passport format or type indicator is invalid
    pub fn validate_india_passport(&self, passport: &str) -> Result<(), Problem> {
        validation::validate_india_passport(passport)
    }

    /// Check if an Indian passport is a test/dummy pattern
    #[must_use]
    pub fn is_test_india_passport(&self, passport: &str) -> bool {
        validation::is_test_india_passport(passport)
    }
}
