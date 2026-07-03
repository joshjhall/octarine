//! Vehicle ID (VIN) methods.

use super::*;

impl GovernmentBuilder {
    /// Check if value is a vehicle ID (VIN)
    #[must_use]
    pub fn is_vehicle_id(&self, value: &str) -> bool {
        self.inner.is_vehicle_id(value)
    }

    /// Find all vehicle IDs in text
    #[must_use]
    pub fn find_vehicle_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_vehicle_ids_in_text(text)
    }

    /// Validate VIN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the VIN format is invalid
    pub fn validate_vin(&self, vin: &str) -> Result<(), Problem> {
        self.inner.validate_vin(vin)
    }

    /// Validate VIN with checksum verification
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the VIN format is invalid or checksum fails
    pub fn validate_vin_with_checksum(&self, vin: &str) -> Result<(), Problem> {
        self.inner.validate_vin_with_checksum(vin)
    }

    /// Redact a vehicle ID with explicit strategy
    #[must_use]
    pub fn redact_vehicle_id_with_strategy(
        &self,
        vehicle_id: &str,
        strategy: VehicleIdRedactionStrategy,
    ) -> String {
        self.inner
            .redact_vehicle_id_with_strategy(vehicle_id, strategy)
    }

    /// Redact all vehicle IDs in text with explicit strategy
    #[must_use]
    pub fn redact_vehicle_ids_in_text_with_strategy(
        &self,
        text: &str,
        strategy: VehicleIdRedactionStrategy,
    ) -> String {
        self.inner
            .redact_vehicle_ids_in_text_with_strategy(text, strategy)
    }

    /// Normalize a VIN (uppercase)
    #[must_use]
    pub fn normalize_vin(&self, vin: &str) -> String {
        self.inner.normalize_vin(vin)
    }

    /// Convert VIN to display format with spaces
    #[must_use]
    pub fn to_vin_display(&self, vin: &str) -> String {
        self.inner.to_vin_display(vin)
    }

    /// Sanitize a VIN (normalize + validate)
    pub fn sanitize_vin(&self, vin: &str) -> Result<String, Problem> {
        self.inner.sanitize_vin(vin)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // "1HGBH41JXMN109186" is the canonical valid VIN (17 chars, correct
    // ISO 3779 check digit 'X') used throughout the primitive tests.
    const VALID_VIN: &str = "1HGBH41JXMN109186";

    #[test]
    fn test_is_vehicle_id() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_vehicle_id(VALID_VIN));
        assert!(!b.is_vehicle_id("too-short"));
    }

    #[test]
    fn test_find_vehicle_ids_in_text() {
        let b = GovernmentBuilder::silent();
        let matches = b.find_vehicle_ids_in_text("VIN 1HGBH41JXMN109186 registered");
        assert!(!matches.is_empty());
        assert!(b.find_vehicle_ids_in_text("no vin here").is_empty());
    }

    #[test]
    fn test_validate_vin() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_vin(VALID_VIN).is_ok());
        // Contains 'I', 'O', 'Q' which are prohibited in VINs.
        assert!(b.validate_vin("1HGBH41JXMN10918I").is_err());
    }

    #[test]
    fn test_validate_vin_with_checksum() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_vin_with_checksum(VALID_VIN).is_ok());
        // Flip the check digit (position 9) so the ISO 3779 checksum fails.
        assert!(b.validate_vin_with_checksum("1HGBH41J1MN109186").is_err());
    }

    #[test]
    fn test_redact_vehicle_id_with_strategy() {
        let b = GovernmentBuilder::silent();
        assert_eq!(
            b.redact_vehicle_id_with_strategy(VALID_VIN, VehicleIdRedactionStrategy::Token),
            "[VEHICLE_ID]"
        );
        assert_eq!(
            b.redact_vehicle_id_with_strategy(VALID_VIN, VehicleIdRedactionStrategy::ShowWmi),
            "1HG**************"
        );
    }

    #[test]
    fn test_redact_vehicle_ids_in_text_with_strategy() {
        let b = GovernmentBuilder::silent();
        let out = b.redact_vehicle_ids_in_text_with_strategy(
            "VIN 1HGBH41JXMN109186",
            VehicleIdRedactionStrategy::Token,
        );
        assert!(out.contains("[VEHICLE_ID]"));
        assert!(!out.contains("1HGBH41JXMN109186"));
    }

    #[test]
    fn test_normalize_and_display_vin() {
        let b = GovernmentBuilder::silent();
        assert_eq!(b.normalize_vin("1hgbh41jxmn109186"), VALID_VIN);
        assert_eq!(b.to_vin_display(VALID_VIN), "1HG BH41JX MN109186");
    }

    #[test]
    fn test_sanitize_vin() {
        let b = GovernmentBuilder::silent();
        assert_eq!(
            b.sanitize_vin("1hgbh41jxmn109186").expect("valid"),
            VALID_VIN
        );
        assert!(b.sanitize_vin("too-short").is_err());
    }
}
