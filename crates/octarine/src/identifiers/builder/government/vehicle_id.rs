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
