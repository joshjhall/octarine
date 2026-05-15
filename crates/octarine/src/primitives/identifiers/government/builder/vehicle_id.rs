//! Vehicle Identification Number (VIN) operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches VIN format
    #[must_use]
    pub fn is_vehicle_id(&self, value: &str) -> bool {
        detection::is_vehicle_id(value)
    }

    /// Find all vehicle IDs in text
    #[must_use]
    pub fn find_vehicle_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_vehicle_ids_in_text(text)
    }

    /// Validate VIN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the VIN format is invalid
    pub fn validate_vin(&self, vin: &str) -> Result<(), Problem> {
        validation::validate_vin(vin)
    }

    /// Validate VIN with checksum verification
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the VIN format is invalid or checksum fails
    pub fn validate_vin_with_checksum(&self, vin: &str) -> Result<(), Problem> {
        validation::validate_vin_with_checksum(vin)
    }

    /// Redact vehicle ID with explicit strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, VehicleIdRedactionStrategy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    /// let result = builder.redact_vehicle_id_with_strategy(
    ///     "1HGBH41JXMN109186",
    ///     VehicleIdRedactionStrategy::Token,
    /// );
    /// assert_eq!(result, "[VEHICLE_ID]");
    /// ```
    #[must_use]
    pub fn redact_vehicle_id_with_strategy(
        &self,
        vehicle_id: &str,
        strategy: VehicleIdRedactionStrategy,
    ) -> String {
        sanitization::redact_vehicle_id_with_strategy(vehicle_id, strategy)
    }

    /// Redact all vehicle IDs in text with explicit strategy
    #[must_use]
    pub fn redact_vehicle_ids_in_text_with_strategy(
        &self,
        text: &str,
        strategy: VehicleIdRedactionStrategy,
    ) -> String {
        sanitization::redact_vehicle_ids_in_text_with_strategy(text, strategy).into_owned()
    }

    /// Normalize VIN to uppercase
    #[must_use]
    pub fn normalize_vin(&self, vin: &str) -> String {
        conversion::normalize_vin(vin)
    }

    /// Convert VIN to display format with spaces
    #[must_use]
    pub fn to_vin_display(self, vin: &str) -> String {
        conversion::to_vin_display(vin)
    }

    /// Sanitize VIN strict (normalize + validate with checksum)
    ///
    /// Combines normalization and validation in one step.
    /// Returns normalized VIN if valid, error otherwise.
    pub fn sanitize_vin(&self, vin: &str) -> Result<String, Problem> {
        sanitization::sanitize_vin_strict(vin)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    fn builder() -> GovernmentIdentifierBuilder {
        GovernmentIdentifierBuilder::new()
    }

    #[test]
    fn test_vin_operations() {
        let gov = builder();
        assert!(gov.is_vehicle_id("1HGBH41JXMN109186"));
        assert!(gov.validate_vin("1HGBH41JXMN109186").is_ok());
        assert_eq!(gov.normalize_vin("1hgbh41jxmn109186"), "1HGBH41JXMN109186");
    }
}
