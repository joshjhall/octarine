//! Location PII scanning (GPS, address, postal code, named location)
//!
//! Part of the PII scanner domain split (issue #411).

use super::super::super::types::PiiType;
use crate::primitives::identifiers::LocationIdentifierBuilder;

/// Scan for location data (GPS, address, postal code, named location)
pub(super) fn scan_location(text: &str, pii_types: &mut Vec<PiiType>) {
    let location = LocationIdentifierBuilder::new();

    if !location.find_gps_coordinates_in_text(text).is_empty() {
        pii_types.push(PiiType::GpsCoordinates);
    }
    if !location.find_addresses_in_text(text).is_empty() {
        pii_types.push(PiiType::Address);
    }
    if !location.find_postal_codes_in_text(text).is_empty() {
        pii_types.push(PiiType::PostalCode);
    }
    if !location.find_named_locations_in_text(text).is_empty() {
        pii_types.push(PiiType::NamedLocation);
    }
}

/// Coarse pre-filter for the location domain.
pub(super) fn is_location_present(text: &str) -> bool {
    let location = LocationIdentifierBuilder::new();
    location.is_location_identifier(text) || !location.find_all_in_text(text).is_empty()
}
