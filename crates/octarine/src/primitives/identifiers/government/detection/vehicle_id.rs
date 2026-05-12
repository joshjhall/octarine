//! VIN and vehicle ID format detection

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length, get_full_match};

/// Check if a value matches VIN format
#[must_use]
pub fn is_vehicle_id(value: &str) -> bool {
    patterns::vehicle_id::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all vehicle ID patterns in text (VIN, license plates)
///
/// Detects:
/// - VIN (Vehicle Identification Number): 17-character regulated format
/// - License plates: Various US formats
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "VIN: 1HGBH41JXMN109186";
/// let matches = detection::find_vehicle_ids_in_text(text);
/// assert_eq!(matches.len(), 1);
/// ```
#[must_use]
pub fn find_vehicle_ids_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::vehicle_id::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::VehicleId,
            ));
        }
    }

    deduplicate_matches(matches)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_vehicle_id() {
        assert!(is_vehicle_id("1HGBH41JXMN109186")); // VIN
        assert!(!is_vehicle_id("invalid"));
    }

    #[test]
    fn test_find_vehicle_ids_in_text() {
        let text = "VIN: 1HGBH41JXMN109186";
        let matches = find_vehicle_ids_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect vehicle ID pattern");
        assert_eq!(first.identifier_type, IdentifierType::VehicleId);
    }

    #[test]
    fn test_empty_input() {
        assert!(!is_vehicle_id(""));
    }
}
