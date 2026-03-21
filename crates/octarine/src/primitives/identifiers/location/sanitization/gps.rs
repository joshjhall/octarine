//! GPS coordinate sanitization
//!
//! Redacts and masks GPS coordinates with domain-specific redaction strategies.

use super::super::conversion;
use super::super::detection;
use super::super::redaction::GpsRedactionStrategy;
use crate::primitives::Problem;
use crate::primitives::data::tokens::RedactionTokenCore;

// ============================================================================
// GPS Coordinate Redaction
// ============================================================================

/// Redact GPS coordinate with explicit strategy
///
/// Provides type-safe GPS redaction with privacy-aware precision levels.
/// Validates format using detection layer before redaction.
///
/// # Arguments
///
/// * `coord` - GPS coordinate to redact
/// * `strategy` - GPS-specific redaction strategy (precision levels or token)
///
/// # Returns
///
/// Redacted GPS coordinate according to strategy:
/// - **None**: Returns coord as-is (dev/qa only)
/// - **CityLevel**: `"40.7, -74.0"` (±111km accuracy)
/// - **NeighborhoodLevel**: `"40.71, -74.01"` (±1.1km accuracy)
/// - **StreetLevel**: `"40.713, -74.006"` (±110m accuracy)
/// - **BuildingLevel**: `"40.7128, -74.0060"` (±11m accuracy)
/// - **Token**: `"[GPS]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"*****************"` (length-preserving)
/// - **Hashes**: `"#################"` (length-preserving)
///
/// # Security
///
/// Invalid coordinates return `[GPS]` token to avoid leaking partial information.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::sanitization::*;
/// use crate::primitives::identifiers::location::redaction::GpsRedactionStrategy;
///
/// let gps = "40.7128, -74.0060";
///
/// // City-level precision (GDPR compliant for analytics)
/// assert_eq!(
///     redact_gps_coordinate_with_strategy(gps, GpsRedactionStrategy::CityLevel),
///     "40.7, -74.0"
/// );
///
/// // Complete token redaction (recommended default)
/// assert_eq!(
///     redact_gps_coordinate_with_strategy(gps, GpsRedactionStrategy::Token),
///     "[GPS]"
/// );
///
/// // Invalid coordinate - always fully redacted
/// assert_eq!(
///     redact_gps_coordinate_with_strategy("invalid", GpsRedactionStrategy::CityLevel),
///     "[GPS]"
/// );
/// ```
#[must_use]
pub fn redact_gps_coordinate_with_strategy(coord: &str, strategy: GpsRedactionStrategy) -> String {
    // No redaction - return as-is (dev/qa only)
    if matches!(strategy, GpsRedactionStrategy::Skip) {
        return coord.to_string();
    }

    // Validate format first to prevent information leakage
    if !detection::is_gps_coordinate(coord) {
        return RedactionTokenCore::GpsCoordinate.into();
    }

    match strategy {
        GpsRedactionStrategy::Skip => coord.to_string(), // Already handled above

        // Precision-based redaction
        GpsRedactionStrategy::CityLevel
        | GpsRedactionStrategy::NeighborhoodLevel
        | GpsRedactionStrategy::StreetLevel
        | GpsRedactionStrategy::BuildingLevel => {
            if let Some(decimal_places) = strategy.decimal_places() {
                round_gps_coordinate(coord, decimal_places)
            } else {
                RedactionTokenCore::GpsCoordinate.into()
            }
        }

        GpsRedactionStrategy::Token => RedactionTokenCore::GpsCoordinate.into(),
        GpsRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        GpsRedactionStrategy::Asterisks => "*".repeat(coord.len()),
        GpsRedactionStrategy::Hashes => "#".repeat(coord.len()),
    }
}

/// Round GPS coordinate to specified decimal places
///
/// Helper function for precision-based redaction.
fn round_gps_coordinate(coord: &str, decimal_places: u8) -> String {
    // Try to parse as decimal degrees
    let parts: Vec<&str> = coord.split(',').collect();
    if parts.len() != 2 {
        return RedactionTokenCore::GpsCoordinate.into();
    }

    let lat = parts.first().and_then(|s| s.trim().parse::<f64>().ok());
    let lon = parts.get(1).and_then(|s| s.trim().parse::<f64>().ok());

    match (lat, lon) {
        (Some(lat), Some(lon)) => {
            let factor = 10_f64.powi(i32::from(decimal_places));
            let rounded_lat = (lat * factor).round() / factor;
            let rounded_lon = (lon * factor).round() / factor;
            format!(
                "{:.prec$}, {:.prec$}",
                rounded_lat,
                rounded_lon,
                prec = decimal_places as usize
            )
        }
        _ => RedactionTokenCore::GpsCoordinate.into(),
    }
}

/// Sanitize GPS coordinate strict (normalize format + validate)
///
/// Normalizes GPS coordinate to canonical decimal degrees format and validates
/// range and format. Returns normalized format if valid, error otherwise.
///
/// This combines normalization and validation in one step - the most
/// common pattern for accepting GPS input.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::sanitization;
///
/// // Normalize DMS to decimal degrees
/// let sanitized = sanitization::sanitize_gps_coordinate_strict("40°42'46\"N 74°00'21\"W")?;
/// assert_eq!(sanitized, "40.7128, -74.0060");
///
/// // Already in decimal degrees - validates range
/// let sanitized = sanitization::sanitize_gps_coordinate_strict("40.7128, -74.0060")?;
/// assert_eq!(sanitized, "40.7128, -74.0060");
///
/// // Invalid coordinate (out of range)
/// assert!(sanitization::sanitize_gps_coordinate_strict("91.0, 0.0").is_err());
/// ```
pub fn sanitize_gps_coordinate_strict(coord: &str) -> Result<String, Problem> {
    // Normalize format (convert to decimal degrees, standardize spacing)
    let normalized = conversion::normalize_gps_coordinate(coord)?;

    // Validation happens inside normalize_gps_coordinate via detect_gps_format
    // Additional validation: Check range
    let parts: Vec<&str> = normalized.split(',').collect();
    if parts.len() == 2 {
        let lat = parts.first().and_then(|s| s.trim().parse::<f64>().ok());
        let lon = parts.get(1).and_then(|s| s.trim().parse::<f64>().ok());

        if let (Some(lat), Some(lon)) = (lat, lon) {
            if !(-90.0..=90.0).contains(&lat) {
                return Err(Problem::Validation(
                    "Latitude must be between -90 and 90 degrees".into(),
                ));
            }
            if !(-180.0..=180.0).contains(&lon) {
                return Err(Problem::Validation(
                    "Longitude must be between -180 and 180 degrees".into(),
                ));
            }
        }
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_redact_gps_coordinate_with_strategy_token() {
        assert_eq!(
            redact_gps_coordinate_with_strategy("40.7128, -74.0060", GpsRedactionStrategy::Token),
            "[GPS_COORDINATE]"
        );
    }

    #[test]
    fn test_redact_gps_coordinate_with_strategy_city_level() {
        assert_eq!(
            redact_gps_coordinate_with_strategy(
                "40.7128, -74.0060",
                GpsRedactionStrategy::CityLevel
            ),
            "40.7, -74.0"
        );
    }

    #[test]
    fn test_redact_gps_coordinate_with_strategy_neighborhood_level() {
        assert_eq!(
            redact_gps_coordinate_with_strategy(
                "40.7128, -74.0060",
                GpsRedactionStrategy::NeighborhoodLevel
            ),
            "40.71, -74.01"
        );
    }

    #[test]
    fn test_redact_gps_coordinate_with_strategy_city_level_precision() {
        // City-level (used for HIPAA-compliant anonymization)
        assert_eq!(
            redact_gps_coordinate_with_strategy(
                "40.7128, -74.0060",
                GpsRedactionStrategy::CityLevel
            ),
            "40.7, -74.0"
        );
        // Invalid coordinates return token
        assert_eq!(
            redact_gps_coordinate_with_strategy("invalid", GpsRedactionStrategy::CityLevel),
            "[GPS_COORDINATE]"
        );
    }

    #[test]
    fn test_sanitize_gps_coordinate_strict() {
        // Valid decimal degrees
        let result = sanitize_gps_coordinate_strict("40.7128, -74.0060");
        assert!(result.is_ok());

        // Out of range latitude
        let result = sanitize_gps_coordinate_strict("91.0, 0.0");
        assert!(result.is_err());

        // Out of range longitude
        let result = sanitize_gps_coordinate_strict("0.0, 181.0");
        assert!(result.is_err());
    }
}
