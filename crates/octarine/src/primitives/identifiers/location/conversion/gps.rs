//! GPS coordinate conversion and calculations
//!
//! Provides conversion between GPS coordinate formats and geographic calculations.
//!
//! # Supported Formats
//!
//! - **Decimal Degrees** (DD): 40.7128, -74.0060 (canonical format)
//! - **Degrees Minutes Seconds** (DMS): 40°42'46"N 74°00'21"W
//! - **Degrees Decimal Minutes** (DDM): 40°42.767'N 74°00.36'W

use crate::primitives::Problem;

// ============================================================================
// Types
// ============================================================================

/// GPS coordinate format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpsFormat {
    /// Decimal degrees: 40.7128, -74.0060
    DecimalDegrees,
    /// Degrees minutes seconds: 40°42'46"N 74°00'21"W
    DegreesMinutesSeconds,
    /// Degrees decimal minutes: 40°42.767'N 74°00.36'W
    DegreesDecimalMinutes,
}

// ============================================================================
// GPS Coordinate Normalization
// ============================================================================

/// Normalize GPS coordinate to canonical decimal degrees format
///
/// Converts various GPS coordinate formats to the standard decimal degrees
/// format (latitude, longitude) with consistent spacing and precision.
///
/// # Output Format
///
/// - Format: "latitude, longitude"
/// - Precision: Up to 7 decimal places (±1.1 cm precision)
/// - Range: lat ∈ [-90, 90], lon ∈ [-180, 180]
/// - Example: "40.7128, -74.0060"
///
/// # Supported Input Formats
///
/// - Decimal degrees: "40.7128, -74.0060", "40.7128,-74.0060"
/// - DMS: "40°42'46\"N 74°00'21\"W"
/// - DDM: "40°42.767'N 74°00.36'W"
/// - Labeled: "lat: 40.7128, lon: -74.0060"
///
/// # Errors
///
/// Returns `Problem::validation` if:
/// - Input cannot be parsed as GPS coordinate
/// - Latitude out of range [-90, 90]
/// - Longitude out of range [-180, 180]
pub fn normalize_gps_coordinate(input: &str) -> Result<String, Problem> {
    let trimmed = input.trim();

    // Try to parse as decimal degrees first
    if let Some((lat, lon)) = parse_decimal_degrees(trimmed) {
        return format_decimal_degrees(lat, lon);
    }

    // Try DMS format (Degrees Minutes Seconds)
    if let Some((lat, lon)) = parse_dms_format(trimmed) {
        return format_decimal_degrees(lat, lon);
    }

    // Try DDM format (Degrees Decimal Minutes)
    if let Some((lat, lon)) = parse_ddm_format(trimmed) {
        return format_decimal_degrees(lat, lon);
    }

    Err(Problem::Validation(
        "Cannot parse GPS coordinate format".into(),
    ))
}

/// Detect GPS coordinate format
///
/// Returns the format of a GPS coordinate string, or None if not recognized.
pub fn detect_gps_format(input: &str) -> Option<GpsFormat> {
    let trimmed = input.trim();

    // Check for decimal degrees
    if parse_decimal_degrees(trimmed).is_some() {
        return Some(GpsFormat::DecimalDegrees);
    }

    // Check for DMS (try parsing)
    if parse_dms_format(trimmed).is_some() {
        return Some(GpsFormat::DegreesMinutesSeconds);
    }

    // Check for DDM (try parsing)
    if parse_ddm_format(trimmed).is_some() {
        return Some(GpsFormat::DegreesDecimalMinutes);
    }

    None
}

// ============================================================================
// GPS Distance and Bearing Calculations
// ============================================================================

/// Calculate the great-circle distance between two GPS coordinates using the Haversine formula
///
/// Returns the distance in kilometers between two points on Earth's surface.
///
/// # Arguments
///
/// * `lat1` - Latitude of first point in decimal degrees (-90 to 90)
/// * `lon1` - Longitude of first point in decimal degrees (-180 to 180)
/// * `lat2` - Latitude of second point in decimal degrees (-90 to 90)
/// * `lon2` - Longitude of second point in decimal degrees (-180 to 180)
///
/// # Returns
///
/// Distance in kilometers, or `None` if coordinates are out of range.
pub fn calculate_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> Option<f64> {
    // Validate coordinates
    if !(-90.0..=90.0).contains(&lat1) || !(-90.0..=90.0).contains(&lat2) {
        return None;
    }
    if !(-180.0..=180.0).contains(&lon1) || !(-180.0..=180.0).contains(&lon2) {
        return None;
    }

    // Earth's radius in kilometers
    const EARTH_RADIUS_KM: f64 = 6371.0;

    // Convert degrees to radians
    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let delta_lat = (lat2 - lat1).to_radians();
    let delta_lon = (lon2 - lon1).to_radians();

    // Haversine formula
    let a = (delta_lat / 2.0).sin().powi(2)
        + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    let distance = EARTH_RADIUS_KM * c;

    Some(distance)
}

/// Calculate the initial bearing (forward azimuth) between two GPS coordinates
///
/// Returns the compass bearing in degrees (0-360) from the first point to the second.
///
/// # Returns
///
/// Bearing in degrees (0-360), where:
/// - 0° = North
/// - 90° = East
/// - 180° = South
/// - 270° = West
///
/// Returns `None` if coordinates are out of range.
pub fn calculate_bearing(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> Option<f64> {
    // Validate coordinates
    if !(-90.0..=90.0).contains(&lat1) || !(-90.0..=90.0).contains(&lat2) {
        return None;
    }
    if !(-180.0..=180.0).contains(&lon1) || !(-180.0..=180.0).contains(&lon2) {
        return None;
    }

    // Convert degrees to radians
    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let delta_lon = (lon2 - lon1).to_radians();

    // Calculate bearing
    let y = delta_lon.sin() * lat2_rad.cos();
    let x = lat1_rad.cos() * lat2_rad.sin() - lat1_rad.sin() * lat2_rad.cos() * delta_lon.cos();
    let theta = y.atan2(x);

    // Convert to degrees and normalize to 0-360
    let bearing_degrees = (theta.to_degrees() + 360.0) % 360.0;

    Some(bearing_degrees)
}

/// Calculate the final bearing (arrival bearing) between two GPS coordinates
///
/// Returns the compass bearing in degrees (0-360) when arriving at the second point
/// from the first. This is the reverse bearing from point 2 to point 1, reversed.
pub fn calculate_final_bearing(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> Option<f64> {
    // Final bearing is the reverse bearing from point 2 to point 1, reversed
    let reverse_bearing = calculate_bearing(lat2, lon2, lat1, lon1)?;
    Some((reverse_bearing + 180.0) % 360.0)
}

// ============================================================================
// GPS Display Formatting
// ============================================================================

/// Convert GPS coordinates to DMS (Degrees Minutes Seconds) string
///
/// Converts decimal degrees to the traditional DMS format used in navigation.
///
/// # Returns
///
/// Formatted string like "40°42'46\"N 74°00'21\"W", or None if coordinates are out of range.
pub fn to_dms(lat: f64, lon: f64) -> Option<String> {
    // Validate coordinates
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }

    // Convert latitude
    let lat_dir = if lat >= 0.0 { 'N' } else { 'S' };
    let lat_abs = lat.abs();
    let lat_deg = lat_abs.floor() as i32;
    let lat_min_dec = (lat_abs - lat_deg as f64) * 60.0;
    let lat_min = lat_min_dec.floor() as i32;
    let lat_sec = (lat_min_dec - lat_min as f64) * 60.0;

    // Convert longitude
    let lon_dir = if lon >= 0.0 { 'E' } else { 'W' };
    let lon_abs = lon.abs();
    let lon_deg = lon_abs.floor() as i32;
    let lon_min_dec = (lon_abs - lon_deg as f64) * 60.0;
    let lon_min = lon_min_dec.floor() as i32;
    let lon_sec = (lon_min_dec - lon_min as f64) * 60.0;

    // Format as DMS
    Some(format!(
        "{}°{:02}'{:02}\"{} {}°{:02}'{:02}\"{}",
        lat_deg,
        lat_min,
        lat_sec.round() as i32,
        lat_dir,
        lon_deg,
        lon_min,
        lon_sec.round() as i32,
        lon_dir
    ))
}

/// Convert GPS coordinates to DDM (Degrees Decimal Minutes) string
///
/// Converts decimal degrees to DDM format, which is commonly used in GPS devices.
///
/// # Returns
///
/// Formatted string like "40°42.767'N 74°00.360'W", or None if coordinates are out of range.
pub fn to_ddm(lat: f64, lon: f64) -> Option<String> {
    // Validate coordinates
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }

    // Convert latitude
    let lat_dir = if lat >= 0.0 { 'N' } else { 'S' };
    let lat_abs = lat.abs();
    let lat_deg = lat_abs.floor() as i32;
    let lat_min = (lat_abs - lat_deg as f64) * 60.0;

    // Convert longitude
    let lon_dir = if lon >= 0.0 { 'E' } else { 'W' };
    let lon_abs = lon.abs();
    let lon_deg = lon_abs.floor() as i32;
    let lon_min = (lon_abs - lon_deg as f64) * 60.0;

    // Format as DDM with 3 decimal places for minutes
    Some(format!(
        "{}°{:06.3}'{} {}°{:06.3}'{}",
        lat_deg, lat_min, lat_dir, lon_deg, lon_min, lon_dir
    ))
}

/// Convert GPS coordinates to a specified format
///
/// Converts decimal degrees to the requested GPS format.
pub fn to_gps_format(lat: f64, lon: f64, format: GpsFormat) -> Option<String> {
    match format {
        GpsFormat::DecimalDegrees => format_decimal_degrees(lat, lon).ok(),
        GpsFormat::DegreesMinutesSeconds => to_dms(lat, lon),
        GpsFormat::DegreesDecimalMinutes => to_ddm(lat, lon),
    }
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Parse decimal degrees format: "40.7128, -74.0060"
fn parse_decimal_degrees(input: &str) -> Option<(f64, f64)> {
    // Remove common labels
    let cleaned = input
        .replace("lat:", "")
        .replace("lon:", "")
        .replace("latitude:", "")
        .replace("longitude:", "");

    let parts: Vec<&str> = cleaned.split(',').map(|s| s.trim()).collect();
    if parts.len() != 2 {
        return None;
    }

    let lat = parts.first()?.parse::<f64>().ok()?;
    let lon = parts.get(1)?.parse::<f64>().ok()?;

    // Validate ranges
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }

    Some((lat, lon))
}

/// Parse DMS (Degrees Minutes Seconds) format: "40°42'46"N 74°00'21"W"
pub(crate) fn parse_dms_format(input: &str) -> Option<(f64, f64)> {
    // Try regex pattern for DMS format
    let pattern = regex::Regex::new(
        r#"(\d+)[°\s]+(\d+)['\s]+([0-9.]+)["\s]*([NSEW])\s+(\d+)[°\s]+(\d+)['\s]+([0-9.]+)["\s]*([NSEW])"#
    ).ok()?;

    let caps = pattern.captures(input)?;

    // Parse latitude (first coordinate)
    let lat_deg = caps.get(1)?.as_str().parse::<f64>().ok()?;
    let lat_min = caps.get(2)?.as_str().parse::<f64>().ok()?;
    let lat_sec = caps.get(3)?.as_str().parse::<f64>().ok()?;
    let lat_dir = caps.get(4)?.as_str().chars().next()?;

    // Parse longitude (second coordinate)
    let lon_deg = caps.get(5)?.as_str().parse::<f64>().ok()?;
    let lon_min = caps.get(6)?.as_str().parse::<f64>().ok()?;
    let lon_sec = caps.get(7)?.as_str().parse::<f64>().ok()?;
    let lon_dir = caps.get(8)?.as_str().chars().next()?;

    // Validate directions
    if !matches!(lat_dir, 'N' | 'S') || !matches!(lon_dir, 'E' | 'W') {
        return None;
    }

    // Convert to decimal degrees
    let lat = convert_dms_to_dd(lat_deg, lat_min, lat_sec, lat_dir)?;
    let lon = convert_dms_to_dd(lon_deg, lon_min, lon_sec, lon_dir)?;

    // Validate ranges
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }

    Some((lat, lon))
}

/// Parse DDM (Degrees Decimal Minutes) format: "40°42.767'N 74°00.36'W"
pub(crate) fn parse_ddm_format(input: &str) -> Option<(f64, f64)> {
    // Try regex pattern for DDM format
    let pattern = regex::Regex::new(
        r"(\d+)[°\s]+([0-9.]+)['\s]*([NSEW])\s+(\d+)[°\s]+([0-9.]+)['\s]*([NSEW])",
    )
    .ok()?;

    let caps = pattern.captures(input)?;

    // Parse latitude (first coordinate)
    let lat_deg = caps.get(1)?.as_str().parse::<f64>().ok()?;
    let lat_min = caps.get(2)?.as_str().parse::<f64>().ok()?;
    let lat_dir = caps.get(3)?.as_str().chars().next()?;

    // Parse longitude (second coordinate)
    let lon_deg = caps.get(4)?.as_str().parse::<f64>().ok()?;
    let lon_min = caps.get(5)?.as_str().parse::<f64>().ok()?;
    let lon_dir = caps.get(6)?.as_str().chars().next()?;

    // Validate directions
    if !matches!(lat_dir, 'N' | 'S') || !matches!(lon_dir, 'E' | 'W') {
        return None;
    }

    // Convert to decimal degrees
    let lat = convert_ddm_to_dd(lat_deg, lat_min, lat_dir)?;
    let lon = convert_ddm_to_dd(lon_deg, lon_min, lon_dir)?;

    // Validate ranges
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }

    Some((lat, lon))
}

/// Convert DMS (Degrees Minutes Seconds) to Decimal Degrees
fn convert_dms_to_dd(degrees: f64, minutes: f64, seconds: f64, direction: char) -> Option<f64> {
    // Validate components
    if degrees < 0.0 || !(0.0..60.0).contains(&minutes) || !(0.0..60.0).contains(&seconds) {
        return None;
    }

    // Convert to decimal degrees
    let dd = degrees + (minutes / 60.0) + (seconds / 3600.0);

    // Apply direction (S and W are negative)
    let result = match direction {
        'N' | 'E' => dd,
        'S' | 'W' => -dd,
        _ => return None,
    };

    Some(result)
}

/// Convert DDM (Degrees Decimal Minutes) to Decimal Degrees
fn convert_ddm_to_dd(degrees: f64, decimal_minutes: f64, direction: char) -> Option<f64> {
    // Validate components
    if degrees < 0.0 || !(0.0..60.0).contains(&decimal_minutes) {
        return None;
    }

    // Convert to decimal degrees
    let dd = degrees + (decimal_minutes / 60.0);

    // Apply direction (S and W are negative)
    let result = match direction {
        'N' | 'E' => dd,
        'S' | 'W' => -dd,
        _ => return None,
    };

    Some(result)
}

/// Format decimal degrees with consistent precision
fn format_decimal_degrees(lat: f64, lon: f64) -> Result<String, Problem> {
    // Validate ranges
    if !(-90.0..=90.0).contains(&lat) {
        return Err(Problem::Validation("Latitude out of range".into()));
    }
    if !(-180.0..=180.0).contains(&lon) {
        return Err(Problem::Validation("Longitude out of range".into()));
    }

    // Format with up to 7 decimal places, removing trailing zeros
    let lat_str = format!("{:.7}", lat)
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string();
    let lon_str = format!("{:.7}", lon)
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string();

    Ok(format!("{}, {}", lat_str, lon_str))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    // ===== GPS Coordinate Normalization Tests =====

    #[test]
    fn test_normalize_gps_decimal_degrees() {
        assert_eq!(
            normalize_gps_coordinate("40.7128, -74.0060")
                .expect("GPS normalization should succeed"),
            "40.7128, -74.006"
        );

        assert_eq!(
            normalize_gps_coordinate("40.7128,-74.0060").expect("GPS normalization should succeed"),
            "40.7128, -74.006"
        );

        assert_eq!(
            normalize_gps_coordinate("  40.7128  ,  -74.0060  ")
                .expect("GPS normalization should succeed"),
            "40.7128, -74.006"
        );
    }

    #[test]
    fn test_normalize_gps_precision() {
        assert_eq!(
            normalize_gps_coordinate("40.71280000, -74.00600000")
                .expect("GPS normalization should succeed"),
            "40.7128, -74.006"
        );

        assert_eq!(
            normalize_gps_coordinate("40.7128123, -74.0060456")
                .expect("GPS normalization should succeed"),
            "40.7128123, -74.0060456"
        );
    }

    #[test]
    fn test_normalize_gps_with_labels() {
        assert_eq!(
            normalize_gps_coordinate("lat: 40.7128, lon: -74.0060")
                .expect("GPS normalization should succeed"),
            "40.7128, -74.006"
        );
    }

    #[test]
    fn test_normalize_gps_invalid() {
        assert!(normalize_gps_coordinate("91, 0").is_err());
        assert!(normalize_gps_coordinate("-91, 0").is_err());
        assert!(normalize_gps_coordinate("0, 181").is_err());
        assert!(normalize_gps_coordinate("0, -181").is_err());
        assert!(normalize_gps_coordinate("invalid").is_err());
    }

    #[test]
    fn test_detect_gps_format() {
        assert_eq!(
            detect_gps_format("40.7128, -74.0060"),
            Some(GpsFormat::DecimalDegrees)
        );
        assert_eq!(detect_gps_format("invalid"), None);
    }

    // ===== Distance and Bearing Tests =====

    #[test]
    fn test_calculate_distance_same_point() {
        let distance = calculate_distance(40.7128, -74.0060, 40.7128, -74.0060)
            .expect("Distance calculation should succeed");
        assert!(distance.abs() < 0.001);
    }

    #[test]
    fn test_calculate_distance_new_york_to_los_angeles() {
        let distance = calculate_distance(40.7128, -74.0060, 34.0522, -118.2437)
            .expect("Distance calculation should succeed");
        assert!((distance - 3936.0).abs() < 39.36);
    }

    #[test]
    fn test_calculate_distance_invalid() {
        assert!(calculate_distance(91.0, 0.0, 0.0, 0.0).is_none());
        assert!(calculate_distance(0.0, 181.0, 0.0, 0.0).is_none());
    }

    #[test]
    fn test_calculate_bearing_cardinal() {
        let north = calculate_bearing(0.0, 0.0, 10.0, 0.0).unwrap();
        assert!((north - 0.0).abs() < 0.1);

        let east = calculate_bearing(0.0, 0.0, 0.0, 10.0).unwrap();
        assert!((east - 90.0).abs() < 0.1);

        let south = calculate_bearing(10.0, 0.0, 0.0, 0.0).unwrap();
        assert!((south - 180.0).abs() < 0.1);

        let west = calculate_bearing(0.0, 10.0, 0.0, 0.0).unwrap();
        assert!((west - 270.0).abs() < 0.1);
    }

    // ===== Formatting Tests =====

    #[test]
    fn test_to_dms() {
        let dms = to_dms(40.7128, -74.0060).expect("DMS formatting should succeed");
        assert!(dms.contains('°'));
        assert!(dms.contains('N'));
        assert!(dms.contains('W'));
    }

    #[test]
    fn test_to_ddm() {
        let ddm = to_ddm(40.7128, -74.0060).expect("DDM formatting should succeed");
        assert!(ddm.contains('°'));
        assert!(!ddm.contains('"'));
    }

    #[test]
    fn test_to_gps_format_all_formats() {
        let lat = 51.5074;
        let lon = -0.1278;
        assert!(to_gps_format(lat, lon, GpsFormat::DecimalDegrees).is_some());
        assert!(to_gps_format(lat, lon, GpsFormat::DegreesMinutesSeconds).is_some());
        assert!(to_gps_format(lat, lon, GpsFormat::DegreesDecimalMinutes).is_some());
    }

    // ===== DMS/DDM Parsing Tests =====

    #[test]
    fn test_normalize_gps_dms_format() {
        let result = normalize_gps_coordinate("40°42'46\"N 74°00'21\"W")
            .expect("DMS normalization should succeed");
        assert!(result.starts_with("40.71277"));
        assert!(result.contains("-74.00583"));
    }

    #[test]
    fn test_normalize_gps_ddm_format() {
        let result = normalize_gps_coordinate("40°42.767'N 74°00.36'W")
            .expect("DDM normalization should succeed");
        assert!(result.starts_with("40.71278"));
        assert!(result.contains("-74.006"));
    }

    #[test]
    fn test_round_trip_dms() {
        let lat = 40.7128;
        let lon = -74.0060;
        let dms = to_dms(lat, lon).expect("DMS formatting should succeed");
        let parsed = parse_dms_format(&dms).expect("DMS parsing should succeed");
        assert!((parsed.0 - lat).abs() < 0.001);
        assert!((parsed.1 - lon).abs() < 0.001);
    }

    #[test]
    fn test_round_trip_ddm() {
        let lat = 40.7128;
        let lon = -74.0060;
        let ddm = to_ddm(lat, lon).expect("DDM formatting should succeed");
        let parsed = parse_ddm_format(&ddm).expect("DDM parsing should succeed");
        assert!((parsed.0 - lat).abs() < 0.0001);
        assert!((parsed.1 - lon).abs() < 0.0001);
    }
}
