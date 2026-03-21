//! Text redaction (find and replace in documents)
//!
//! Functions for redacting location identifiers within text content.

use super::super::detection;
use super::super::redaction::TextRedactionPolicy;
use std::borrow::Cow;

use super::address::redact_street_address_with_strategy;
use super::gps::redact_gps_coordinate_with_strategy;
use super::postal::redact_postal_code_with_strategy;

// ============================================================================
// Text Redaction Functions
// ============================================================================

/// Redact all GPS coordinates in text with explicit strategy
///
/// Maps the policy to appropriate GPS strategy:
/// - `Partial` → `CityLevel` (40.7, -74.0)
/// - `Complete` → `Token` ([GPS])
/// - `Anonymous` → `Anonymous` ([REDACTED])
/// - `None` → No redaction
///
/// # Arguments
///
/// * `text` - Text to scan for GPS coordinates
/// * `policy` - Generic redaction policy for text scanning
///
/// # Returns
///
/// `Cow<'_, str>` - Borrowed if no GPS found, owned if replacements made.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::sanitization::*;
/// use crate::primitives::identifiers::location::redaction::TextRedactionPolicy;
///
/// let text = "Location: 40.7128, -74.0060";
///
/// // Complete redaction
/// assert_eq!(
///     redact_gps_coordinates_in_text_with_strategy(text, TextRedactionPolicy::Complete),
///     "Location: [GPS]"
/// );
///
/// // Partial redaction (city-level)
/// assert_eq!(
///     redact_gps_coordinates_in_text_with_strategy(text, TextRedactionPolicy::Partial),
///     "Location: 40.7, -74.0"
/// );
/// ```
#[must_use]
pub fn redact_gps_coordinates_in_text_with_strategy(
    text: &str,
    policy: TextRedactionPolicy,
) -> Cow<'_, str> {
    let matches = detection::find_gps_coordinates_in_text(text);

    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let gps_strategy = policy.to_gps_strategy();
    let mut result = text.to_string();

    // Process in reverse to maintain correct positions
    for m in matches.iter().rev() {
        let coord = &text[m.start..m.end];
        let redacted = redact_gps_coordinate_with_strategy(coord, gps_strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all street addresses in text with explicit strategy
///
/// Maps the policy to appropriate address strategy:
/// - `Partial` → `ShowState` ([ADDRESS-CA])
/// - `Complete` → `Token` ([ADDRESS])
/// - `Anonymous` → `Anonymous` ([REDACTED])
/// - `None` → No redaction
///
/// # Arguments
///
/// * `text` - Text to scan for addresses
/// * `policy` - Generic redaction policy for text scanning
///
/// # Returns
///
/// `Cow<'_, str>` - Borrowed if no addresses found, owned if replacements made.
#[must_use]
pub fn redact_addresses_in_text_with_strategy(
    text: &str,
    policy: TextRedactionPolicy,
) -> Cow<'_, str> {
    let matches = detection::find_addresses_in_text(text);

    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let address_strategy = policy.to_address_strategy();
    let mut result = text.to_string();

    // Process in reverse to maintain correct positions
    for m in matches.iter().rev() {
        let address = &text[m.start..m.end];
        let redacted = redact_street_address_with_strategy(address, address_strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all postal codes in text with explicit strategy
///
/// Maps the policy to appropriate postal code strategy:
/// - `Partial` → `ShowPrefix` (100**)
/// - `Complete` → `Token` ([POSTAL_CODE])
/// - `Anonymous` → `Anonymous` ([REDACTED])
/// - `None` → No redaction
///
/// # Arguments
///
/// * `text` - Text to scan for postal codes
/// * `policy` - Generic redaction policy for text scanning
///
/// # Returns
///
/// `Cow<'_, str>` - Borrowed if no postal codes found, owned if replacements made.
#[must_use]
pub fn redact_postal_codes_in_text_with_strategy(
    text: &str,
    policy: TextRedactionPolicy,
) -> Cow<'_, str> {
    let matches = detection::find_postal_codes_in_text(text);

    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let postal_strategy = policy.to_postal_code_strategy();
    let mut result = text.to_string();

    // Process in reverse to maintain correct positions
    for m in matches.iter().rev() {
        let code = &text[m.start..m.end];
        let redacted = redact_postal_code_with_strategy(code, postal_strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

/// Redact all location data with explicit strategy
///
/// Comprehensive redaction for GPS coordinates, addresses, and postal codes using
/// consistent policy mappings:
/// - `Partial` → CityLevel (GPS), ShowState (address), ShowPrefix (postal)
/// - `Complete` → Type-specific tokens ([GPS], [ADDRESS], [POSTAL_CODE])
/// - `Anonymous` → Generic [REDACTED] for all types
/// - `None` → No redaction
///
/// # Arguments
///
/// * `text` - Text to scan for all location identifiers
/// * `policy` - Generic redaction policy to apply consistently across all identifier types
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::sanitization::*;
/// use crate::primitives::identifiers::location::redaction::TextRedactionPolicy;
///
/// let text = "Meet at 123 Main St, NY 10001 (40.7128, -74.0060)";
///
/// let result = redact_all_location_data_with_strategy(text, TextRedactionPolicy::Complete);
/// // Result: "Meet at [ADDRESS] [POSTAL_CODE] [GPS]"
///
/// let result = redact_all_location_data_with_strategy(text, TextRedactionPolicy::Partial);
/// // Result: "Meet at [ADDRESS] 100** (40.7, -74.0)"
/// ```
#[must_use]
pub fn redact_all_location_data_with_strategy(text: &str, policy: TextRedactionPolicy) -> String {
    // Order matters: redact addresses before postal codes to avoid double-replacement
    let result = redact_gps_coordinates_in_text_with_strategy(text, policy);
    let result = redact_addresses_in_text_with_strategy(&result, policy);
    let result = redact_postal_codes_in_text_with_strategy(&result, policy);

    result.into_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_redact_gps_coordinates_in_text_with_strategy() {
        let text = "Location: 40.7128, -74.0060";
        let result =
            redact_gps_coordinates_in_text_with_strategy(text, TextRedactionPolicy::Complete);
        assert_eq!(result, "Location: [GPS_COORDINATE]");
    }

    #[test]
    fn test_redact_gps_coordinates_in_text_with_strategy_partial() {
        let text = "Location: 40.7128, -74.0060";
        let result =
            redact_gps_coordinates_in_text_with_strategy(text, TextRedactionPolicy::Partial);
        assert_eq!(result, "Location: 40.7, -74.0");
    }

    #[test]
    fn test_redact_addresses_in_text_with_strategy() {
        let text = "Ship to: 123 Main Street";
        let result = redact_addresses_in_text_with_strategy(text, TextRedactionPolicy::Complete);
        assert_eq!(result, "Ship to: [ADDRESS]");
    }

    #[test]
    fn test_redact_postal_codes_in_text_with_strategy() {
        let text = "ZIP: 10001";
        let result = redact_postal_codes_in_text_with_strategy(text, TextRedactionPolicy::Complete);
        assert_eq!(result, "ZIP: [POSTAL_CODE]");
    }

    #[test]
    fn test_redact_postal_codes_in_text_with_strategy_partial() {
        let text = "ZIP: 10001";
        let result = redact_postal_codes_in_text_with_strategy(text, TextRedactionPolicy::Partial);
        assert_eq!(result, "ZIP: 100**");
    }

    #[test]
    fn test_redact_all_location_data_with_strategy() {
        let text = "Meet at 123 Main St, ZIP 10001 (40.7128, -74.0060)";
        let result = redact_all_location_data_with_strategy(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[ADDRESS]"));
        assert!(result.contains("[POSTAL_CODE]"));
        assert!(result.contains("[GPS_COORDINATE]"));
    }

    #[test]
    fn test_no_redaction_in_clean_text() {
        let text = "This text contains no location data";
        let result = redact_all_location_data_with_strategy(text, TextRedactionPolicy::Complete);
        assert_eq!(result, text);
    }

    #[test]
    fn test_cow_optimization() {
        // Clean text should return borrowed
        let text = "Clean text";
        let result =
            redact_gps_coordinates_in_text_with_strategy(text, TextRedactionPolicy::Complete);
        assert!(matches!(result, Cow::Borrowed(_)));

        // Dirty text should return owned
        let text = "Location: 40.7128, -74.0060";
        let result =
            redact_gps_coordinates_in_text_with_strategy(text, TextRedactionPolicy::Complete);
        assert!(matches!(result, Cow::Owned(_)));
    }
}
