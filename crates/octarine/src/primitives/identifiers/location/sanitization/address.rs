//! Street address sanitization
//!
//! Redacts and masks street addresses with domain-specific redaction strategies.

use super::super::detection;
use super::super::redaction::AddressRedactionStrategy;
use crate::primitives::Problem;
use crate::primitives::data::tokens::RedactionTokenCore;

// ============================================================================
// Street Address Redaction
// ============================================================================

/// Redact street address with explicit strategy
///
/// Provides type-safe address redaction with options for showing regional context.
/// Validates format using detection layer before redaction.
///
/// # Arguments
///
/// * `address` - Street address to redact
/// * `strategy` - Address-specific redaction strategy
///
/// # Returns
///
/// Redacted address according to strategy:
/// - **None**: Returns address as-is (dev/qa only)
/// - **ShowCityState**: `"[ADDRESS-SanFrancisco-CA]"` (requires parsing)
/// - **ShowState**: `"[ADDRESS-CA]"` (requires parsing)
/// - **ShowCountry**: `"[ADDRESS-US]"` (requires parsing)
/// - **Token**: `"[ADDRESS]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"*****************"` (length-preserving)
/// - **Hashes**: `"#################"` (length-preserving)
///
/// # Regional Redaction
///
/// Regional strategies extract geographic context while protecting the specific address:
/// - **ShowCityState**: `[ADDRESS-SanFrancisco-CA]`
/// - **ShowState**: `[ADDRESS-CA]`
/// - **ShowCountry**: `[ADDRESS-US]`
///
/// Address parsing extracts city/state from common US address formats:
/// - "Street, City, State ZIP"
/// - "Street, City State ZIP"
/// - Falls back to `[ADDRESS]` if parsing fails
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::sanitization::*;
/// use crate::primitives::identifiers::location::redaction::AddressRedactionStrategy;
///
/// let addr = "123 Main Street, San Francisco, CA 94102";
///
/// // Regional redaction
/// assert_eq!(
///     redact_street_address_with_strategy(addr, AddressRedactionStrategy::ShowCityState),
///     "[ADDRESS-SanFrancisco-CA]"
/// );
///
/// assert_eq!(
///     redact_street_address_with_strategy(addr, AddressRedactionStrategy::ShowState),
///     "[ADDRESS-CA]"
/// );
///
/// // Complete token redaction
/// assert_eq!(
///     redact_street_address_with_strategy(addr, AddressRedactionStrategy::Token),
///     "[ADDRESS]"
/// );
/// ```
#[must_use]
pub fn redact_street_address_with_strategy(
    address: &str,
    strategy: AddressRedactionStrategy,
) -> String {
    // No redaction - return as-is (dev/qa only)
    if matches!(strategy, AddressRedactionStrategy::Skip) {
        return address.to_string();
    }

    // Validate format first
    if !detection::is_street_address(address) {
        return RedactionTokenCore::Address.into();
    }

    match strategy {
        AddressRedactionStrategy::Skip => address.to_string(),

        AddressRedactionStrategy::ShowCityState => {
            if let Some((city, state)) = extract_city_state(address) {
                format!("[ADDRESS-{}-{}]", sanitize_for_token(&city), state)
            } else {
                RedactionTokenCore::Address.into()
            }
        }

        AddressRedactionStrategy::ShowState => {
            if let Some(state) = extract_state(address) {
                format!("[ADDRESS-{}]", state)
            } else {
                RedactionTokenCore::Address.into()
            }
        }

        AddressRedactionStrategy::ShowCountry => {
            // US addresses (default assumption for detected addresses)
            "[ADDRESS-US]".to_string()
        }

        AddressRedactionStrategy::Token => RedactionTokenCore::Address.into(),
        AddressRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        AddressRedactionStrategy::Asterisks => "*".repeat(address.len()),
        AddressRedactionStrategy::Hashes => "#".repeat(address.len()),
    }
}

/// Extract state code from US address
///
/// Looks for 2-letter state code in common address formats.
pub(super) fn extract_state(address: &str) -> Option<String> {
    // Match patterns like ", CA 94102" or ", CA" or " CA " near end
    let state_pattern = regex::Regex::new(r"[,\s]([A-Z]{2})[\s\d-]*$").ok()?;
    state_pattern
        .captures(address)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

/// Extract city and state from US address
///
/// Looks for patterns like "City, State ZIP" or "City State ZIP".
pub(super) fn extract_city_state(address: &str) -> Option<(String, String)> {
    // Match patterns like "San Francisco, CA" or "New York, NY 10001"
    let pattern = regex::Regex::new(r",\s*([A-Za-z\s]+),\s*([A-Z]{2})[\s\d-]*$").ok()?;

    if let Some(caps) = pattern.captures(address) {
        let city = caps.get(1)?.as_str().trim().to_string();
        let state = caps.get(2)?.as_str().to_string();
        return Some((city, state));
    }

    // Try alternative pattern: "City State ZIP" (no comma before state)
    let alt_pattern = regex::Regex::new(r",\s*([A-Za-z\s]+)\s+([A-Z]{2})[\s\d-]*$").ok()?;

    if let Some(caps) = alt_pattern.captures(address) {
        let city = caps.get(1)?.as_str().trim().to_string();
        let state = caps.get(2)?.as_str().to_string();
        return Some((city, state));
    }

    None
}

/// Sanitize city name for use in token
///
/// Removes spaces and special characters for clean token format.
fn sanitize_for_token(text: &str) -> String {
    text.chars().filter(|c| c.is_alphanumeric()).collect()
}

/// Sanitize street address strict (normalize format + validate)
///
/// Normalizes street address casing and spacing, and validates format.
/// Returns normalized address if valid, error otherwise.
///
/// # Note
///
/// Current implementation validates format but does not normalize casing/spacing
/// as address normalization is complex and varies by country.
/// Future enhancement: Implement full address normalization.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::sanitization;
///
/// // Validate address
/// let sanitized = sanitization::sanitize_street_address_strict("123 Main Street")?;
/// assert_eq!(sanitized, "123 Main Street");
///
/// // Invalid address
/// assert!(sanitization::sanitize_street_address_strict("").is_err());
/// ```
pub fn sanitize_street_address_strict(address: &str) -> Result<String, Problem> {
    let trimmed = address.trim();

    // Validate format using detection
    if !detection::is_street_address(trimmed) {
        return Err(Problem::Validation("Invalid street address format".into()));
    }

    // TODO: Implement full address normalization (casing, spacing, abbreviations)
    // For now, just return trimmed
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_redact_street_address_with_strategy_token() {
        assert_eq!(
            redact_street_address_with_strategy("123 Main Street", AddressRedactionStrategy::Token),
            "[ADDRESS]"
        );
    }

    #[test]
    fn test_redact_street_address_with_strategy_show_state() {
        assert_eq!(
            redact_street_address_with_strategy(
                "123 Main St, San Francisco, CA 94102",
                AddressRedactionStrategy::ShowState
            ),
            "[ADDRESS-CA]"
        );
        assert_eq!(
            redact_street_address_with_strategy(
                "456 Oak Ave, New York, NY 10001",
                AddressRedactionStrategy::ShowState
            ),
            "[ADDRESS-NY]"
        );
        // Fallback if no state found
        assert_eq!(
            redact_street_address_with_strategy(
                "123 Main Street",
                AddressRedactionStrategy::ShowState
            ),
            "[ADDRESS]"
        );
    }

    #[test]
    fn test_redact_street_address_with_strategy_show_city_state() {
        assert_eq!(
            redact_street_address_with_strategy(
                "123 Main St, San Francisco, CA 94102",
                AddressRedactionStrategy::ShowCityState
            ),
            "[ADDRESS-SanFrancisco-CA]"
        );
        assert_eq!(
            redact_street_address_with_strategy(
                "456 Oak Ave, New York, NY 10001",
                AddressRedactionStrategy::ShowCityState
            ),
            "[ADDRESS-NewYork-NY]"
        );
        // Fallback if parsing fails
        assert_eq!(
            redact_street_address_with_strategy(
                "123 Main Street",
                AddressRedactionStrategy::ShowCityState
            ),
            "[ADDRESS]"
        );
    }

    #[test]
    fn test_redact_street_address_with_strategy_show_country() {
        assert_eq!(
            redact_street_address_with_strategy(
                "123 Main St, San Francisco, CA 94102",
                AddressRedactionStrategy::ShowCountry
            ),
            "[ADDRESS-US]"
        );
    }

    #[test]
    fn test_extract_state() {
        assert_eq!(
            extract_state("123 Main St, San Francisco, CA 94102"),
            Some("CA".to_string())
        );
        assert_eq!(
            extract_state("456 Oak Ave, New York, NY 10001"),
            Some("NY".to_string())
        );
        assert_eq!(
            extract_state("789 Elm St, Austin, TX"),
            Some("TX".to_string())
        );
        assert_eq!(extract_state("123 Main Street"), None);
    }

    #[test]
    fn test_extract_city_state() {
        assert_eq!(
            extract_city_state("123 Main St, San Francisco, CA 94102"),
            Some(("San Francisco".to_string(), "CA".to_string()))
        );
        assert_eq!(
            extract_city_state("456 Oak Ave, New York, NY 10001"),
            Some(("New York".to_string(), "NY".to_string()))
        );
        // Alternative format (no comma before state)
        assert_eq!(
            extract_city_state("789 Elm St, Austin TX 78701"),
            Some(("Austin".to_string(), "TX".to_string()))
        );
        assert_eq!(extract_city_state("123 Main Street"), None);
    }

    #[test]
    fn test_sanitize_street_address_strict() {
        // Valid address
        let result = sanitize_street_address_strict("123 Main Street");
        assert!(result.is_ok());

        // Empty address
        let result = sanitize_street_address_strict("");
        assert!(result.is_err());
    }
}
