//! Phone number detection functions
//!
//! Detection for international phone numbers.

use super::super::super::common::patterns;

use super::common::{MAX_IDENTIFIER_LENGTH, exceeds_safe_length};

// ============================================================================
// Single-Value Detection
// ============================================================================

/// Check if value is an international phone number
///
/// Detects phone numbers with international prefix (+)
#[must_use]
pub fn is_phone_international(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::PHONE_INTL.is_match(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_phone_international() {
        // With country code
        assert!(is_phone_international("+1 555 123 4567"));
        assert!(is_phone_international("+44 20 7946 0958"));
        assert!(is_phone_international("+81 3 1234 5678"));
        // Without + - not international format
        assert!(!is_phone_international("555-123-4567"));
        assert!(!is_phone_international("not a phone"));
    }
}
