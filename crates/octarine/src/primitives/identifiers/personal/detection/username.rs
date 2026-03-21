//! Username detection
//!
//! Pure detection functions for usernames.

use super::super::super::common::patterns;

// ============================================================================
// Public API
// ============================================================================

/// Check if value is a username
///
/// Uses heuristic-based detection for usernames. Checks for:
/// - Matches username pattern (alphanumeric + underscores/hyphens/dots)
/// - Length between 3-32 characters
/// - Doesn't contain '@' (to avoid emails)
/// - Not all digits (to avoid phone numbers/IDs)
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection;
///
/// assert!(detection::is_username("john_doe"));
/// assert!(detection::is_username("user123"));
/// assert!(detection::is_username("test-user"));
///
/// // Invalid usernames
/// assert!(!detection::is_username("ab"));           // Too short
/// assert!(!detection::is_username("user@email.com")); // Contains @
/// assert!(!detection::is_username("12345"));        // All digits
/// ```
///
/// # Note
///
/// Username detection is heuristic-based and has a high false positive rate.
/// For production use, validate against your specific username requirements.
#[must_use]
pub fn is_username(value: &str) -> bool {
    let trimmed = value.trim();

    // Must match username pattern
    if !patterns::username::STANDARD.is_match(trimmed) {
        return false;
    }

    // Must not contain '@' or '.' to avoid emails/domains
    if trimmed.contains('@') {
        return false;
    }

    // Length must be 3-32 characters (common username constraints)
    if trimmed.len() < 3 || trimmed.len() > 32 {
        return false;
    }

    // Must not be all digits (to avoid phone numbers, IDs, etc.)
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_valid_usernames() {
        assert!(is_username("john_doe"));
        assert!(is_username("user123"));
        assert!(is_username("test-user"));
        assert!(is_username("abc")); // Minimum 3 chars
    }

    #[test]
    fn test_invalid_usernames() {
        // Too short
        assert!(!is_username("ab"));

        // Contains @
        assert!(!is_username("user@email.com"));

        // All digits
        assert!(!is_username("12345"));
        assert!(!is_username("123"));

        // Empty
        assert!(!is_username(""));

        // Just whitespace
        assert!(!is_username("   "));
    }

    #[test]
    fn test_username_length_boundaries() {
        // At minimum length (3)
        assert!(is_username("abc"));

        // Below minimum
        assert!(!is_username("ab"));
        assert!(!is_username("a"));

        // At maximum (32 chars)
        assert!(is_username("a2345678901234567890123456789012"));

        // Above maximum (33 chars)
        assert!(!is_username("a23456789012345678901234567890123"));
    }

    #[test]
    fn test_username_with_special_chars() {
        // Underscore allowed
        assert!(is_username("john_doe"));

        // Hyphen allowed
        assert!(is_username("john-doe"));

        // Multiple special chars
        assert!(is_username("john_doe-test"));

        // @ not allowed (looks like email)
        assert!(!is_username("john@doe"));
    }
}
