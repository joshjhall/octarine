//! Username detection
//!
//! Pure detection functions for usernames.

use super::super::super::common::patterns;
use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};

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

/// Detect usernames in free text
///
/// Tokenizes text on whitespace and punctuation boundaries, then checks each
/// token with `is_username()`. To reduce false positives in free text, tokens
/// must also contain at least one separator character (`_`, `-`, or `.`) — this
/// distinguishes username-like patterns (`john_doe`, `admin-panel`) from
/// ordinary words.
///
/// # Note
///
/// Username detection is heuristic-based. Best used for PII type detection
/// (does text contain a username?) rather than precise extraction.
#[must_use]
pub fn detect_usernames_in_text(text: &str) -> Vec<IdentifierMatch> {
    // Limit input length for safety
    if text.len() > 10_000 {
        return Vec::new();
    }

    let mut matches = Vec::new();
    let mut start = 0;

    for (i, ch) in text.char_indices() {
        if ch.is_whitespace() || ch == ',' || ch == ';' || ch == '(' || ch == ')' {
            if start < i {
                let token = &text[start..i];
                if is_username(token) && looks_like_username_in_text(token) {
                    matches.push(IdentifierMatch::new(
                        start,
                        i,
                        token.to_string(),
                        IdentifierType::Username,
                        DetectionConfidence::Low,
                    ));
                }
            }
            start = i.saturating_add(ch.len_utf8());
        }
    }

    // Check the last token
    if start < text.len() {
        let token = &text[start..];
        if is_username(token) && looks_like_username_in_text(token) {
            matches.push(IdentifierMatch::new(
                start,
                text.len(),
                token.to_string(),
                IdentifierType::Username,
                DetectionConfidence::Low,
            ));
        }
    }

    matches
}

/// Extra heuristic for text scanning: require at least one separator character
/// to distinguish usernames from ordinary words in free text.
fn looks_like_username_in_text(token: &str) -> bool {
    token.contains('_') || token.contains('-') || token.contains('.')
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
    fn test_detect_usernames_in_text() {
        let matches = detect_usernames_in_text("User john_doe logged in from admin-panel");
        // john_doe and admin-panel should match username pattern
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.matched_text == "john_doe"));
    }

    #[test]
    fn test_detect_usernames_in_text_no_matches() {
        // Plain words without separators should not match
        let matches = detect_usernames_in_text("no usernames here at all");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_detect_usernames_ignores_plain_words() {
        // Alphanumeric tokens without separators should not match
        let matches = detect_usernames_in_text("User registered with ref ABC123");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_detect_usernames_skips_emails() {
        let matches = detect_usernames_in_text("Contact user@example.com for help");
        // "user@example.com" should not match (contains @)
        assert!(matches.iter().all(|m| !m.matched_text.contains('@')));
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
