//! Email address detection
//!
//! Pure detection functions for email addresses.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};

use super::cache::EMAIL_CACHE;

/// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 10_000;

// ============================================================================
// Public API
// ============================================================================

/// Check if value is an email address (cached)
pub fn is_email(value: &str) -> bool {
    let trimmed = value.trim();

    // Check cache first
    if let Some(result) = EMAIL_CACHE.get(&trimmed.to_string()) {
        return result;
    }

    // Compute fresh
    let result = patterns::email::EXACT.is_match(trimmed);

    // Cache the result
    EMAIL_CACHE.insert(trimmed.to_string(), result);

    result
}

/// Check if an email is a known test/sample pattern
///
/// Test emails are commonly used in documentation and testing.
/// These should not be treated as real user data.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection;
///
/// assert!(detection::is_test_email("test@example.com"));
/// assert!(detection::is_test_email("user@test.com"));
/// assert!(!detection::is_test_email("john@company.com"));
/// ```
#[must_use]
pub fn is_test_email(email: &str) -> bool {
    let email_lower = email.to_lowercase();

    // RFC 2606 reserved domains for testing
    let test_domains = [
        "@example.com",
        "@example.org",
        "@example.net",
        "@test.com",
        "@test.org",
        "@localhost",
        "@invalid",
        "@example.co.uk",
    ];

    for domain in &test_domains {
        if email_lower.ends_with(domain) {
            return true;
        }
    }

    // Common test local parts
    let test_local_parts = [
        "test@",
        "demo@",
        "sample@",
        "example@",
        "fake@",
        "noreply@",
        "no-reply@",
        "donotreply@",
        "admin@test",
        "user@test",
    ];

    for local in &test_local_parts {
        if email_lower.starts_with(local) || email_lower.contains(local) {
            return true;
        }
    }

    false
}

/// Detect all email addresses in text
///
/// Scans text for email patterns and returns all matches with positions.
/// Includes ReDoS protection for large inputs.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection::detect_emails_in_text;
///
/// let text = "Contact: user@example.com or admin@company.org";
/// let matches = detect_emails_in_text(text);
/// assert_eq!(matches.len(), 2);
/// ```
#[allow(clippy::expect_used)]
#[must_use]
pub fn detect_emails_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::email::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = capture.get(0).expect("BUG: capture group 0 always exists");
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::Email,
            ));
        }
    }

    super::common::deduplicate_matches(matches)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::super::{clear_personal_caches, email_cache_stats};
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_is_email() {
        // Various valid formats
        assert!(is_email("user@example.com"));
        assert!(is_email("user.name@example.com"));
        assert!(is_email("user+tag@example.com"));
        assert!(is_email("user_name@example.co.uk"));

        // Invalid formats
        assert!(!is_email(""));
        assert!(!is_email("   "));
        assert!(!is_email("user")); // No @
        assert!(!is_email("@example.com")); // No local part
        assert!(!is_email("user@")); // No domain
        assert!(!is_email("user@.com")); // Invalid domain
    }

    #[test]
    fn test_is_test_email() {
        assert!(is_test_email("test@example.com"));
        assert!(is_test_email("user@test.com"));
        assert!(is_test_email("demo@company.org"));
        assert!(!is_test_email("john@company.com"));
    }

    #[test]
    fn test_detect_emails_in_text() {
        let text = "Contact: user@example.com or admin@company.org";
        let matches = detect_emails_in_text(text);
        assert_eq!(matches.len(), 2);
        assert_eq!(
            matches.first().expect("first").matched_text,
            "user@example.com"
        );
        assert_eq!(
            matches.get(1).expect("second").matched_text,
            "admin@company.org"
        );
    }

    #[test]
    fn test_detect_emails_no_matches() {
        let text = "No emails here just text";
        let matches = detect_emails_in_text(text);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    #[serial]
    fn test_email_cache_hits() {
        clear_personal_caches();

        let email = "test@example.com";
        let _result1 = is_email(email);
        let stats1 = email_cache_stats();

        let _result2 = is_email(email);
        let stats2 = email_cache_stats();

        assert!(stats2.hits > stats1.hits);
    }
}
