//! Email address detection
//!
//! Pure detection functions for email addresses.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};

use super::cache::EMAIL_CACHE;

/// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 10_000;

/// Common programming file extensions that look like TLDs (2+ chars, alpha-only)
const CODE_FILE_EXTENSIONS: &[&str] = &[
    "py", "js", "ts", "rs", "go", "rb", "cs", "sh", "pl", "pm", "ex", "kt", "md", "el", "hs", "ml",
    "cc", "hh",
];

// ============================================================================
// False Positive Filters
// ============================================================================

/// Check if an email match in text is a code context false positive
///
/// Rejects matches where the TLD is a programming file extension or the match
/// is preceded by code-context indicators like `import`, `from`, or `require`.
fn is_code_context_false_positive(text: &str, match_start: usize, matched: &str) -> bool {
    // Check if TLD is a known code file extension
    if let Some(dot_pos) = matched.rfind('.') {
        let tld = matched.get(dot_pos.saturating_add(1)..);
        if let Some(tld) = tld {
            let tld_lower = tld.to_lowercase();
            if CODE_FILE_EXTENSIONS.contains(&tld_lower.as_str()) {
                return true;
            }
        }
    }

    // Check preceding text for code context indicators
    let prefix_len = 20.min(match_start);
    if let Some(prefix) = text.get(match_start.saturating_sub(prefix_len)..match_start) {
        let prefix_trimmed = prefix.trim_end();
        if prefix_trimmed.ends_with("import")
            || prefix_trimmed.ends_with("from")
            || prefix_trimmed.ends_with("require(")
            || prefix_trimmed.ends_with("require('")
            || prefix_trimmed.ends_with("require(\"")
        {
            return true;
        }
    }

    false
}

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
            let matched_text = full_match.as_str();

            // Filter out code context false positives
            if is_code_context_false_positive(text, full_match.start(), matched_text) {
                continue;
            }

            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                matched_text.to_string(),
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

    // ── RFC compliance and format tests ────────────────────────────────

    #[test]
    fn test_subaddressing_support() {
        assert!(is_email("user+tag@gmail.com"));
        assert!(is_email("user+newsletter@example.com"));
        assert!(is_email("first.last+work@company.org"));
    }

    #[test]
    fn test_long_and_new_tlds() {
        assert!(is_email("user@example.museum"));
        assert!(is_email("user@example.photography"));
        assert!(is_email("user@example.international"));
        assert!(is_email("user@example.app"));
        assert!(is_email("user@example.dev"));
        assert!(is_email("user@example.io"));
        assert!(is_email("user@example.cloud"));
    }

    #[test]
    fn test_ip_literal_email() {
        assert!(is_email("user@[192.168.1.1]"));
        assert!(is_email("admin@[10.0.0.1]"));
        // Note: regex validates format (1-3 digits per octet) but not value range
        // IP value validation is delegated to the validation layer
        assert!(!is_email("user@[]")); // Empty brackets
        assert!(!is_email("user@[not.an.ip]")); // Non-digits
    }

    #[test]
    fn test_detect_ip_literal_in_text() {
        let text = "Send to admin@[10.0.0.1] for internal mail";
        let matches = detect_emails_in_text(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches.first().expect("first").matched_text,
            "admin@[10.0.0.1]"
        );
    }

    // ── Code context false positive tests ──────────────────────────────

    #[test]
    fn test_code_annotations_not_matched() {
        // Java annotations — these don't match the email regex at all (no domain.tld)
        let text = "@Override public void method() {}";
        let matches = detect_emails_in_text(text);
        assert!(matches.is_empty());

        let text = "@Entity @Table(name = \"users\")";
        let matches = detect_emails_in_text(text);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_package_scopes_not_matched() {
        // Package scopes don't match (no domain.tld)
        let text = "import @angular/core from 'npm'";
        let matches = detect_emails_in_text(text);
        assert!(matches.is_empty());

        let text = "@types/node is a package";
        let matches = detect_emails_in_text(text);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_file_extension_false_positives() {
        // Code file references that look like emails
        let text = "See config@settings.py for details";
        let matches = detect_emails_in_text(text);
        assert!(
            matches.is_empty(),
            "config@settings.py should be filtered as code context: {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );

        let text = "Check handler@routes.js for the endpoint";
        let matches = detect_emails_in_text(text);
        assert!(
            matches.is_empty(),
            "handler@routes.js should be filtered: {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );

        let text = "See main@lib.rs for entry point";
        let matches = detect_emails_in_text(text);
        assert!(
            matches.is_empty(),
            "main@lib.rs should be filtered: {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_import_context_filtering() {
        let text = "from admin@utils.co import something";
        let matches = detect_emails_in_text(text);
        assert!(
            matches.is_empty(),
            "import context should be filtered: {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_real_emails_not_filtered() {
        // Real emails should still be detected
        let text = "Contact john@company.com or jane+work@example.org";
        let matches = detect_emails_in_text(text);
        assert_eq!(
            matches.len(),
            2,
            "real emails should still match: {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
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
