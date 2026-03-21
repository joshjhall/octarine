//! URL detection functions
//!
//! Detection for web URLs with various protocol schemes.

use super::super::super::common::patterns;
use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};

use super::common::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

// ============================================================================
// Single-Value Detection
// ============================================================================

/// Check if value is a URL
///
/// Supports:
/// - HTTP/HTTPS
/// - FTP
/// - WebSocket (ws://, wss://)
/// - Generic URLs with other schemes
#[must_use]
pub fn is_url(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::URL_HTTP.is_match(trimmed)
        || patterns::network::URL_FTP.is_match(trimmed)
        || patterns::network::URL_WSS.is_match(trimmed)
        || patterns::network::URL_WS.is_match(trimmed)
        || patterns::network::URL_GENERIC.is_match(trimmed)
}

// ============================================================================
// Text Scanning
// ============================================================================

/// Find all URLs in text
#[must_use]
pub fn find_urls_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for pattern in patterns::network::urls() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::Url,
                DetectionConfidence::Medium, // URLs are context-dependent
            ));
        }
    }
    deduplicate_matches(matches)
}

// ============================================================================
// Test Data Detection
// ============================================================================

/// Check if URL is a test/development URL
///
/// Detects:
/// - localhost URLs
/// - 127.0.0.1 URLs
/// - RFC 2606 reserved domains (example.com, example.net, example.org)
/// - .test, .example, .localhost, .invalid TLDs
/// - Common development patterns (dev., staging., test.)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::detection::is_test_url;
///
/// assert!(is_test_url("http://localhost:8080"));
/// assert!(is_test_url("https://example.com/api"));
/// assert!(is_test_url("http://127.0.0.1/test"));
/// assert!(!is_test_url("https://www.google.com"));
/// ```
#[must_use]
pub fn is_test_url(url: &str) -> bool {
    let lower = url.to_lowercase();

    // localhost variations
    if lower.contains("://localhost") || lower.contains("://127.0.0.1") {
        return true;
    }

    // IPv6 loopback in URL
    if lower.contains("://[::1]") {
        return true;
    }

    // RFC 2606 reserved domains
    let test_domains = ["example.com", "example.net", "example.org", "example.edu"];
    for domain in &test_domains {
        if lower.contains(domain) {
            return true;
        }
    }

    // RFC 2606 reserved TLDs
    let test_tlds = [".test", ".example", ".invalid", ".localhost"];
    for tld in &test_tlds {
        // Check for TLD at end of hostname (before path/port)
        // Simple check: contains the TLD followed by non-letter or end
        if lower.contains(&format!("{tld}/"))
            || lower.contains(&format!("{tld}:"))
            || lower.ends_with(tld)
        {
            return true;
        }
    }

    // Common development subdomains
    let dev_patterns = [
        "://dev.",
        "://staging.",
        "://test.",
        "://demo.",
        "://qa.",
        "://sandbox.",
        "://local.",
    ];
    for pattern in &dev_patterns {
        if lower.contains(pattern) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_is_url() {
        // HTTP/HTTPS
        assert!(is_url("http://example.com"));
        assert!(is_url("https://example.com"));
        assert!(is_url("https://example.com/path/to/page"));
        assert!(is_url("https://example.com:8080/path"));
        // FTP
        assert!(is_url("ftp://ftp.example.com/file.txt"));
        // WebSocket
        assert!(is_url("ws://example.com/socket"));
        assert!(is_url("wss://example.com/socket"));
        // Invalid
        assert!(!is_url("not-a-url"));
        assert!(!is_url("example.com")); // no protocol
    }

    #[test]
    fn test_find_urls_in_text() {
        let text = "Visit https://example.com or http://test.org for more info";
        let matches = find_urls_in_text(text);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_is_test_url() {
        // localhost
        assert!(is_test_url("http://localhost:8080"));
        assert!(is_test_url("https://localhost/api"));
        // 127.0.0.1
        assert!(is_test_url("http://127.0.0.1/test"));
        // IPv6 loopback
        assert!(is_test_url("http://[::1]:8080/"));
        // RFC 2606 domains
        assert!(is_test_url("https://example.com/api"));
        assert!(is_test_url("https://example.net/test"));
        assert!(is_test_url("https://example.org/"));
        // RFC 2606 TLDs
        assert!(is_test_url("https://myapp.test/"));
        assert!(is_test_url("https://api.localhost/"));
        assert!(is_test_url("https://mysite.invalid/"));
        // Dev subdomains
        assert!(is_test_url("https://dev.myapp.com/"));
        assert!(is_test_url("https://staging.myapp.com/"));
        // Real URLs - NOT test
        assert!(!is_test_url("https://www.google.com"));
        assert!(!is_test_url("https://github.com/user/repo"));
    }
}
