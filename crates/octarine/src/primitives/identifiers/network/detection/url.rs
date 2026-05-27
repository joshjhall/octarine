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
// PSL Bare-Host Validation
// ============================================================================

/// Validate a bare hostname against the Public Suffix List.
///
/// Used under `url-strict` to accept bare URLs (`example.com`, `www.example.com`)
/// while rejecting prose tokens that contain a dot (`map.contains`,
/// `foo.notatld`).
///
/// The host is lowercased before consulting the PSL because DNS names are
/// case-insensitive (RFC 1035 § 2.3.3) but `addr`'s matcher is
/// case-sensitive against the lowercase PSL.
#[cfg(feature = "url-strict")]
fn is_bare_host_valid(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    addr::parse_domain_name(&lower)
        .map(|d| d.has_known_suffix())
        .unwrap_or(false)
}

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
///
/// Under the default `url-strict` feature, also accepts bare hosts whose TLD
/// is on the Public Suffix List (e.g., `example.com`, `www.example.com`).
#[must_use]
pub fn is_url(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }

    let scheme_match = patterns::network::URL_HTTP.is_match(trimmed)
        || patterns::network::URL_FTP.is_match(trimmed)
        || patterns::network::URL_WSS.is_match(trimmed)
        || patterns::network::URL_WS.is_match(trimmed)
        || patterns::network::URL_GENERIC.is_match(trimmed);
    if scheme_match {
        return true;
    }

    // Bare-host fallback under `url-strict` only — preserves today's
    // "scheme required" behavior for callers that opt out.
    #[cfg(feature = "url-strict")]
    {
        is_bare_host_valid(trimmed)
    }
    #[cfg(not(feature = "url-strict"))]
    {
        false
    }
}

// ============================================================================
// Text Scanning
// ============================================================================

/// Find all URLs in text
///
/// Under the default `url-strict` feature, uses `linkify` for prose-aware
/// boundary detection (e.g., trims trailing punctuation, balances parens)
/// and accepts bare URLs. Candidates are post-filtered through
/// `url::Url::parse` (scheme-prefixed) or the Public Suffix List
/// (bare hosts) to reject prose tokens like `map.contains`.
///
/// Under `not(url-strict)`, falls back to the original regex-based scan.
#[cfg(feature = "url-strict")]
#[must_use]
pub fn find_urls_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut finder = linkify::LinkFinder::new();
    finder.url_must_have_scheme(false);
    finder.kinds(&[linkify::LinkKind::Url]);

    let mut matches = Vec::new();
    for link in finder.links(text) {
        let candidate = link.as_str();
        let valid = if candidate.contains("://") {
            url::Url::parse(candidate).is_ok()
        } else {
            is_bare_host_valid(candidate)
        };
        if !valid {
            continue;
        }
        matches.push(IdentifierMatch::new(
            link.start(),
            link.end(),
            candidate.to_string(),
            IdentifierType::Url,
            DetectionConfidence::Medium, // URLs are context-dependent
        ));
    }
    deduplicate_matches(matches)
}

/// Find all URLs in text (regex fallback under `not(url-strict)`).
#[cfg(not(feature = "url-strict"))]
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
                DetectionConfidence::Medium,
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
    #![allow(clippy::panic, clippy::expect_used)]
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
    }

    /// Under `url-strict`, bare hostnames with a Public Suffix List TLD are
    /// recognized as URLs (`example.com`, `www.example.com`), while prose
    /// tokens that look like dotted names are not (`map.contains`,
    /// `foo.notatld`).
    #[cfg(feature = "url-strict")]
    #[test]
    fn test_is_url_bare_host_strict() {
        assert!(is_url("example.com"));
        assert!(is_url("www.example.com"));
        assert!(is_url("github.io"));
        // Prose tokens — must not validate.
        assert!(!is_url("map.contains"));
        assert!(!is_url("foo.notatld"));
        assert!(!is_url("3.5.2"));
    }

    /// Under `not(url-strict)`, the legacy "scheme required" behavior holds.
    #[cfg(not(feature = "url-strict"))]
    #[test]
    fn test_is_url_no_bare_host() {
        assert!(!is_url("example.com"));
    }

    #[test]
    fn test_find_urls_in_text() {
        let text = "Visit https://example.com or http://test.org for more info";
        let matches = find_urls_in_text(text);
        assert_eq!(matches.len(), 2);
    }

    /// Bare-URL detection (issue #429): `linkify` extracts dotted hosts from
    /// prose under `url-strict`, then the PSL post-filter keeps only the
    /// real domains.
    #[cfg(feature = "url-strict")]
    #[test]
    fn test_find_urls_bare_in_prose() {
        let text = "visit example.com today";
        let matches = find_urls_in_text(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches.first().expect("first").matched_text, "example.com");
    }

    /// Issue #429: URL extraction must not greedily eat trailing prose.
    /// The legacy regex `https?://[^\s]+` happened to stop at whitespace
    /// already, but apostrophes and trailing punctuation tested here can
    /// confuse less careful extractors.
    #[cfg(feature = "url-strict")]
    #[test]
    fn test_find_urls_does_not_over_match() {
        let text = "Read https://example.com it's great";
        let matches = find_urls_in_text(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches.first().expect("first").matched_text,
            "https://example.com"
        );

        // Trailing punctuation is stripped by linkify.
        let text = "Check https://example.com/foo.";
        let matches = find_urls_in_text(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches.first().expect("first").matched_text,
            "https://example.com/foo"
        );
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
