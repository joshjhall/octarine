//! Domain, hostname, and port detection functions
//!
//! Detection for domain names, hostnames, and port numbers.

use super::super::super::common::patterns;

use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};

use super::common::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

// ============================================================================
// Single-Value Detection
// ============================================================================

/// Check if value is a domain name (without protocol)
///
/// Returns false if the value contains a protocol (://)
#[must_use]
pub fn is_domain(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    // Reject if contains protocol separator
    if trimmed.contains("://") {
        return false;
    }
    patterns::network::DOMAIN.is_match(trimmed)
}

/// Check if value is a hostname
#[must_use]
pub fn is_hostname(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::HOSTNAME.is_match(trimmed)
}

/// Check if value is a port number
#[must_use]
pub fn is_port(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::PORT.is_match(trimmed)
}

// ============================================================================
// Text Scanning
// ============================================================================

/// Find all domain names in text
#[must_use]
pub fn find_domains_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for capture in patterns::network::DOMAIN.captures_iter(text) {
        let full_match = get_full_match(&capture);
        matches.push(IdentifierMatch::new(
            full_match.start(),
            full_match.end(),
            full_match.as_str().to_string(),
            IdentifierType::Domain,
            DetectionConfidence::Medium,
        ));
    }
    deduplicate_matches(matches)
}

/// Conservative filter: HOSTNAME regex matches any single word, so require
/// a hyphen, an ASCII digit, or a `:port` suffix to avoid flagging plain
/// English. Trade-off: bare `localhost` is filtered; `localhost:8080` passes.
fn is_likely_real_hostname(matched: &str) -> bool {
    matched.contains('-') || matched.chars().any(|c| c.is_ascii_digit()) || matched.contains(':')
}

/// Find all hostname-like tokens in text
///
/// Filters plain English words via a conservative rule. Detection-only;
/// validation is out of scope.
#[must_use]
pub fn find_hostnames_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for capture in patterns::network::HOSTNAME.captures_iter(text) {
        let full_match = get_full_match(&capture);
        let matched_text = full_match.as_str();
        if !is_likely_real_hostname(matched_text) {
            continue;
        }
        matches.push(IdentifierMatch::new(
            full_match.start(),
            full_match.end(),
            matched_text.to_string(),
            IdentifierType::Hostname,
            DetectionConfidence::Low,
        ));
    }
    deduplicate_matches(matches)
}

/// Find all port tokens (`:N`) in text
#[must_use]
pub fn find_ports_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for capture in patterns::network::PORT.captures_iter(text) {
        let full_match = get_full_match(&capture);
        matches.push(IdentifierMatch::new(
            full_match.start(),
            full_match.end(),
            full_match.as_str().to_string(),
            IdentifierType::Port,
            DetectionConfidence::Medium,
        ));
    }
    deduplicate_matches(matches)
}

// ============================================================================
// Test Data Detection
// ============================================================================

/// Check if domain is a test/reserved domain
///
/// Detects:
/// - RFC 2606 reserved domains (example.com/net/org)
/// - RFC 2606 reserved TLDs (.test, .example, .invalid, .localhost)
/// - localhost
/// - Common test patterns
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::detection::is_test_domain;
///
/// assert!(is_test_domain("example.com"));
/// assert!(is_test_domain("test.localhost"));
/// assert!(is_test_domain("myapp.test"));
/// assert!(!is_test_domain("google.com"));
/// ```
#[must_use]
pub fn is_test_domain(domain: &str) -> bool {
    let lower = domain.to_lowercase();

    // localhost
    if lower == "localhost" {
        return true;
    }

    // RFC 2606 reserved domains
    let reserved = ["example.com", "example.net", "example.org", "example.edu"];
    for d in &reserved {
        if lower == *d || lower.ends_with(&format!(".{d}")) {
            return true;
        }
    }

    // RFC 2606 reserved TLDs
    let reserved_tlds = [".test", ".example", ".invalid", ".localhost"];
    for tld in &reserved_tlds {
        if lower.ends_with(tld) {
            return true;
        }
    }

    // Common test subdomains (if they appear at start)
    let test_prefixes = ["dev.", "staging.", "test.", "demo.", "qa.", "sandbox."];
    for prefix in &test_prefixes {
        if lower.starts_with(prefix) {
            return true;
        }
    }

    false
}

/// Check if hostname is a test/development hostname
///
/// Detects:
/// - localhost
/// - Common test prefixes (test-, dev-, staging-)
/// - Common test suffixes (-test, -dev, -local)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::detection::is_test_hostname;
///
/// assert!(is_test_hostname("localhost"));
/// assert!(is_test_hostname("test-server"));
/// assert!(is_test_hostname("db-dev"));
/// assert!(!is_test_hostname("production-db"));
/// ```
#[must_use]
pub fn is_test_hostname(hostname: &str) -> bool {
    let lower = hostname.to_lowercase();

    // Remove port if present
    let name = lower.split(':').next().unwrap_or(&lower);

    // localhost
    if name == "localhost" {
        return true;
    }

    // Test prefixes
    let test_prefixes = [
        "test-", "dev-", "staging-", "demo-", "qa-", "local-", "sandbox-",
    ];
    for prefix in &test_prefixes {
        if name.starts_with(prefix) {
            return true;
        }
    }

    // Test suffixes
    let test_suffixes = [
        "-test", "-dev", "-local", "-staging", "-demo", "-qa", "-sandbox",
    ];
    for suffix in &test_suffixes {
        if name.ends_with(suffix) {
            return true;
        }
    }

    // Contains test keywords
    let test_keywords = ["localhost", "testserver", "devserver", "mockserver"];
    for keyword in &test_keywords {
        if name == *keyword {
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
    fn test_is_domain() {
        assert!(is_domain("example.com"));
        assert!(is_domain("sub.example.com"));
        assert!(is_domain("example.co.uk"));
        // With protocol - NOT domain
        assert!(!is_domain("https://example.com"));
        // Invalid
        assert!(!is_domain("not a domain"));
    }

    #[test]
    fn test_find_domains_in_text() {
        let matches = find_domains_in_text("Visit example.com and api.github.com for more");
        assert!(matches.len() >= 2);
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::Domain)
        );
    }

    #[test]
    fn test_find_domains_in_text_empty() {
        let matches = find_domains_in_text("No domains here just plain text");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_is_hostname() {
        assert!(is_hostname("server1"));
        assert!(is_hostname("my-server"));
        assert!(is_hostname("db-server-01"));
    }

    #[test]
    fn test_is_port() {
        assert!(is_port(":8080"));
        assert!(is_port(":443"));
        assert!(is_port(":3000"));
        assert!(!is_port(":0")); // Port 0 is invalid (pattern starts with [1-9])
        assert!(!is_port("8080")); // Missing colon
    }

    #[test]
    fn test_is_test_domain() {
        // RFC 2606 reserved
        assert!(is_test_domain("example.com"));
        assert!(is_test_domain("example.net"));
        assert!(is_test_domain("example.org"));
        assert!(is_test_domain("sub.example.com"));
        // Reserved TLDs
        assert!(is_test_domain("myapp.test"));
        assert!(is_test_domain("api.localhost"));
        assert!(is_test_domain("site.invalid"));
        // localhost
        assert!(is_test_domain("localhost"));
        // Test prefixes
        assert!(is_test_domain("dev.myapp.com"));
        assert!(is_test_domain("staging.api.io"));
        // Real domains - NOT test
        assert!(!is_test_domain("google.com"));
        assert!(!is_test_domain("github.com"));
    }

    #[test]
    fn test_is_test_hostname() {
        // localhost
        assert!(is_test_hostname("localhost"));
        assert!(is_test_hostname("localhost:8080"));
        // Test prefixes
        assert!(is_test_hostname("test-server"));
        assert!(is_test_hostname("dev-db"));
        assert!(is_test_hostname("staging-api"));
        // Test suffixes
        assert!(is_test_hostname("server-test"));
        assert!(is_test_hostname("db-dev"));
        assert!(is_test_hostname("api-local"));
        // Regular hostnames - NOT test
        assert!(!is_test_hostname("production-db"));
        assert!(!is_test_hostname("web-server"));
    }

    #[test]
    fn test_find_hostnames_in_text_filters_english_words() {
        let matches = find_hostnames_in_text("Hello there, this is the server.");
        assert!(
            matches.is_empty(),
            "expected zero hostnames in plain English, got {matches:?}"
        );
    }

    #[test]
    fn test_find_hostnames_in_text_detects_real_hostnames() {
        let matches = find_hostnames_in_text("server1 my-db-prod cache:8080");
        let values: Vec<&str> = matches.iter().map(|m| m.matched_text.as_str()).collect();
        assert!(values.contains(&"server1"), "missing server1 in {values:?}");
        assert!(
            values.contains(&"my-db-prod"),
            "missing my-db-prod in {values:?}"
        );
        assert!(
            values.iter().any(|v| v.starts_with("cache")),
            "missing cache:8080 in {values:?}"
        );
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::Hostname)
        );
    }

    #[test]
    fn test_find_hostnames_in_text_localhost_alone_filtered() {
        // Bare `localhost` (no digit/hyphen/colon) — filtered. Trade-off for
        // the conservative rule. `localhost:8080` still passes.
        assert!(find_hostnames_in_text("localhost").is_empty());
        assert!(!find_hostnames_in_text("localhost:8080").is_empty());
    }

    #[test]
    fn test_find_ports_in_text() {
        let matches = find_ports_in_text("Connect to :8080 or :443 for HTTPS.");
        assert_eq!(matches.len(), 2);
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::Port)
        );
    }

    #[test]
    fn test_find_ports_in_text_empty() {
        assert!(find_ports_in_text("no ports here").is_empty());
    }
}
