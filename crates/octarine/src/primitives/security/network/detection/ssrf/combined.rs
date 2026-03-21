//! Combined SSRF Detection
//!
//! High-level functions combining multiple SSRF detection methods.

// Allow dead_code: These are Layer 1 primitives that will be used by observe module
#![allow(dead_code)]

use super::cloud_metadata::is_cloud_metadata_endpoint;
use super::internal_hosts::is_internal_host;
use super::schemes::is_dangerous_scheme;

// ============================================================================
// URL Host Extraction
// ============================================================================

/// Extract host from URL for SSRF checking
///
/// Handles:
/// - Standard URLs (http://host/path)
/// - URLs with ports (http://host:8080/path)
/// - URLs with auth (http://user:pass@host/path)
/// - IPv6 URLs (http://[::1]/path)
///
/// # Returns
///
/// The hostname portion, or None if URL is malformed.
#[must_use]
pub fn extract_host_for_ssrf_check(url: &str) -> Option<String> {
    let trimmed = url.trim();

    // Find scheme separator
    let rest = if let Some(idx) = trimmed.find("://") {
        &trimmed[idx.saturating_add(3)..]
    } else {
        trimmed
    };

    // Handle auth (user:pass@host)
    let host_part = if let Some(at_idx) = rest.find('@') {
        &rest[at_idx.saturating_add(1)..]
    } else {
        rest
    };

    // Handle path
    let host_with_port = if let Some(slash_idx) = host_part.find('/') {
        &host_part[..slash_idx]
    } else if let Some(question_idx) = host_part.find('?') {
        &host_part[..question_idx]
    } else if let Some(hash_idx) = host_part.find('#') {
        &host_part[..hash_idx]
    } else {
        host_part
    };

    // Handle IPv6 with brackets
    if host_with_port.starts_with('[')
        && let Some(bracket_end) = host_with_port.find(']')
    {
        return Some(host_with_port[..bracket_end.saturating_add(1)].to_string());
    }

    // Handle port
    let host = if let Some(colon_idx) = host_with_port.rfind(':') {
        // Make sure this isn't part of IPv6
        if !host_with_port[..colon_idx].contains(':') {
            &host_with_port[..colon_idx]
        } else {
            host_with_port
        }
    } else {
        host_with_port
    };

    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

// ============================================================================
// Combined SSRF Detection
// ============================================================================

/// Check if URL is potentially SSRF-unsafe
///
/// Returns true if URL targets:
/// - Internal/private hosts
/// - Cloud metadata endpoints
/// - Uses dangerous schemes
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::detection::ssrf::is_potential_ssrf;
///
/// // Cloud metadata
/// assert!(is_potential_ssrf("http://169.254.169.254/latest/meta-data/"));
///
/// // File access
/// assert!(is_potential_ssrf("file:///etc/passwd"));
///
/// // Internal host
/// assert!(is_potential_ssrf("http://localhost/admin"));
///
/// // Private network
/// assert!(is_potential_ssrf("http://192.168.1.1/api"));
///
/// // Safe external URL
/// assert!(!is_potential_ssrf("https://api.github.com/users"));
/// ```
#[must_use]
pub fn is_potential_ssrf(url: &str) -> bool {
    let trimmed = url.trim();

    // Check for dangerous schemes first (most critical)
    if is_dangerous_scheme(trimmed) {
        return true;
    }

    // Extract host for further checks
    let host = match extract_host_for_ssrf_check(trimmed) {
        Some(h) => h,
        None => return false, // Can't extract host, assume safe
    };

    // Check cloud metadata endpoints
    if is_cloud_metadata_endpoint(&host) {
        return true;
    }

    // Check internal hosts
    if is_internal_host(&host) {
        return true;
    }

    false
}

/// Check if URL is a test/development SSRF payload
///
/// Detects known SSRF test patterns used in security testing.
#[must_use]
pub fn is_test_ssrf_url(url: &str) -> bool {
    let lower = url.to_lowercase();

    // Common SSRF test payloads
    if lower.contains("169.254.169.254") {
        return true;
    }
    if lower.contains("metadata.google") {
        return true;
    }
    if lower.contains("burpcollaborator") || lower.contains("oastify.com") {
        return true;
    }
    if lower.contains("requestbin") || lower.contains("webhook.site") {
        return true;
    }

    // RFC 5737 TEST-NET addresses
    if lower.contains("192.0.2.") || lower.contains("198.51.100.") || lower.contains("203.0.113.") {
        return true;
    }

    // RFC 2606 reserved domains
    if lower.contains(".example.") || lower.contains(".test.") || lower.contains(".invalid.") {
        return true;
    }

    false
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // --- URL Host Extraction Tests ---

    #[test]
    fn test_extract_host_standard() {
        assert_eq!(
            extract_host_for_ssrf_check("https://api.example.com/path"),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            extract_host_for_ssrf_check("http://localhost:8080/api"),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn test_extract_host_with_auth() {
        assert_eq!(
            extract_host_for_ssrf_check("http://user:pass@internal.server/"),
            Some("internal.server".to_string())
        );
    }

    #[test]
    fn test_extract_host_ipv6() {
        assert_eq!(
            extract_host_for_ssrf_check("http://[::1]/path"),
            Some("[::1]".to_string())
        );
    }

    // --- Combined SSRF Detection Tests ---

    #[test]
    fn test_potential_ssrf_metadata() {
        assert!(is_potential_ssrf(
            "http://169.254.169.254/latest/meta-data/"
        ));
        assert!(is_potential_ssrf(
            "http://metadata.google.internal/computeMetadata/v1/"
        ));
    }

    #[test]
    fn test_potential_ssrf_dangerous_scheme() {
        assert!(is_potential_ssrf("file:///etc/passwd"));
        assert!(is_potential_ssrf("gopher://internal:25/_"));
    }

    #[test]
    fn test_potential_ssrf_internal() {
        assert!(is_potential_ssrf("http://localhost/admin"));
        assert!(is_potential_ssrf("http://192.168.1.1/api"));
        assert!(is_potential_ssrf("http://db.internal:5432/"));
    }

    #[test]
    fn test_potential_ssrf_safe() {
        assert!(!is_potential_ssrf("https://api.github.com/users"));
        assert!(!is_potential_ssrf("https://webhook.site/callback"));
        assert!(!is_potential_ssrf("https://example.com/api"));
    }

    // --- Test Pattern Detection ---

    #[test]
    fn test_ssrf_test_patterns() {
        assert!(is_test_ssrf_url("http://169.254.169.254/test"));
        assert!(is_test_ssrf_url("http://test.burpcollaborator.net"));
        assert!(is_test_ssrf_url("http://192.0.2.1/test"));
        assert!(is_test_ssrf_url("http://test.example.com"));
        assert!(!is_test_ssrf_url("https://api.production.com"));
    }
}
