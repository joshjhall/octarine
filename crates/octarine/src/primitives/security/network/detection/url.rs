//! URL detection and parsing utilities
//!
//! Pure functions for URL parsing without PII detection concerns.

// Allow dead_code: These are Layer 1 primitives that will be used by observe module
#![allow(dead_code)]
// Allow arithmetic side effects in URL parsing (safe string indexing)
#![allow(clippy::arithmetic_side_effects)]

// ============================================================================
// URL Parsing
// ============================================================================

/// Extract the scheme from a URL
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::data::network::detection::url::extract_scheme;
///
/// assert_eq!(extract_scheme("https://example.com"), Some("https"));
/// assert_eq!(extract_scheme("file:///etc/passwd"), Some("file"));
/// assert_eq!(extract_scheme("example.com"), None);
/// ```
#[must_use]
pub fn extract_scheme(url: &str) -> Option<&str> {
    let trimmed = url.trim();
    if let Some(idx) = trimmed.find("://") {
        let scheme = &trimmed[..idx];
        // Validate scheme: only alphanumeric, +, -, .
        if scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        {
            return Some(scheme);
        }
    }
    None
}

/// Extract the host from a URL
///
/// Returns the host portion without port or path.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::data::network::detection::url::extract_host;
///
/// assert_eq!(extract_host("https://example.com:8080/path"), Some("example.com"));
/// assert_eq!(extract_host("http://192.168.1.1/api"), Some("192.168.1.1"));
/// assert_eq!(extract_host("invalid"), None);
/// ```
#[must_use]
pub fn extract_host(url: &str) -> Option<&str> {
    let trimmed = url.trim();

    // Find the scheme separator
    let after_scheme = if let Some(idx) = trimmed.find("://") {
        &trimmed[idx + 3..]
    } else if let Some(rest) = trimmed.strip_prefix("//") {
        rest
    } else {
        return None;
    };

    // Remove userinfo if present (user:pass@)
    let after_userinfo = if let Some(at_idx) = after_scheme.find('@') {
        &after_scheme[at_idx + 1..]
    } else {
        after_scheme
    };

    // Find the end of the host (port, path, query, or fragment)
    let host_end = after_userinfo
        .find([':', '/', '?', '#'])
        .unwrap_or(after_userinfo.len());

    let host = &after_userinfo[..host_end];

    if host.is_empty() { None } else { Some(host) }
}

/// Check if a URL is absolute (has a scheme)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::data::network::detection::url::is_absolute_url;
///
/// assert!(is_absolute_url("https://example.com"));
/// assert!(is_absolute_url("file:///etc/passwd"));
/// assert!(!is_absolute_url("/path/to/file"));
/// assert!(!is_absolute_url("relative/path"));
/// ```
#[must_use]
pub fn is_absolute_url(url: &str) -> bool {
    extract_scheme(url).is_some()
}

/// Check if a URL is relative (no scheme)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::data::network::detection::url::is_relative_url;
///
/// assert!(is_relative_url("/path/to/file"));
/// assert!(is_relative_url("relative/path"));
/// assert!(is_relative_url("../parent"));
/// assert!(!is_relative_url("https://example.com"));
/// ```
#[must_use]
pub fn is_relative_url(url: &str) -> bool {
    !is_absolute_url(url)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_scheme() {
        assert_eq!(extract_scheme("https://example.com"), Some("https"));
        assert_eq!(extract_scheme("http://example.com"), Some("http"));
        assert_eq!(extract_scheme("file:///etc/passwd"), Some("file"));
        assert_eq!(extract_scheme("ftp://ftp.example.com"), Some("ftp"));
        assert_eq!(
            extract_scheme("custom+scheme://host"),
            Some("custom+scheme")
        );
        assert_eq!(extract_scheme("example.com"), None);
        assert_eq!(extract_scheme("/path"), None);
        assert_eq!(extract_scheme(""), None);
    }

    #[test]
    fn test_extract_host() {
        assert_eq!(extract_host("https://example.com"), Some("example.com"));
        assert_eq!(
            extract_host("https://example.com:8080"),
            Some("example.com")
        );
        assert_eq!(
            extract_host("https://example.com/path"),
            Some("example.com")
        );
        assert_eq!(
            extract_host("https://example.com?query"),
            Some("example.com")
        );
        assert_eq!(
            extract_host("https://example.com#frag"),
            Some("example.com")
        );
        assert_eq!(
            extract_host("https://user:pass@example.com"),
            Some("example.com")
        );
        assert_eq!(extract_host("http://192.168.1.1"), Some("192.168.1.1"));
        assert_eq!(extract_host("//example.com/path"), Some("example.com"));
        assert_eq!(extract_host("example.com"), None);
        assert_eq!(extract_host(""), None);
    }

    #[test]
    fn test_is_absolute_url() {
        assert!(is_absolute_url("https://example.com"));
        assert!(is_absolute_url("http://example.com"));
        assert!(is_absolute_url("file:///etc/passwd"));
        assert!(!is_absolute_url("/path/to/file"));
        assert!(!is_absolute_url("relative/path"));
        assert!(!is_absolute_url(""));
    }

    #[test]
    fn test_is_relative_url() {
        assert!(is_relative_url("/path/to/file"));
        assert!(is_relative_url("relative/path"));
        assert!(is_relative_url("../parent"));
        assert!(is_relative_url(""));
        assert!(!is_relative_url("https://example.com"));
    }
}
