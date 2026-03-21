//! Dangerous Scheme Detection
//!
//! Detection functions for dangerous URL schemes in SSRF contexts.

// Allow dead_code: These are Layer 1 primitives that will be used by observe module
#![allow(dead_code)]

// ============================================================================
// Constants
// ============================================================================

/// URL schemes that should never be allowed in SSRF contexts
///
/// These schemes can be abused to:
/// - Read local files (file://)
/// - Access internal services (gopher://, ldap://)
/// - Bypass firewalls (dict://)
pub const DANGEROUS_SCHEMES: &[&str] = &[
    "file", "gopher", "dict", "ldap", "ldaps", "tftp", "sftp", "ftp", "data", "jar", "netdoc",
    "phar",   // PHP archive
    "expect", // PHP expect
    "input",  // PHP input
    "zip", "rar", "glob", "ssh2", "ogg",
];

/// URL schemes that are generally safe for SSRF contexts
pub const SAFE_SCHEMES: &[&str] = &["http", "https"];

// ============================================================================
// Detection Functions
// ============================================================================

/// Check if URL uses a dangerous scheme
///
/// Dangerous schemes can be used to:
/// - Read local files (file://)
/// - Access internal services (gopher://, ldap://)
/// - Execute code (phar://, expect://)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::detection::ssrf::is_dangerous_scheme;
///
/// assert!(is_dangerous_scheme("file:///etc/passwd"));
/// assert!(is_dangerous_scheme("gopher://internal:80/_"));
/// assert!(is_dangerous_scheme("ldap://dc.internal"));
/// assert!(!is_dangerous_scheme("https://api.example.com"));
/// ```
#[must_use]
pub fn is_dangerous_scheme(url: &str) -> bool {
    let lower = url.to_lowercase();
    let trimmed = lower.trim();

    for &scheme in DANGEROUS_SCHEMES {
        if trimmed.starts_with(&format!("{scheme}:")) {
            return true;
        }
    }

    false
}

/// Check if URL uses only safe schemes (HTTP/HTTPS)
///
/// Returns false if URL has no scheme or uses any non-HTTP(S) scheme.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::detection::ssrf::is_safe_scheme;
///
/// assert!(is_safe_scheme("https://api.example.com"));
/// assert!(is_safe_scheme("http://webhook.site/callback"));
/// assert!(!is_safe_scheme("file:///etc/passwd"));
/// assert!(!is_safe_scheme("ftp://server/file"));
/// ```
#[must_use]
pub fn is_safe_scheme(url: &str) -> bool {
    let lower = url.to_lowercase();
    let trimmed = lower.trim();

    for &scheme in SAFE_SCHEMES {
        if trimmed.starts_with(&format!("{scheme}://")) {
            return true;
        }
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

    #[test]
    fn test_dangerous_schemes() {
        assert!(is_dangerous_scheme("file:///etc/passwd"));
        assert!(is_dangerous_scheme("gopher://internal:80/_GET%20/"));
        assert!(is_dangerous_scheme("ldap://dc.internal"));
        assert!(is_dangerous_scheme("dict://internal:11211/"));
        assert!(!is_dangerous_scheme("https://api.example.com"));
        assert!(!is_dangerous_scheme("http://webhook.site"));
    }

    #[test]
    fn test_safe_schemes() {
        assert!(is_safe_scheme("https://api.example.com"));
        assert!(is_safe_scheme("http://webhook.site/callback"));
        assert!(!is_safe_scheme("file:///etc/passwd"));
        assert!(!is_safe_scheme("ftp://server/file"));
        assert!(!is_safe_scheme("example.com")); // No scheme
    }
}
