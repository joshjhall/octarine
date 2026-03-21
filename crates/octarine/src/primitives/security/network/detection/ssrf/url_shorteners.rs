//! URL Shortener Detection
//!
//! Detection functions for URL shortener services.

// Allow dead_code: These are Layer 1 primitives that will be used by observe module
#![allow(dead_code)]

// ============================================================================
// Constants
// ============================================================================

/// Known URL shortener services
///
/// URL shorteners can bypass domain allowlists and hide malicious destinations.
pub const URL_SHORTENERS: &[&str] = &[
    // Major shorteners
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    // Enterprise/marketing shorteners
    "rebrand.ly",
    "bl.ink",
    "short.io",
    "cutt.ly",
    "shor.by",
    // Social media shorteners
    "lnkd.in",
    "youtu.be",
    "fb.me",
    "instagr.am",
    // Other common shorteners
    "is.gd",
    "v.gd",
    "buff.ly",
    "tiny.cc",
    "shorturl.at",
    "s.id",
    "rb.gy",
    "clck.ru",
    "trib.al",
];

// ============================================================================
// Detection Functions
// ============================================================================

/// Check if host is a URL shortener service
///
/// URL shorteners can bypass domain allowlists and hide malicious destinations.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::detection::ssrf::is_url_shortener;
///
/// assert!(is_url_shortener("bit.ly"));
/// assert!(is_url_shortener("links.bit.ly"));
/// assert!(!is_url_shortener("example.com"));
/// ```
#[must_use]
pub fn is_url_shortener(host: &str) -> bool {
    let lower = host.to_lowercase();
    let trimmed = lower.trim();

    for &shortener in URL_SHORTENERS {
        if trimmed == shortener || trimmed.ends_with(&format!(".{shortener}")) {
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
    fn test_url_shorteners() {
        assert!(is_url_shortener("bit.ly"));
        assert!(is_url_shortener("tinyurl.com"));
        assert!(is_url_shortener("t.co"));
        assert!(is_url_shortener("youtu.be"));
        assert!(!is_url_shortener("example.com"));
        assert!(!is_url_shortener("github.com"));
    }

    #[test]
    fn test_url_shortener_subdomains() {
        assert!(is_url_shortener("custom.bit.ly"));
        assert!(is_url_shortener("links.rebrand.ly"));
        assert!(!is_url_shortener("bitly.com")); // Not bit.ly
    }
}
