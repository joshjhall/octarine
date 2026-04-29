//! Infrastructure / CDN API key detection (Cloudflare).

use super::super::super::super::common::patterns;
use super::MAX_IDENTIFIER_LENGTH;

/// Check if value is a Cloudflare Origin CA key
///
/// Origin CA keys start with "v1.0-" followed by 24 hex characters,
/// a dash, and 146 hex characters (175+ chars total)
#[must_use]
pub fn is_cloudflare_ca_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_CLOUDFLARE_CA.is_match(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_cloudflare_ca_key() {
        // Valid Origin CA key (v1.0- + 24 hex + - + 146 hex)
        let key = format!("v1.0-{}-{}", "a".repeat(24), "b".repeat(146));
        assert!(is_cloudflare_ca_key(&key));
        // Invalid: too short
        assert!(!is_cloudflare_ca_key(&format!(
            "v1.0-{}-{}",
            "a".repeat(24),
            "b".repeat(10)
        )));
        // Invalid: wrong prefix
        assert!(!is_cloudflare_ca_key(&format!(
            "v2.0-{}-{}",
            "a".repeat(24),
            "b".repeat(146)
        )));
    }
}
