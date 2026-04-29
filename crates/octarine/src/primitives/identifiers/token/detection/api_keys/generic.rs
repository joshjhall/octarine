//! Generic credential detection (bearer tokens, URLs with embedded credentials).

use super::super::super::super::common::patterns;
use super::MAX_IDENTIFIER_LENGTH;

/// Check if value is a Bearer token
///
/// Bearer tokens appear in Authorization headers: "Bearer <token>"
#[must_use]
pub fn is_bearer_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::BEARER_TOKEN.is_match(trimmed)
}

/// Check if value is a URL with embedded credentials
///
/// Matches URLs like: https://user:password@host.com/path
#[must_use]
pub fn is_url_with_credentials(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::URL_WITH_CREDENTIALS.is_match(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_bearer_token() {
        // Valid bearer tokens
        assert!(is_bearer_token(
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ));
        assert!(is_bearer_token("bearer abcdef1234567890abcdef"));
        assert!(is_bearer_token("BEARER MyLongTokenValue12345678"));
        assert!(!is_bearer_token("Bearer short")); // Too short
        assert!(!is_bearer_token("Token abc123")); // Wrong prefix
    }

    #[test]
    fn test_is_url_with_credentials() {
        // Valid URLs with credentials
        assert!(is_url_with_credentials("https://user:password@example.com"));
        assert!(is_url_with_credentials(
            "ftp://admin:secret@ftp.example.com/path"
        ));
        assert!(is_url_with_credentials(
            "postgres://dbuser:dbpass@localhost:5432/mydb"
        ));
        assert!(!is_url_with_credentials("https://example.com")); // No credentials
        assert!(!is_url_with_credentials("user:password@example.com")); // No protocol
    }
}
