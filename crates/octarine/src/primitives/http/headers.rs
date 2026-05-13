//! Header-parsing primitives
//!
//! Pure parsers for HTTP header values. Callers convert from framework types
//! (e.g. `axum::http::HeaderValue`) to `&str` before calling in, keeping
//! this module dependency-free.

/// Parse the first client IP from an `X-Forwarded-For` header value.
///
/// `X-Forwarded-For` is a comma-separated chain of intermediaries:
/// `"client, proxy1, proxy2"`. The first entry is the original client.
///
/// Returns `None` if the header is empty or contains only whitespace.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::http::headers::parse_forwarded_for;
///
/// assert_eq!(parse_forwarded_for("203.0.113.5, 10.0.0.1"), Some("203.0.113.5"));
/// assert_eq!(parse_forwarded_for("  198.51.100.7  "), Some("198.51.100.7"));
/// assert_eq!(parse_forwarded_for(""), None);
/// ```
#[must_use]
pub fn parse_forwarded_for(header_value: &str) -> Option<&str> {
    let first = header_value.split(',').next()?.trim();
    if first.is_empty() { None } else { Some(first) }
}

/// Parse a single client IP from an `X-Real-IP` header value (nginx
/// convention).
///
/// Returns `None` if the header is empty or whitespace.
#[must_use]
pub fn parse_real_ip(header_value: &str) -> Option<&str> {
    let trimmed = header_value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Strip the `"Bearer "` prefix from an Authorization header value, returning
/// the token slice when the prefix is present.
///
/// Returns `None` for any value that does not start with the exact
/// case-sensitive prefix `Bearer ` (matching RFC 6750 §2.1 syntax that
/// upstream callers expect).
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::http::headers::parse_bearer_token;
///
/// assert_eq!(parse_bearer_token("Bearer abc.def.ghi"), Some("abc.def.ghi"));
/// assert_eq!(parse_bearer_token("Basic dXNlcjpwYXNz"), None);
/// ```
#[must_use]
pub fn parse_bearer_token(auth_header: &str) -> Option<&str> {
    auth_header.strip_prefix("Bearer ")
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_for_single_ip() {
        assert_eq!(parse_forwarded_for("203.0.113.5"), Some("203.0.113.5"));
    }

    #[test]
    fn forwarded_for_takes_first_in_chain() {
        assert_eq!(
            parse_forwarded_for("203.0.113.5, 10.0.0.1, 10.0.0.2"),
            Some("203.0.113.5"),
        );
    }

    #[test]
    fn forwarded_for_trims_whitespace() {
        assert_eq!(parse_forwarded_for("  203.0.113.5  "), Some("203.0.113.5"));
    }

    #[test]
    fn forwarded_for_returns_none_on_empty() {
        assert_eq!(parse_forwarded_for(""), None);
        assert_eq!(parse_forwarded_for("   "), None);
        assert_eq!(parse_forwarded_for(","), None);
    }

    #[test]
    fn real_ip_trims_whitespace() {
        assert_eq!(parse_real_ip("  198.51.100.7  "), Some("198.51.100.7"));
    }

    #[test]
    fn real_ip_returns_none_on_empty() {
        assert_eq!(parse_real_ip(""), None);
        assert_eq!(parse_real_ip("   "), None);
    }

    #[test]
    fn bearer_token_strips_prefix() {
        assert_eq!(
            parse_bearer_token("Bearer abc.def.ghi"),
            Some("abc.def.ghi")
        );
    }

    #[test]
    fn bearer_token_rejects_other_schemes() {
        assert_eq!(parse_bearer_token("Basic dXNlcjpwYXNz"), None);
        assert_eq!(parse_bearer_token("Digest realm=test"), None);
    }

    #[test]
    fn bearer_token_is_case_sensitive() {
        // Per RFC 6750, the scheme is case-insensitive in HTTP, but upstream
        // callers historically matched the exact "Bearer " prefix; preserve
        // that behavior here. Documented in function-level docs.
        assert_eq!(parse_bearer_token("bearer abc"), None);
        assert_eq!(parse_bearer_token("BEARER abc"), None);
    }

    #[test]
    fn bearer_token_requires_space_separator() {
        assert_eq!(parse_bearer_token("Bearer"), None);
        assert_eq!(parse_bearer_token("Bearer:abc"), None);
    }

    #[test]
    fn bearer_token_empty_after_prefix() {
        // Caller is responsible for rejecting empty tokens; this returns Some("")
        // to keep the primitive a pure prefix-strip.
        assert_eq!(parse_bearer_token("Bearer "), Some(""));
    }
}
