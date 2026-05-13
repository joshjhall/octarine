//! Request-ID primitives
//!
//! Parses incoming request IDs from header strings, falling back to a freshly
//! generated UUID v4 when the header is missing or unparseable.

use uuid::Uuid;

/// Parse an incoming request-ID header as a UUID, generating a new v4 when
/// the input is `None` or not a valid UUID.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::http::request_id::parse_or_generate_request_id;
///
/// // Valid UUID is preserved
/// let id = parse_or_generate_request_id(Some("550e8400-e29b-41d4-a716-446655440000"));
/// assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
///
/// // Missing or invalid input generates a fresh v4
/// let fresh = parse_or_generate_request_id(None);
/// assert_eq!(fresh.get_version_num(), 4);
/// ```
#[must_use]
pub fn parse_or_generate_request_id(header_value: Option<&str>) -> Uuid {
    header_value
        .and_then(|s| Uuid::try_parse(s).ok())
        .unwrap_or_else(Uuid::new_v4)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn preserves_valid_uuid() {
        let valid = "550e8400-e29b-41d4-a716-446655440000";
        let id = parse_or_generate_request_id(Some(valid));
        assert_eq!(id.to_string(), valid);
    }

    #[test]
    fn generates_v4_when_missing() {
        let id = parse_or_generate_request_id(None);
        assert_eq!(id.get_version_num(), 4);
    }

    #[test]
    fn generates_v4_when_malformed() {
        let id = parse_or_generate_request_id(Some("not-a-uuid"));
        assert_eq!(id.get_version_num(), 4);
    }

    #[test]
    fn generates_v4_when_empty() {
        let id = parse_or_generate_request_id(Some(""));
        assert_eq!(id.get_version_num(), 4);
    }

    #[test]
    fn distinct_ids_when_generated() {
        let a = parse_or_generate_request_id(None);
        let b = parse_or_generate_request_id(None);
        assert_ne!(a, b);
    }
}
