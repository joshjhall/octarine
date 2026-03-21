//! Shortcut functions for URL path normalization
//!
//! Convenience functions that provide quick access to common operations
//! without needing to instantiate a builder.

// Allow dead_code: These are public API functions that will be used by consumers
#![allow(dead_code)]

use std::borrow::Cow;

use crate::primitives::data::network::{
    NormalizeUrlPathOptions as PrimitiveOptions, PathPattern as PrimitivePathPattern,
    normalize_path_segments as prim_normalize_segments,
    normalize_path_segments_with_patterns as prim_normalize_segments_with_patterns,
    normalize_url_path as prim_normalize, normalize_url_path_with_options as prim_normalize_opts,
};

use super::types::{NormalizeUrlPathOptions, PathPattern};

/// Normalize a URL path to a canonical form
///
/// Applies strict normalization:
/// - Removes trailing slashes (unless path is just "/")
/// - Collapses multiple consecutive slashes into one
/// - Removes dot segments (. and ..) per RFC 3986
///
/// # Arguments
///
/// * `path` - The URL path to normalize
///
/// # Returns
///
/// A normalized path string. Returns `Cow::Borrowed` if no changes needed.
///
/// # Examples
///
/// ```ignore
/// use octarine::data::network::normalize_url_path;
///
/// // Basic normalization
/// assert_eq!(normalize_url_path("/api/users/"), "/api/users");
/// assert_eq!(normalize_url_path("/api//users"), "/api/users");
/// assert_eq!(normalize_url_path("/api/./users"), "/api/users");
/// assert_eq!(normalize_url_path("/api/v1/../v2/users"), "/api/v2/users");
///
/// // Root path preserved
/// assert_eq!(normalize_url_path("/"), "/");
/// ```
#[must_use]
pub fn normalize_url_path(path: &str) -> Cow<'_, str> {
    prim_normalize(path)
}

/// Normalize a URL path with custom options
///
/// # Arguments
///
/// * `path` - The URL path to normalize
/// * `options` - Normalization options
///
/// # Returns
///
/// A normalized path string.
///
/// # Examples
///
/// ```ignore
/// use octarine::data::network::{normalize_url_path_with_options, NormalizeUrlPathOptions};
///
/// // For metrics (lowercase)
/// let options = NormalizeUrlPathOptions::for_metrics();
/// assert_eq!(
///     normalize_url_path_with_options("/API/Users/", &options),
///     "/api/users"
/// );
///
/// // Minimal normalization (keep trailing slash)
/// let options = NormalizeUrlPathOptions::minimal();
/// assert_eq!(
///     normalize_url_path_with_options("/api/users/", &options),
///     "/api/users/"
/// );
/// ```
#[must_use]
pub fn normalize_url_path_with_options<'a>(
    path: &'a str,
    options: &NormalizeUrlPathOptions,
) -> Cow<'a, str> {
    let prim_opts = PrimitiveOptions {
        remove_trailing_slash: options.remove_trailing_slash,
        collapse_slashes: options.collapse_slashes,
        lowercase: options.lowercase,
        remove_dot_segments: options.remove_dot_segments,
    };
    prim_normalize_opts(path, &prim_opts)
}

/// Normalize path segments by replacing dynamic values with placeholders
///
/// Automatically detects and replaces:
/// - Numeric IDs (e.g., "123" → "{id}")
/// - UUIDs (e.g., "550e8400-e29b-41d4-a716-446655440000" → "{uuid}")
///
/// Useful for metrics aggregation where paths like "/users/123" and "/users/456"
/// should be counted together as "/users/{id}".
///
/// # Arguments
///
/// * `path` - The URL path to normalize
///
/// # Returns
///
/// A normalized path with dynamic segments replaced by placeholders.
///
/// # Examples
///
/// ```ignore
/// use octarine::data::network::normalize_path_segments;
///
/// // Numeric IDs
/// assert_eq!(normalize_path_segments("/users/123"), "/users/{id}");
///
/// // UUIDs
/// assert_eq!(
///     normalize_path_segments("/orders/550e8400-e29b-41d4-a716-446655440000"),
///     "/orders/{uuid}"
/// );
///
/// // Mixed
/// assert_eq!(
///     normalize_path_segments("/users/123/orders/550e8400-e29b-41d4-a716-446655440000"),
///     "/users/{id}/orders/{uuid}"
/// );
/// ```
#[must_use]
pub fn normalize_path_segments(path: &str) -> Cow<'_, str> {
    prim_normalize_segments(path)
}

/// Normalize path segments using custom patterns with auto-detection fallback
///
/// First tries to match against user-defined patterns, then falls back to
/// automatic detection of numeric IDs and UUIDs.
///
/// # Arguments
///
/// * `path` - The URL path to normalize
/// * `patterns` - Custom patterns to match against first
///
/// # Returns
///
/// A normalized path with dynamic segments replaced by placeholders.
///
/// # Examples
///
/// ```ignore
/// use octarine::data::network::{normalize_path_segments_with_patterns, PathPattern};
///
/// let patterns = vec![
///     PathPattern::new("/api/{version}/users/{id}"),
/// ];
///
/// // Matches pattern
/// assert_eq!(
///     normalize_path_segments_with_patterns("/api/v1/users/123", &patterns),
///     "/api/{version}/users/{id}"
/// );
///
/// // Falls back to auto-detection
/// assert_eq!(
///     normalize_path_segments_with_patterns("/other/456", &patterns),
///     "/other/{id}"
/// );
/// ```
#[must_use]
pub fn normalize_path_segments_with_patterns<'a>(
    path: &'a str,
    patterns: &[PathPattern],
) -> Cow<'a, str> {
    // Convert wrapper types to primitives
    let prim_patterns: Vec<PrimitivePathPattern> =
        patterns.iter().map(|p| p.as_ref().clone()).collect();
    prim_normalize_segments_with_patterns(path, &prim_patterns)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_normalize_basic() {
        assert_eq!(normalize_url_path("/api/users"), "/api/users");
        assert_eq!(normalize_url_path("/"), "/");
        assert_eq!(normalize_url_path(""), "");
    }

    #[test]
    fn test_normalize_trailing_slash() {
        assert_eq!(normalize_url_path("/api/users/"), "/api/users");
        assert_eq!(normalize_url_path("/api/"), "/api");
        assert_eq!(normalize_url_path("/"), "/");
    }

    #[test]
    fn test_normalize_double_slashes() {
        assert_eq!(normalize_url_path("/api//users"), "/api/users");
        assert_eq!(normalize_url_path("//api///users//"), "/api/users");
    }

    #[test]
    fn test_normalize_dot_segments() {
        assert_eq!(normalize_url_path("/api/./users"), "/api/users");
        assert_eq!(normalize_url_path("/api/../users"), "/users");
        assert_eq!(normalize_url_path("/api/v1/../v2/users"), "/api/v2/users");
    }

    #[test]
    fn test_normalize_with_options() {
        let options = NormalizeUrlPathOptions::for_metrics();
        assert_eq!(
            normalize_url_path_with_options("/API/Users/", &options),
            "/api/users"
        );
    }

    #[test]
    fn test_normalize_minimal() {
        let options = NormalizeUrlPathOptions::minimal();
        assert_eq!(
            normalize_url_path_with_options("/api/users/", &options),
            "/api/users/"
        );
    }

    #[test]
    fn test_normalize_path_segments_numeric() {
        assert_eq!(normalize_path_segments("/users/123"), "/users/{id}");
        assert_eq!(
            normalize_path_segments("/users/123/orders/456"),
            "/users/{id}/orders/{id}"
        );
    }

    #[test]
    fn test_normalize_path_segments_uuid() {
        assert_eq!(
            normalize_path_segments("/users/550e8400-e29b-41d4-a716-446655440000"),
            "/users/{uuid}"
        );
    }

    #[test]
    fn test_normalize_path_segments_mixed() {
        assert_eq!(
            normalize_path_segments("/users/123/orders/550e8400-e29b-41d4-a716-446655440000"),
            "/users/{id}/orders/{uuid}"
        );
    }

    #[test]
    fn test_normalize_path_segments_no_change() {
        assert_eq!(normalize_path_segments("/api/users"), "/api/users");
        assert_eq!(normalize_path_segments("/health"), "/health");
    }

    #[test]
    fn test_normalize_path_segments_with_patterns() {
        let patterns = vec![PathPattern::new("/api/{version}/users/{id}")];

        assert_eq!(
            normalize_path_segments_with_patterns("/api/v1/users/123", &patterns),
            "/api/{version}/users/{id}"
        );
        assert_eq!(
            normalize_path_segments_with_patterns("/api/v2/users/456", &patterns),
            "/api/{version}/users/{id}"
        );
    }

    #[test]
    fn test_normalize_path_segments_with_patterns_fallback() {
        let patterns = vec![PathPattern::new("/api/{version}/users/{id}")];

        // Falls back to auto-detection for unmatched paths
        assert_eq!(
            normalize_path_segments_with_patterns("/other/123", &patterns),
            "/other/{id}"
        );
    }
}
