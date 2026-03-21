//! URL path normalization
//!
//! Provides functions for normalizing URL paths to a canonical form.
//! This is useful for metrics collection, caching, and routing.

// Allow dead code until this module is integrated with higher layers
#![allow(dead_code)]
// Allow arithmetic on char indices - bounded by string length
#![allow(clippy::arithmetic_side_effects)]

use std::borrow::Cow;

/// Options for URL path normalization
#[derive(Debug, Clone, Default)]
pub struct NormalizeUrlPathOptions {
    /// Remove trailing slashes (default: true)
    pub remove_trailing_slash: bool,
    /// Collapse multiple consecutive slashes (default: true)
    pub collapse_slashes: bool,
    /// Lowercase the path (default: false, as paths are case-sensitive)
    pub lowercase: bool,
    /// Remove dot segments (. and ..) (default: true)
    pub remove_dot_segments: bool,
}

impl NormalizeUrlPathOptions {
    /// Create options with all normalizations enabled
    #[must_use]
    pub fn strict() -> Self {
        Self {
            remove_trailing_slash: true,
            collapse_slashes: true,
            lowercase: false,
            remove_dot_segments: true,
        }
    }

    /// Create options for metrics collection (lowercase for grouping)
    #[must_use]
    pub fn for_metrics() -> Self {
        Self {
            remove_trailing_slash: true,
            collapse_slashes: true,
            lowercase: true,
            remove_dot_segments: true,
        }
    }

    /// Create minimal normalization options
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            remove_trailing_slash: false,
            collapse_slashes: true,
            lowercase: false,
            remove_dot_segments: false,
        }
    }
}

/// Normalize a URL path to a canonical form
///
/// Applies the following normalizations based on options:
/// - Removes trailing slashes (unless path is just "/")
/// - Collapses multiple consecutive slashes into one
/// - Optionally lowercases the path
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
/// // Internal API - use octarine::data::network for public access
/// use octarine::primitives::data::network::normalize_url_path;
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
    normalize_url_path_with_options(path, &NormalizeUrlPathOptions::strict())
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
#[must_use]
pub fn normalize_url_path_with_options<'a>(
    path: &'a str,
    options: &NormalizeUrlPathOptions,
) -> Cow<'a, str> {
    if path.is_empty() {
        return Cow::Borrowed("");
    }

    let mut result = String::new();
    let mut modified = false;

    // Process the path
    let mut prev_was_slash = false;
    let mut segments: Vec<&str> = Vec::new();
    let mut current_segment_start = 0;

    // Split into segments for dot segment processing
    if options.remove_dot_segments {
        let mut had_consecutive_slashes = false;
        for (i, c) in path.char_indices() {
            if c == '/' {
                // Detect consecutive slashes (empty segment would be skipped)
                if i == current_segment_start && i > 0 {
                    had_consecutive_slashes = true;
                }
                if i > current_segment_start {
                    segments.push(&path[current_segment_start..i]);
                }
                current_segment_start = i + 1;
            }
        }
        if current_segment_start < path.len() {
            segments.push(&path[current_segment_start..]);
        }
        if had_consecutive_slashes && options.collapse_slashes {
            modified = true;
        }

        // Process dot segments
        let mut output_segments: Vec<&str> = Vec::new();
        for segment in &segments {
            match *segment {
                "." => {
                    modified = true;
                    // Skip current directory references
                }
                ".." => {
                    modified = true;
                    // Go up one directory
                    output_segments.pop();
                }
                _ => {
                    output_segments.push(segment);
                }
            }
        }

        // Rebuild path from segments
        let starts_with_slash = path.starts_with('/');
        let ends_with_slash = path.ends_with('/') && path.len() > 1;

        if starts_with_slash {
            result.push('/');
        }

        for (i, segment) in output_segments.iter().enumerate() {
            if i > 0 {
                result.push('/');
            }
            if options.lowercase {
                result.push_str(&segment.to_lowercase());
                if segment.chars().any(|c| c.is_uppercase()) {
                    modified = true;
                }
            } else {
                result.push_str(segment);
            }
        }

        // Handle trailing slash
        if ends_with_slash && !options.remove_trailing_slash {
            result.push('/');
        } else if ends_with_slash {
            modified = true;
        }
    } else {
        // Simple processing without dot segment removal
        for c in path.chars() {
            if c == '/' {
                if prev_was_slash && options.collapse_slashes {
                    modified = true;
                    continue;
                }
                prev_was_slash = true;
            } else {
                prev_was_slash = false;
            }

            if options.lowercase && c.is_uppercase() {
                result.push(c.to_lowercase().next().unwrap_or(c));
                modified = true;
            } else {
                result.push(c);
            }
        }
    }

    // Collapse slashes if we haven't already processed this
    if options.collapse_slashes && !options.remove_dot_segments {
        let collapsed = collapse_slashes(&result);
        if collapsed.len() != result.len() {
            result = collapsed;
            modified = true;
        }
    } else if options.collapse_slashes && options.remove_dot_segments {
        // Already built result, check for collapsed slashes
        let collapsed = collapse_slashes(&result);
        if collapsed != result {
            result = collapsed;
            modified = true;
        }
    }

    // Remove trailing slash (but keep root path as "/")
    if options.remove_trailing_slash && result.len() > 1 && result.ends_with('/') {
        result.pop();
        modified = true;
    }

    // Ensure we have at least "/" for empty result from root path
    if result.is_empty() && path.starts_with('/') {
        return Cow::Borrowed("/");
    }

    if modified {
        Cow::Owned(result)
    } else {
        Cow::Borrowed(path)
    }
}

// ============================================================================
// Path Segment Normalization (for metrics)
// ============================================================================

/// Placeholder used for UUID segments in normalized paths
pub const UUID_PLACEHOLDER: &str = "{uuid}";

/// Placeholder used for numeric ID segments in normalized paths
pub const ID_PLACEHOLDER: &str = "{id}";

/// Normalize URL path segments for metrics collection.
///
/// Replaces dynamic path segments (UUIDs, numeric IDs) with placeholders
/// to prevent high-cardinality metrics labels.
///
/// # Detection
///
/// - **UUIDs**: Standard format `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` → `{uuid}`
/// - **Numeric IDs**: Pure digit segments like `123`, `456789` → `{id}`
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
/// use octarine::primitives::data::network::normalize_path_segments;
///
/// assert_eq!(
///     normalize_path_segments("/users/123/orders/456"),
///     "/users/{id}/orders/{id}"
/// );
/// assert_eq!(
///     normalize_path_segments("/users/550e8400-e29b-41d4-a716-446655440000"),
///     "/users/{uuid}"
/// );
/// ```
#[must_use]
pub fn normalize_path_segments(path: &str) -> Cow<'_, str> {
    normalize_path_segments_with_patterns(path, &[])
}

/// Pattern for matching and normalizing URL paths.
///
/// Use `{name}` placeholders to match any single path segment.
#[derive(Debug, Clone)]
pub struct PathPattern {
    /// The normalized form (e.g., "/users/{id}")
    normalized: String,
    /// Segments of the pattern
    segments: Vec<PatternSegment>,
}

#[derive(Debug, Clone)]
enum PatternSegment {
    Literal(String),
    /// Matches any non-empty path segment
    Placeholder,
}

impl PathPattern {
    /// Create a new path pattern.
    ///
    /// Placeholders are denoted with `{name}` syntax (the name is for documentation only).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::primitives::data::network::PathPattern;
    ///
    /// let pattern = PathPattern::new("/users/{id}/orders/{order_id}");
    /// ```
    #[must_use]
    pub fn new(pattern: &str) -> Self {
        let segments: Vec<PatternSegment> = pattern
            .split('/')
            .map(|seg| {
                if seg.starts_with('{') && seg.ends_with('}') {
                    PatternSegment::Placeholder
                } else {
                    PatternSegment::Literal(seg.to_string())
                }
            })
            .collect();

        Self {
            normalized: pattern.to_string(),
            segments,
        }
    }

    /// Try to match a path against this pattern.
    ///
    /// Returns the normalized form if it matches, None otherwise.
    fn try_match(&self, path: &str) -> Option<&str> {
        let path_segments: Vec<&str> = path.split('/').collect();

        if path_segments.len() != self.segments.len() {
            return None;
        }

        for (path_seg, pattern_seg) in path_segments.iter().zip(self.segments.iter()) {
            match pattern_seg {
                PatternSegment::Literal(lit) => {
                    if path_seg != lit {
                        return None;
                    }
                }
                PatternSegment::Placeholder => {
                    // Placeholder matches any non-empty segment
                    if path_seg.is_empty() {
                        return None;
                    }
                }
            }
        }

        Some(&self.normalized)
    }
}

/// Normalize URL path segments with user-defined patterns.
///
/// First checks user-defined patterns, then falls back to auto-detection
/// of UUIDs and numeric IDs.
///
/// # Arguments
///
/// * `path` - The URL path to normalize
/// * `patterns` - User-defined patterns to check first
///
/// # Returns
///
/// A normalized path with dynamic segments replaced.
#[must_use]
pub fn normalize_path_segments_with_patterns<'a>(
    path: &'a str,
    patterns: &[PathPattern],
) -> Cow<'a, str> {
    // First check user-defined patterns
    for pattern in patterns {
        if let Some(normalized) = pattern.try_match(path) {
            return Cow::Owned(normalized.to_string());
        }
    }

    // Fall back to auto-detection
    let mut modified = false;
    let result: String = path
        .split('/')
        .map(|segment| {
            if segment.is_empty() {
                segment.to_string()
            } else if is_uuid_segment(segment) {
                modified = true;
                UUID_PLACEHOLDER.to_string()
            } else if is_numeric_segment(segment) {
                modified = true;
                ID_PLACEHOLDER.to_string()
            } else {
                segment.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/");

    if modified {
        Cow::Owned(result)
    } else {
        Cow::Borrowed(path)
    }
}

/// Check if a segment looks like a UUID.
///
/// UUID format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (8-4-4-4-12 hex chars)
fn is_uuid_segment(segment: &str) -> bool {
    // Use the identifiers module for proper UUID detection
    crate::primitives::identifiers::network::NetworkIdentifierBuilder::new().is_uuid(segment)
}

/// Check if a segment is purely numeric.
fn is_numeric_segment(segment: &str) -> bool {
    !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit())
}

// ============================================================================
// Slash Normalization
// ============================================================================

/// Collapse multiple consecutive slashes into one
fn collapse_slashes(path: &str) -> String {
    let mut result = String::with_capacity(path.len());
    let mut prev_was_slash = false;

    for c in path.chars() {
        if c == '/' {
            if !prev_was_slash {
                result.push(c);
            }
            prev_was_slash = true;
        } else {
            result.push(c);
            prev_was_slash = false;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ========================================================================
    // Path Segment Normalization Tests
    // ========================================================================

    #[test]
    fn test_normalize_path_segments_uuids() {
        assert_eq!(
            normalize_path_segments("/users/550e8400-e29b-41d4-a716-446655440000").as_ref(),
            "/users/{uuid}"
        );
        assert_eq!(
            normalize_path_segments("/api/items/550e8400-e29b-41d4-a716-446655440000/details")
                .as_ref(),
            "/api/items/{uuid}/details"
        );
    }

    #[test]
    fn test_normalize_path_segments_numeric_ids() {
        assert_eq!(
            normalize_path_segments("/users/123").as_ref(),
            "/users/{id}"
        );
        assert_eq!(
            normalize_path_segments("/users/123/orders/456").as_ref(),
            "/users/{id}/orders/{id}"
        );
    }

    #[test]
    fn test_normalize_path_segments_mixed() {
        assert_eq!(
            normalize_path_segments("/users/123/orders/550e8400-e29b-41d4-a716-446655440000")
                .as_ref(),
            "/users/{id}/orders/{uuid}"
        );
    }

    #[test]
    fn test_normalize_path_segments_no_change() {
        let path = "/api/users";
        let result = normalize_path_segments(path);
        // Should return borrowed reference when no changes needed
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result.as_ref(), "/api/users");
    }

    #[test]
    fn test_normalize_path_segments_with_patterns() {
        let patterns = vec![PathPattern::new("/api/{version}/users/{id}")];

        assert_eq!(
            normalize_path_segments_with_patterns("/api/v1/users/123", &patterns).as_ref(),
            "/api/{version}/users/{id}"
        );
        assert_eq!(
            normalize_path_segments_with_patterns("/api/v2/users/456", &patterns).as_ref(),
            "/api/{version}/users/{id}"
        );

        // Falls back to auto-detection for unmatched paths
        assert_eq!(
            normalize_path_segments_with_patterns("/other/123", &patterns).as_ref(),
            "/other/{id}"
        );
    }

    #[test]
    fn test_path_pattern_matching() {
        let pattern = PathPattern::new("/users/{id}/orders/{order_id}");

        assert_eq!(
            pattern.try_match("/users/123/orders/456"),
            Some("/users/{id}/orders/{order_id}")
        );
        assert_eq!(
            pattern.try_match("/users/abc/orders/def"),
            Some("/users/{id}/orders/{order_id}")
        );
        assert_eq!(pattern.try_match("/users/123"), None); // too short
        assert_eq!(pattern.try_match("/other/123/orders/456"), None); // wrong prefix
    }

    // ========================================================================
    // URL Path Normalization Tests
    // ========================================================================

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
        // Root path should stay as "/"
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
        assert_eq!(normalize_url_path("/api/v1/./v2/../v3"), "/api/v1/v3");
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
        // Trailing slash preserved
        assert_eq!(
            normalize_url_path_with_options("/api/users/", &options),
            "/api/users/"
        );
        // But double slashes still collapsed
        assert_eq!(
            normalize_url_path_with_options("/api//users/", &options),
            "/api/users/"
        );
    }

    #[test]
    fn test_cow_optimization() {
        // Already normalized path should return Borrowed
        let path = "/api/users";
        let result = normalize_url_path(path);
        assert!(matches!(result, Cow::Borrowed(_)));

        // Path needing normalization should return Owned
        let path = "/api/users/";
        let result = normalize_url_path(path);
        assert!(matches!(result, Cow::Owned(_)));
    }
}
