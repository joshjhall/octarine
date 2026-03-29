// Allow clippy lints that are overly strict for this utility module
#![allow(clippy::unnecessary_map_or)]

//! Path joining utilities
//!
//! Functions for safely joining path segments.
//! These are pure functions with NO observe dependencies.
//!
//! ## Coverage
//!
//! - Join two path segments
//! - Join multiple segments
//! - Platform-aware joining
//!
//! ## Design Principles
//!
//! 1. **Pure Functions**: No logging, no side effects
//! 2. **No Validation**: Does NOT check for security issues
//! 3. **Format Only**: Handles separators, not security
//!
//! ## Important: Construction vs Sanitization
//!
//! Construction functions handle **format** (separators, joining).
//! Security validation should happen BEFORE or AFTER construction,
//! not during. This keeps concerns separated.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

// ============================================================================
// Basic Joining
// ============================================================================

/// Join two path segments with forward slash separator
///
/// Handles cases where segments may already have separators.
/// Does NOT validate for security issues.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::join;
///
/// assert_eq!(join::join_unix("path/to", "file.txt"), "path/to/file.txt");
/// assert_eq!(join::join_unix("path/to/", "file.txt"), "path/to/file.txt");
/// assert_eq!(join::join_unix("path/to", "/file.txt"), "path/to/file.txt");
/// ```
#[must_use]
pub fn join_unix(base: &str, segment: &str) -> String {
    if base.is_empty() {
        return segment.to_string();
    }
    if segment.is_empty() {
        return base.to_string();
    }

    let base = base.strip_suffix('/').unwrap_or(base);
    let segment = segment.strip_prefix('/').unwrap_or(segment);

    format!("{}/{}", base, segment)
}

/// Join two path segments with backslash separator
///
/// Handles cases where segments may already have separators.
/// Does NOT validate for security issues.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::join;
///
/// assert_eq!(join::join_windows("path\\to", "file.txt"), "path\\to\\file.txt");
/// assert_eq!(join::join_windows("path\\to\\", "file.txt"), "path\\to\\file.txt");
/// ```
#[must_use]
pub fn join_windows(base: &str, segment: &str) -> String {
    if base.is_empty() {
        return segment.to_string();
    }
    if segment.is_empty() {
        return base.to_string();
    }

    let base = base.strip_suffix('\\').unwrap_or(base);
    let segment = segment.strip_prefix('\\').unwrap_or(segment);

    format!("{}\\{}", base, segment)
}

/// Join path segments using std::path::Path
///
/// Uses the standard library's path joining which is platform-aware.
/// This is the recommended approach for portable code.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::join;
///
/// let result = join::join_std("path/to", "file.txt");
/// // Result depends on platform: "path/to/file.txt" or "path\to\file.txt"
/// ```
#[must_use]
pub fn join_std(base: &str, segment: &str) -> PathBuf {
    Path::new(base).join(segment)
}

// ============================================================================
// Multiple Segment Joining
// ============================================================================

/// Join multiple path segments with forward slash separator
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::join;
///
/// assert_eq!(
///     join::join_many_unix(&["path", "to", "file.txt"]),
///     "path/to/file.txt"
/// );
/// ```
#[must_use]
pub fn join_many_unix(segments: &[&str]) -> String {
    if segments.is_empty() {
        return String::new();
    }

    let first = segments.first().unwrap_or(&"");
    let mut result = (*first).to_string();
    for segment in segments.get(1..).unwrap_or(&[]) {
        result = join_unix(&result, segment);
    }
    result
}

/// Join multiple path segments with backslash separator
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::join;
///
/// assert_eq!(
///     join::join_many_windows(&["path", "to", "file.txt"]),
///     "path\\to\\file.txt"
/// );
/// ```
#[must_use]
pub fn join_many_windows(segments: &[&str]) -> String {
    if segments.is_empty() {
        return String::new();
    }

    let first = segments.first().unwrap_or(&"");
    let mut result = (*first).to_string();
    for segment in segments.get(1..).unwrap_or(&[]) {
        result = join_windows(&result, segment);
    }
    result
}

/// Join multiple path segments using std::path
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::join;
///
/// let result = join::join_many_std(&["path", "to", "file.txt"]);
/// ```
#[must_use]
pub fn join_many_std(segments: &[&str]) -> PathBuf {
    let mut path = PathBuf::new();
    for segment in segments {
        path.push(segment);
    }
    path
}

// ============================================================================
// Conditional Joining
// ============================================================================

/// Join segments only if the second is not absolute
///
/// If `segment` is an absolute path, returns it unchanged.
/// Otherwise, joins with `base`.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::construction::join;
///
/// // Relative segment - joins
/// assert_eq!(join::join_if_relative("base", "relative/path"), "base/relative/path");
///
/// // Absolute segment - returns as-is
/// assert_eq!(join::join_if_relative("base", "/absolute/path"), "/absolute/path");
/// ```
#[must_use]
pub fn join_if_relative<'a>(base: &'a str, segment: &'a str) -> Cow<'a, str> {
    // Check if segment is absolute
    if segment.starts_with('/')
        || segment.starts_with('\\')
        || (segment.len() >= 2
            && segment
                .chars()
                .next()
                .map_or(false, |c| c.is_ascii_alphabetic())
            && segment.chars().nth(1) == Some(':'))
    {
        // Segment is absolute, return as-is
        Cow::Borrowed(segment)
    } else {
        // Join with base
        Cow::Owned(join_unix(base, segment))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Basic Unix joining
    #[test]
    fn test_join_unix_basic() {
        assert_eq!(join_unix("path/to", "file.txt"), "path/to/file.txt");
        assert_eq!(join_unix("path", "file"), "path/file");
        assert_eq!(join_unix("a", "b"), "a/b");
    }

    #[test]
    fn test_join_unix_with_trailing_separator() {
        assert_eq!(join_unix("path/to/", "file.txt"), "path/to/file.txt");
        assert_eq!(join_unix("dir/", "subdir/"), "dir/subdir/");
    }

    #[test]
    fn test_join_unix_with_leading_separator() {
        assert_eq!(join_unix("path/to", "/file.txt"), "path/to/file.txt");
    }

    #[test]
    fn test_join_unix_empty() {
        assert_eq!(join_unix("", "file.txt"), "file.txt");
        assert_eq!(join_unix("path", ""), "path");
        assert_eq!(join_unix("", ""), "");
    }

    // Basic Windows joining
    #[test]
    fn test_join_windows_basic() {
        assert_eq!(join_windows("path\\to", "file.txt"), "path\\to\\file.txt");
        assert_eq!(join_windows("path", "file"), "path\\file");
    }

    #[test]
    fn test_join_windows_with_trailing_separator() {
        assert_eq!(join_windows("path\\to\\", "file.txt"), "path\\to\\file.txt");
    }

    #[test]
    fn test_join_windows_with_leading_separator() {
        assert_eq!(join_windows("path\\to", "\\file.txt"), "path\\to\\file.txt");
    }

    // Multiple segment joining
    #[test]
    fn test_join_many_unix() {
        assert_eq!(
            join_many_unix(&["path", "to", "file.txt"]),
            "path/to/file.txt"
        );
        assert_eq!(join_many_unix(&["a", "b", "c", "d"]), "a/b/c/d");
        assert_eq!(join_many_unix(&["single"]), "single");
        assert_eq!(join_many_unix(&[]), "");
    }

    #[test]
    fn test_join_many_windows() {
        assert_eq!(
            join_many_windows(&["path", "to", "file.txt"]),
            "path\\to\\file.txt"
        );
    }

    // Conditional joining
    #[test]
    fn test_join_if_relative_unix() {
        assert_eq!(
            join_if_relative("base", "relative/path").as_ref(),
            "base/relative/path"
        );
        assert_eq!(
            join_if_relative("base", "/absolute/path").as_ref(),
            "/absolute/path"
        );
    }

    #[test]
    fn test_join_if_relative_windows() {
        assert_eq!(
            join_if_relative("base", "C:\\absolute").as_ref(),
            "C:\\absolute"
        );
        assert_eq!(join_if_relative("base", "\\root").as_ref(), "\\root");
    }

    // std::path joining
    #[test]
    fn test_join_std() {
        let result = join_std("path/to", "file.txt");
        assert!(result.ends_with("file.txt"));
    }

    #[test]
    fn test_join_many_std() {
        let result = join_many_std(&["path", "to", "file.txt"]);
        assert!(result.ends_with("file.txt"));
    }

    // Edge cases
    #[test]
    fn test_join_with_dots() {
        // Join preserves dots - it doesn't resolve them
        assert_eq!(join_unix("path", "../other"), "path/../other");
        assert_eq!(join_unix("path", "./current"), "path/./current");
    }

    #[test]
    fn test_join_preserves_dangerous_patterns() {
        // Join does NOT sanitize - that's validation's job
        assert_eq!(join_unix("path", "$(whoami)"), "path/$(whoami)");
        assert_eq!(join_unix("path", "../../etc"), "path/../../etc");
    }
}
