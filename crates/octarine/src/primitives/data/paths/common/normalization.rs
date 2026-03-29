// Allow clippy lints that are overly strict for this utility module
#![allow(clippy::manual_strip)]

//! Path normalization utilities
//!
//! Functions for normalizing path format (separators, redundancy, trailing).
//! These are pure functions with NO observe dependencies.
//!
//! ## Coverage
//!
//! - Separator normalization: `/` ↔ `\`
//! - Redundant separator removal: `//` → `/`
//! - Trailing separator handling
//! - Current directory (`.`) simplification
//!
//! ## Design Principles
//!
//! 1. **Pure Functions**: No logging, no side effects
//! 2. **Format Transformation Only**: Does NOT validate or sanitize
//! 3. **Preserves Security Patterns**: Does NOT remove attack vectors
//! 4. **Zero-Copy Where Possible**: Uses `Cow<str>` for efficiency
//!
//! ## Important: Separation of Concerns
//!
//! **Normalization is NOT sanitization!**
//!
//! Normalization transforms format (separators, redundancy) but must
//! PRESERVE dangerous patterns for the validation layer to detect:
//!
//! ```ignore
//! // Normalization preserves attack vectors
//! normalize_separators("path\\$(whoami)\\file")
//!     // Returns: "path/$(whoami)/file"
//!     // Command injection PRESERVED for validation layer
//!
//! normalize_separators("path\\..\\..\\etc")
//!     // Returns: "path/../../etc"
//!     // Traversal PRESERVED for validation layer
//! ```
//!
//! If normalization removed attacks, validation would never see them!

use std::borrow::Cow;

// ============================================================================
// Detection Functions
// ============================================================================

/// Check if path has mixed separators
///
/// Detects paths using both forward and back slashes.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::normalization;
///
/// assert!(normalization::is_mixed_separators_present("path/to\\file"));
/// assert!(!normalization::is_mixed_separators_present("path/to/file"));
/// ```
#[must_use]
pub fn is_mixed_separators_present(path: &str) -> bool {
    path.contains('/') && path.contains('\\')
}

/// Check if path has redundant separators
///
/// Detects consecutive separators (`//` or `\\\\`).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::normalization;
///
/// assert!(normalization::is_redundant_separators_present("path//to/file"));
/// assert!(normalization::is_redundant_separators_present("path\\\\to"));
/// assert!(!normalization::is_redundant_separators_present("path/to/file"));
/// ```
#[must_use]
pub fn is_redundant_separators_present(path: &str) -> bool {
    path.contains("//") || path.contains("\\\\")
}

/// Check if path has trailing separator
///
/// Detects paths ending with `/` or `\`.
/// Note: Root paths (`/` or `\`) are not considered to have trailing separators.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::normalization;
///
/// assert!(normalization::is_trailing_separator_present("path/to/dir/"));
/// assert!(!normalization::is_trailing_separator_present("path/to/file"));
/// assert!(!normalization::is_trailing_separator_present("/")); // Root is OK
/// ```
#[must_use]
pub fn is_trailing_separator_present(path: &str) -> bool {
    path.len() > 1 && (path.ends_with('/') || path.ends_with('\\'))
}

/// Check if path needs any normalization
///
/// Returns `true` if path has:
/// - Mixed separators
/// - Redundant separators
/// - Trailing separators
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::normalization;
///
/// assert!(normalization::needs_normalization("path//to\\file/"));
/// assert!(!normalization::needs_normalization("path/to/file"));
/// ```
#[must_use]
pub fn needs_normalization(path: &str) -> bool {
    is_mixed_separators_present(path)
        || is_redundant_separators_present(path)
        || is_trailing_separator_present(path)
}

// ============================================================================
// Separator Normalization
// ============================================================================

/// Normalize all separators to forward slashes
///
/// Converts backslashes to forward slashes for consistent Unix-style paths.
/// Returns `Cow::Borrowed` if no changes needed.
///
/// **Note**: This does NOT remove dangerous patterns. Command injection
/// and traversal patterns are preserved for validation.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::normalization;
///
/// assert_eq!(normalization::to_forward_slashes("path\\to\\file"), "path/to/file");
/// assert_eq!(normalization::to_forward_slashes("path/to/file"), "path/to/file"); // No change
/// ```
#[must_use]
pub fn to_forward_slashes(path: &str) -> Cow<'_, str> {
    if path.contains('\\') {
        Cow::Owned(path.replace('\\', "/"))
    } else {
        Cow::Borrowed(path)
    }
}

/// Normalize all separators to backslashes
///
/// Converts forward slashes to backslashes for Windows-style paths.
/// Returns `Cow::Borrowed` if no changes needed.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::normalization;
///
/// assert_eq!(normalization::to_backslashes("path/to/file"), "path\\to\\file");
/// assert_eq!(normalization::to_backslashes("path\\to\\file"), "path\\to\\file"); // No change
/// ```
#[must_use]
pub fn to_backslashes(path: &str) -> Cow<'_, str> {
    if path.contains('/') {
        Cow::Owned(path.replace('/', "\\"))
    } else {
        Cow::Borrowed(path)
    }
}

// ============================================================================
// Redundant Separator Removal
// ============================================================================

/// Strip redundant forward slashes
///
/// Converts sequences of `//` to single `/`.
/// Preserves leading `/` for absolute paths.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::normalization;
///
/// assert_eq!(normalization::strip_redundant_forward_slashes("path//to///file"), "path/to/file");
/// assert_eq!(normalization::strip_redundant_forward_slashes("//root"), "/root"); // Preserves one leading /
/// ```
#[must_use]
pub fn strip_redundant_forward_slashes(path: &str) -> Cow<'_, str> {
    if !path.contains("//") {
        return Cow::Borrowed(path);
    }

    let mut result = String::with_capacity(path.len());
    let mut prev_was_slash = false;

    for ch in path.chars() {
        if ch == '/' {
            if !prev_was_slash {
                result.push(ch);
            }
            prev_was_slash = true;
        } else {
            result.push(ch);
            prev_was_slash = false;
        }
    }

    Cow::Owned(result)
}

/// Strip redundant backslashes
///
/// Converts sequences of `\\\\` to single `\\`.
/// Preserves UNC path prefix (`\\\\server`).
///
/// **Note**: UNC paths start with exactly two backslashes. This function
/// preserves the UNC prefix while removing redundant backslashes elsewhere.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::normalization;
///
/// assert_eq!(normalization::strip_redundant_backslashes("path\\\\to\\\\\\file"), "path\\to\\file");
/// ```
#[must_use]
pub fn strip_redundant_backslashes(path: &str) -> Cow<'_, str> {
    if !path.contains("\\\\") {
        return Cow::Borrowed(path);
    }

    // Handle UNC path prefix specially
    let (prefix, rest) = if path.starts_with("\\\\") {
        // Find end of UNC prefix (\\server\share)
        ("\\\\", &path[2..])
    } else {
        ("", path)
    };

    let mut result = String::with_capacity(path.len());
    result.push_str(prefix);

    let mut prev_was_backslash = false;
    for ch in rest.chars() {
        if ch == '\\' {
            if !prev_was_backslash {
                result.push(ch);
            }
            prev_was_backslash = true;
        } else {
            result.push(ch);
            prev_was_backslash = false;
        }
    }

    Cow::Owned(result)
}

/// Strip all redundant separators (both forward and back)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::normalization;
///
/// assert_eq!(normalization::strip_redundant_separators("path//to\\\\file"), "path/to\\file");
/// ```
#[must_use]
pub fn strip_redundant_separators(path: &str) -> Cow<'_, str> {
    let result = strip_redundant_forward_slashes(path);
    match strip_redundant_backslashes(&result) {
        Cow::Borrowed(_) => result,
        Cow::Owned(s) => Cow::Owned(s),
    }
}

// ============================================================================
// Trailing Separator Handling
// ============================================================================

/// Strip trailing separator from path
///
/// Removes trailing `/` or `\` from path.
/// Does not modify root paths (`/` or `\`).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::normalization;
///
/// assert_eq!(normalization::strip_trailing_separator("path/to/dir/"), "path/to/dir");
/// assert_eq!(normalization::strip_trailing_separator("/"), "/"); // Root unchanged
/// ```
#[must_use]
pub fn strip_trailing_separator(path: &str) -> &str {
    if path.len() > 1 {
        path.strip_suffix('/')
            .unwrap_or_else(|| path.strip_suffix('\\').unwrap_or(path))
    } else {
        path
    }
}

/// Ensure path has trailing separator
///
/// Adds trailing `/` if not present. For Windows-style paths with
/// only backslashes, adds `\` instead.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::normalization;
///
/// assert_eq!(normalization::ensure_trailing_separator("path/to/dir"), "path/to/dir/");
/// assert_eq!(normalization::ensure_trailing_separator("path\\to\\dir"), "path\\to\\dir\\");
/// assert_eq!(normalization::ensure_trailing_separator("path/to/dir/"), "path/to/dir/"); // Unchanged
/// ```
#[must_use]
pub fn ensure_trailing_separator(path: &str) -> Cow<'_, str> {
    if path.ends_with('/') || path.ends_with('\\') {
        Cow::Borrowed(path)
    } else if path.contains('\\') && !path.contains('/') {
        // Windows-style path
        Cow::Owned(format!("{}\\", path))
    } else {
        // Unix-style or mixed (default to forward slash)
        Cow::Owned(format!("{}/", path))
    }
}

// ============================================================================
// Full Normalization
// ============================================================================

/// Fully normalize path to Unix-style
///
/// Applies all normalizations:
/// 1. Convert backslashes to forward slashes
/// 2. Remove redundant slashes
/// 3. Remove trailing separator (optional)
///
/// **Note**: Does NOT remove dangerous patterns (traversal, injection).
/// Those are preserved for the validation layer.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::normalization;
///
/// assert_eq!(normalization::normalize_unix("path\\\\to//file/"), "path/to/file");
/// ```
#[must_use]
pub fn normalize_unix(path: &str) -> Cow<'_, str> {
    // Step 1: Convert separators
    let result = to_forward_slashes(path);

    // Step 2: Remove redundant
    let result = match strip_redundant_forward_slashes(&result) {
        Cow::Borrowed(_) => result,
        Cow::Owned(s) => Cow::Owned(s),
    };

    // Step 3: Remove trailing
    let trimmed = strip_trailing_separator(&result);
    if trimmed.len() != result.len() {
        Cow::Owned(trimmed.to_string())
    } else {
        result
    }
}

/// Fully normalize path to Windows-style
///
/// Applies all normalizations:
/// 1. Convert forward slashes to backslashes
/// 2. Remove redundant slashes
/// 3. Remove trailing separator (optional)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::normalization;
///
/// assert_eq!(normalization::normalize_windows("path//to\\\\file\\"), "path\\to\\file");
/// ```
#[must_use]
pub fn normalize_windows(path: &str) -> Cow<'_, str> {
    // Step 1: Convert separators
    let result = to_backslashes(path);

    // Step 2: Remove redundant
    let result = match strip_redundant_backslashes(&result) {
        Cow::Borrowed(_) => result,
        Cow::Owned(s) => Cow::Owned(s),
    };

    // Step 3: Remove trailing
    let trimmed = strip_trailing_separator(&result);
    if trimmed.len() != result.len() {
        Cow::Owned(trimmed.to_string())
    } else {
        result
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Detection tests
    #[test]
    fn test_is_mixed_separators_present() {
        assert!(is_mixed_separators_present("path/to\\file"));
        assert!(is_mixed_separators_present("C:\\Users/file"));
        assert!(!is_mixed_separators_present("path/to/file"));
        assert!(!is_mixed_separators_present("path\\to\\file"));
        assert!(!is_mixed_separators_present("file.txt"));
    }

    #[test]
    fn test_is_redundant_separators_present() {
        assert!(is_redundant_separators_present("path//to/file"));
        assert!(is_redundant_separators_present("path///file"));
        assert!(is_redundant_separators_present("path\\\\to\\file"));
        assert!(!is_redundant_separators_present("path/to/file"));
        assert!(!is_redundant_separators_present("path\\to\\file"));
    }

    #[test]
    fn test_is_trailing_separator_present() {
        assert!(is_trailing_separator_present("path/to/dir/"));
        assert!(is_trailing_separator_present("path\\to\\dir\\"));
        assert!(!is_trailing_separator_present("path/to/file"));
        assert!(!is_trailing_separator_present("/")); // Root
        assert!(!is_trailing_separator_present("\\")); // Root
    }

    #[test]
    fn test_needs_normalization() {
        assert!(needs_normalization("path//to\\file/"));
        assert!(needs_normalization("path/to/"));
        assert!(needs_normalization("path//file"));
        assert!(needs_normalization("path/to\\file"));
        assert!(!needs_normalization("path/to/file"));
    }

    // Separator normalization tests
    #[test]
    fn test_to_forward_slashes() {
        assert_eq!(
            to_forward_slashes("path\\to\\file").as_ref(),
            "path/to/file"
        );
        assert_eq!(
            to_forward_slashes("C:\\Windows\\System32").as_ref(),
            "C:/Windows/System32"
        );
        // No change cases - should return Borrowed
        let result = to_forward_slashes("path/to/file");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn test_to_backslashes() {
        assert_eq!(to_backslashes("path/to/file").as_ref(), "path\\to\\file");
        // No change cases
        let result = to_backslashes("path\\to\\file");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    // Redundant separator tests
    #[test]
    fn test_strip_redundant_forward_slashes() {
        assert_eq!(
            strip_redundant_forward_slashes("path//to///file").as_ref(),
            "path/to/file"
        );
        assert_eq!(
            strip_redundant_forward_slashes("//root/path").as_ref(),
            "/root/path"
        );
        // No change cases
        let result = strip_redundant_forward_slashes("path/to/file");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn test_strip_redundant_backslashes() {
        assert_eq!(
            strip_redundant_backslashes("path\\\\to\\\\\\file").as_ref(),
            "path\\to\\file"
        );
        // UNC path preservation
        assert_eq!(
            strip_redundant_backslashes("\\\\server\\\\share").as_ref(),
            "\\\\server\\share"
        );
    }

    // Trailing separator tests
    #[test]
    fn test_strip_trailing_separator() {
        assert_eq!(strip_trailing_separator("path/to/dir/"), "path/to/dir");
        assert_eq!(strip_trailing_separator("path\\to\\dir\\"), "path\\to\\dir");
        assert_eq!(strip_trailing_separator("/"), "/"); // Root unchanged
        assert_eq!(strip_trailing_separator("\\"), "\\"); // Root unchanged
        assert_eq!(strip_trailing_separator("path"), "path"); // No trailing
    }

    #[test]
    fn test_ensure_trailing_separator() {
        assert_eq!(
            ensure_trailing_separator("path/to/dir").as_ref(),
            "path/to/dir/"
        );
        assert_eq!(
            ensure_trailing_separator("path\\to\\dir").as_ref(),
            "path\\to\\dir\\"
        );
        // Already has trailing
        let result = ensure_trailing_separator("path/to/dir/");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    // Full normalization tests
    #[test]
    fn test_normalize_unix() {
        assert_eq!(normalize_unix("path\\\\to//file/").as_ref(), "path/to/file");
        assert_eq!(
            normalize_unix("C:\\Windows\\System32").as_ref(),
            "C:/Windows/System32"
        );
        // Already normalized
        let result = normalize_unix("path/to/file");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn test_normalize_windows() {
        assert_eq!(
            normalize_windows("path//to\\\\file\\").as_ref(),
            "path\\to\\file"
        );
    }

    // Security preservation tests
    #[test]
    fn test_preserves_traversal_patterns() {
        // Normalization must NOT remove traversal patterns
        assert_eq!(
            normalize_unix("path\\..\\..\\etc").as_ref(),
            "path/../../etc"
        );
        assert!(normalize_unix("path\\..\\..\\etc").contains(".."));
    }

    #[test]
    fn test_preserves_injection_patterns() {
        // Normalization must NOT remove injection patterns
        assert_eq!(
            normalize_unix("path\\$(whoami)\\file").as_ref(),
            "path/$(whoami)/file"
        );
        assert!(normalize_unix("path\\$(whoami)\\file").contains("$("));
    }

    // Edge cases
    #[test]
    fn test_empty_string() {
        assert!(!is_mixed_separators_present(""));
        assert!(!is_redundant_separators_present(""));
        assert!(!is_trailing_separator_present(""));
        assert!(!needs_normalization(""));
        assert_eq!(to_forward_slashes("").as_ref(), "");
        assert_eq!(normalize_unix("").as_ref(), "");
    }

    #[test]
    fn test_single_separators() {
        assert_eq!(to_forward_slashes("\\").as_ref(), "/");
        assert_eq!(to_backslashes("/").as_ref(), "\\");
        assert!(!is_trailing_separator_present("/")); // Root is special
    }

    #[test]
    fn test_only_separators() {
        assert_eq!(normalize_unix("////").as_ref(), "/");
        assert_eq!(normalize_unix("\\\\\\\\").as_ref(), "/");
    }
}
