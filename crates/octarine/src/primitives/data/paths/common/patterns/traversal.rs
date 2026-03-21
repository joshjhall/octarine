//! Path traversal detection patterns
//!
//! Core detection functions for directory traversal attacks.
//! These are pure functions with NO observe dependencies.
//!
//! ## Coverage
//!
//! - Basic traversal: `..` sequences
//! - Encoded traversal: `%2e%2e`, `%2f`, `%5c`
//! - Absolute path attempts: `/`, `\`, drive letters
//!
//! ## Design Principles
//!
//! 1. **Pure Functions**: No logging, no side effects
//! 2. **Detection Only**: Returns bool, no Result types
//! 3. **Reusable**: Used by validation and sanitization layers

use std::path::{Component, Path};

// ============================================================================
// Parent Directory Detection
// ============================================================================

/// Check if path contains parent directory references (..)
///
/// Uses `std::path::Path` for robust detection that correctly distinguishes
/// between `..` as a path component (traversal) and `..` within a filename
/// like `file..txt` (not traversal).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::traversal;
///
/// assert!(traversal::is_parent_references_present("../etc"));
/// assert!(traversal::is_parent_references_present("path/../etc"));
/// assert!(traversal::is_parent_references_present("../../etc"));
/// assert!(!traversal::is_parent_references_present("file.txt"));
/// assert!(!traversal::is_parent_references_present("file..txt")); // Not traversal
/// ```
#[must_use]
pub fn is_parent_references_present(path: &str) -> bool {
    for component in Path::new(path).components() {
        if matches!(component, Component::ParentDir) {
            return true;
        }
    }
    false
}

/// Count the number of parent directory references in a path
///
/// Returns the total count of `..` components, useful for OWASP-compliant
/// traversal depth limiting.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::traversal;
///
/// assert_eq!(traversal::count_parent_references("../etc"), 1);
/// assert_eq!(traversal::count_parent_references("../../etc"), 2);
/// assert_eq!(traversal::count_parent_references("a/../b/../c"), 2);
/// assert_eq!(traversal::count_parent_references("file.txt"), 0);
/// ```
#[must_use]
pub fn count_parent_references(path: &str) -> usize {
    Path::new(path)
        .components()
        .filter(|c| matches!(c, Component::ParentDir))
        .count()
}

// ============================================================================
// Absolute Path Detection
// ============================================================================

/// Check if path attempts to use absolute paths
///
/// Detects:
/// - Unix absolute: `/path`
/// - Windows UNC: `\\server\share`
/// - Windows drive: `C:\path`, `D:/path`
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::traversal;
///
/// assert!(traversal::is_absolute_path_present("/etc/passwd"));
/// assert!(traversal::is_absolute_path_present("\\\\server\\share"));
/// assert!(traversal::is_absolute_path_present("C:\\Windows"));
/// assert!(traversal::is_absolute_path_present("D:/Users"));
/// assert!(!traversal::is_absolute_path_present("relative/path"));
/// ```
#[must_use]
pub fn is_absolute_path_present(path: &str) -> bool {
    // Check standard absolute path detection
    if Path::new(path).is_absolute() {
        return true;
    }

    // Unix absolute
    if path.starts_with('/') {
        return true;
    }

    // Windows UNC or absolute backslash
    if path.starts_with('\\') {
        return true;
    }

    // Windows drive letter (C:, D:, etc.)
    // Pattern: single letter followed by colon
    if path.len() >= 2 {
        let mut chars = path.chars();
        if let (Some(first), Some(second)) = (chars.next(), chars.next())
            && first.is_ascii_alphabetic()
            && second == ':'
        {
            return true;
        }
    }

    false
}

// ============================================================================
// Encoded Traversal Detection
// ============================================================================

/// Check for URL-encoded traversal sequences
///
/// Detects percent-encoded path separators and dots:
/// - `%2e` or `%2E` = `.`
/// - `%2f` or `%2F` = `/`
/// - `%5c` or `%5C` = `\`
///
/// Single encoding is detected. For multiple/double encoding detection,
/// use [`super::encoding::has_multiple_encoding`].
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::traversal;
///
/// assert!(traversal::is_encoded_traversal_present("..%2f..%2fetc"));
/// assert!(traversal::is_encoded_traversal_present("%2e%2e%2f"));
/// assert!(traversal::is_encoded_traversal_present("path%5c.."));
/// assert!(traversal::is_encoded_traversal_present("%2E%2E")); // Uppercase
/// assert!(!traversal::is_encoded_traversal_present("normal/path"));
/// ```
#[must_use]
pub fn is_encoded_traversal_present(path: &str) -> bool {
    // Percent-encoded path separator or dot characters
    // Check for both lowercase and uppercase variants
    let path_lower = path.to_lowercase();

    path_lower.contains("%2e") // Encoded .
        || path_lower.contains("%2f") // Encoded /
        || path_lower.contains("%5c") // Encoded \
}

// ============================================================================
// Combined Detection
// ============================================================================

/// Check if path contains any form of traversal attempt
///
/// Comprehensive check combining:
/// - Parent directory references (`..`)
/// - Absolute path attempts
/// - Encoded traversal sequences
///
/// This is the primary traversal detection function.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::traversal;
///
/// assert!(traversal::is_any_traversal_present("../../../etc"));
/// assert!(traversal::is_any_traversal_present("/etc/passwd"));
/// assert!(traversal::is_any_traversal_present("path%2f..%2fetc"));
/// assert!(!traversal::is_any_traversal_present("safe/relative/path"));
/// ```
#[must_use]
pub fn is_any_traversal_present(path: &str) -> bool {
    is_parent_references_present(path)
        || is_absolute_path_present(path)
        || is_encoded_traversal_present(path)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Parent directory tests
    #[test]
    fn test_is_parent_references_present_basic() {
        assert!(is_parent_references_present("../etc"));
        assert!(is_parent_references_present("path/../etc"));
        assert!(is_parent_references_present("../../etc"));
        assert!(is_parent_references_present("a/b/c/../../../d"));
    }

    #[test]
    fn test_is_parent_references_present_safe() {
        assert!(!is_parent_references_present("file.txt"));
        assert!(!is_parent_references_present("path/to/file"));
        assert!(!is_parent_references_present("file..txt")); // Double dot in filename
        assert!(!is_parent_references_present("a.b.c.d"));
        assert!(!is_parent_references_present("...")); // Triple dot is not ParentDir
    }

    #[test]
    fn test_count_parent_references() {
        assert_eq!(count_parent_references("../etc"), 1);
        assert_eq!(count_parent_references("../../etc"), 2);
        assert_eq!(count_parent_references("../../../etc"), 3);
        assert_eq!(count_parent_references("a/../b/../c"), 2);
        assert_eq!(count_parent_references("file.txt"), 0);
        assert_eq!(count_parent_references("path/to/file"), 0);
    }

    // Absolute path tests
    #[test]
    fn test_is_absolute_path_present_unix() {
        assert!(is_absolute_path_present("/etc/passwd"));
        assert!(is_absolute_path_present("/"));
        assert!(is_absolute_path_present("/home/user/file.txt"));
    }

    #[test]
    fn test_is_absolute_path_present_windows() {
        assert!(is_absolute_path_present("C:\\Windows"));
        assert!(is_absolute_path_present("D:\\path"));
        assert!(is_absolute_path_present("C:/Users"));
        assert!(is_absolute_path_present("\\\\server\\share"));
        assert!(is_absolute_path_present("\\path"));
    }

    #[test]
    fn test_is_absolute_path_present_relative() {
        assert!(!is_absolute_path_present("relative/path"));
        assert!(!is_absolute_path_present("file.txt"));
        assert!(!is_absolute_path_present("./local"));
        assert!(!is_absolute_path_present("../parent"));
    }

    // Encoded traversal tests
    #[test]
    fn test_is_encoded_traversal_present_dot() {
        assert!(is_encoded_traversal_present("%2e%2e")); // ..
        assert!(is_encoded_traversal_present("%2E%2E")); // .. (uppercase)
        assert!(is_encoded_traversal_present("..%2e")); // mixed
    }

    #[test]
    fn test_is_encoded_traversal_present_separators() {
        assert!(is_encoded_traversal_present("..%2f..")); // ../..
        assert!(is_encoded_traversal_present("..%2F..")); // uppercase
        assert!(is_encoded_traversal_present("..%5c..")); // ..\..
        assert!(is_encoded_traversal_present("..%5C..")); // uppercase
    }

    #[test]
    fn test_is_encoded_traversal_present_safe() {
        assert!(!is_encoded_traversal_present("normal/path"));
        assert!(!is_encoded_traversal_present("file.txt"));
        assert!(!is_encoded_traversal_present("path/to/file"));
        assert!(!is_encoded_traversal_present("%20")); // Space encoding is fine
    }

    // Combined detection tests
    #[test]
    fn test_is_any_traversal_present() {
        // Parent references
        assert!(is_any_traversal_present("../etc"));
        assert!(is_any_traversal_present("../../passwd"));

        // Absolute paths
        assert!(is_any_traversal_present("/etc/passwd"));
        assert!(is_any_traversal_present("C:\\Windows"));

        // Encoded
        assert!(is_any_traversal_present("..%2fetc"));
        assert!(is_any_traversal_present("%2e%2e/etc"));
    }

    #[test]
    fn test_is_any_traversal_present_safe() {
        assert!(!is_any_traversal_present("safe/path"));
        assert!(!is_any_traversal_present("relative/path/file.txt"));
        assert!(!is_any_traversal_present("file.txt"));
        assert!(!is_any_traversal_present("./current"));
    }

    // Edge cases
    #[test]
    fn test_empty_and_edge_cases() {
        assert!(!is_parent_references_present(""));
        assert!(!is_absolute_path_present(""));
        assert!(!is_encoded_traversal_present(""));
        assert!(!is_any_traversal_present(""));

        // Single characters
        assert!(!is_parent_references_present("."));
        assert!(is_absolute_path_present("/")); // Root is absolute
        assert!(!is_encoded_traversal_present("."));
    }

    #[test]
    fn test_current_directory() {
        // Current directory (.) is NOT a traversal attempt
        assert!(!is_parent_references_present("./file.txt"));
        assert!(!is_parent_references_present("./path/./file"));
        assert_eq!(count_parent_references("./file.txt"), 0);
    }
}
