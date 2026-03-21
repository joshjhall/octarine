//! Boundary validation for path containment
//!
//! Pure validation functions to check if paths stay within designated boundaries.
//! These are **Layer 1 primitives** with NO observe dependencies.
//!
//! ## Security Standards
//!
//! Follows OWASP directory jailing guidelines:
//! - Validate paths stay within boundaries
//! - Detect escape attempts via traversal
//! - Handle both absolute and relative paths
//!
//! ## Dual Function Pattern
//!
//! Every validation has two versions:
//! - **Lenient** (returns `bool`): Quick check for conditionals
//! - **Strict** (returns `Result`): Detailed error information
//!
//! ## Important: Pure Path Operations
//!
//! These functions perform **logical** validation (string manipulation).
//! They do NOT:
//! - Access the filesystem
//! - Resolve symlinks
//! - Verify path existence
//!
//! For filesystem-aware validation, use higher-level security modules.

use crate::primitives::types::Problem;
use std::path::{Component, Path};

// ============================================================================
// Result Type
// ============================================================================

/// Result of boundary validation
pub type ValidationResult = Result<(), Problem>;

// ============================================================================
// Core Validation Functions
// ============================================================================

/// Check if a path stays within a boundary (lenient)
///
/// Returns `true` if the path would remain within the boundary directory.
/// This performs a logical check without filesystem access.
///
/// ## Algorithm
///
/// 1. For absolute paths: Check if path starts with boundary
/// 2. For relative paths: Track depth and ensure it never goes negative
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::validation;
///
/// // Safe relative paths
/// assert!(validation::is_within_boundary("file.txt", "/app/data"));
/// assert!(validation::is_within_boundary("subdir/file.txt", "/app/data"));
///
/// // Traversal attempts
/// assert!(!validation::is_within_boundary("../secret", "/app/data"));
/// assert!(!validation::is_within_boundary("../../etc/passwd", "/app/data"));
///
/// // Absolute paths
/// assert!(!validation::is_within_boundary("/etc/passwd", "/app/data"));
/// assert!(validation::is_within_boundary("/app/data/file.txt", "/app/data"));
/// ```
#[must_use]
pub fn is_within_boundary(path: &str, boundary: &str) -> bool {
    validate_within_boundary_strict(path, boundary).is_ok()
}

/// Validate path stays within boundary (strict)
///
/// Returns `Ok(())` if path stays within boundary, or `Err(Problem)` with details.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::validation;
///
/// assert!(validation::validate_within_boundary_strict("file.txt", "/app").is_ok());
/// assert!(validation::validate_within_boundary_strict("../escape", "/app").is_err());
/// ```
pub fn validate_within_boundary_strict(path: &str, boundary: &str) -> ValidationResult {
    // Validate boundary first
    validate_boundary_specification_strict(boundary)?;

    // Check for empty path
    if path.is_empty() {
        return Err(Problem::validation("Path cannot be empty"));
    }

    // Convert to Path objects for component analysis
    let path_obj = Path::new(path);
    let boundary_obj = Path::new(boundary);

    // Handle absolute paths
    if path_obj.is_absolute() {
        // Absolute path must start with boundary
        if path_obj.starts_with(boundary_obj) {
            return Ok(());
        }
        return Err(Problem::validation(format!(
            "Absolute path '{}' is outside boundary '{}'",
            path, boundary
        )));
    }

    // For relative paths, track depth to detect escape attempts
    let mut depth: i32 = 0;

    for component in path_obj.components() {
        match component {
            Component::ParentDir => {
                depth = depth.saturating_sub(1);
                // If we go negative, we're trying to escape the boundary
                if depth < 0 {
                    return Err(Problem::validation(format!(
                        "Path '{}' attempts to escape boundary via traversal",
                        path
                    )));
                }
            }
            Component::Normal(_) => {
                depth = depth.saturating_add(1);
            }
            Component::CurDir => {
                // Current directory, no change in depth
            }
            Component::RootDir | Component::Prefix(_) => {
                // These indicate absolute path, should have been caught above
                return Err(Problem::validation(format!(
                    "Path '{}' contains unexpected root/prefix component",
                    path
                )));
            }
        }
    }

    Ok(())
}

// ============================================================================
// Boundary Specification Validation
// ============================================================================

/// Check if boundary specification is valid (lenient)
///
/// A valid boundary must:
/// - Not be empty
/// - Not contain null bytes
/// - Be an absolute path
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::validation;
///
/// assert!(validation::is_valid_boundary("/app/data"));
/// assert!(!validation::is_valid_boundary("")); // Empty
/// assert!(!validation::is_valid_boundary("relative/path")); // Not absolute
/// assert!(!validation::is_valid_boundary("/path\0null")); // Contains null
/// ```
#[must_use]
pub fn is_valid_boundary(boundary: &str) -> bool {
    validate_boundary_specification_strict(boundary).is_ok()
}

/// Validate boundary specification (strict)
///
/// Returns detailed error if boundary is invalid.
pub fn validate_boundary_specification_strict(boundary: &str) -> ValidationResult {
    if boundary.is_empty() {
        return Err(Problem::validation("Boundary cannot be empty"));
    }

    if boundary.contains('\0') {
        return Err(Problem::validation("Boundary contains null bytes"));
    }

    if !Path::new(boundary).is_absolute() {
        return Err(Problem::validation("Boundary must be an absolute path"));
    }

    Ok(())
}

// ============================================================================
// Escape Detection
// ============================================================================

/// Check if path would escape the boundary (lenient)
///
/// Convenience function that inverts the boundary check.
/// Returns `true` if the path attempts to escape.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::validation;
///
/// assert!(validation::would_escape_boundary("../secret", "/app/data"));
/// assert!(!validation::would_escape_boundary("file.txt", "/app/data"));
/// ```
#[must_use]
pub fn would_escape_boundary(path: &str, boundary: &str) -> bool {
    !is_within_boundary(path, boundary)
}

/// Calculate the escape depth of a path
///
/// Returns how many directory levels the path would escape.
/// Returns 0 if the path stays within the boundary.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::validation;
///
/// assert_eq!(validation::calculate_escape_depth("../file.txt", "/app"), 1);
/// assert_eq!(validation::calculate_escape_depth("../../etc", "/app"), 2);
/// assert_eq!(validation::calculate_escape_depth("file.txt", "/app"), 0);
/// assert_eq!(validation::calculate_escape_depth("dir/../../../etc", "/app"), 2);
/// ```
#[must_use]
pub fn calculate_escape_depth(path: &str, boundary: &str) -> usize {
    // Validate boundary first
    if validate_boundary_specification_strict(boundary).is_err() {
        return 0;
    }

    if path.is_empty() {
        return 0;
    }

    let path_obj = Path::new(path);

    // Absolute paths outside boundary have undefined escape depth
    if path_obj.is_absolute() {
        return 0;
    }

    // Track minimum depth reached (negative means escape)
    let mut depth: i32 = 0;
    let mut min_depth: i32 = 0;

    for component in path_obj.components() {
        match component {
            Component::ParentDir => {
                depth = depth.saturating_sub(1);
                min_depth = min_depth.min(depth);
            }
            Component::Normal(_) => {
                depth = depth.saturating_add(1);
            }
            Component::CurDir => {}
            _ => {}
        }
    }

    // Return how far below zero we went
    if min_depth < 0 {
        min_depth.unsigned_abs() as usize
    } else {
        0
    }
}

// ============================================================================
// Depth Calculation
// ============================================================================

/// Calculate the depth of a path within a boundary (lenient)
///
/// Returns `None` if path escapes the boundary.
/// Returns `Some(depth)` where depth is the number of directory levels.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::validation;
///
/// assert_eq!(validation::calculate_boundary_depth("file.txt", "/app"), Some(1));
/// assert_eq!(validation::calculate_boundary_depth("dir/file.txt", "/app"), Some(2));
/// assert_eq!(validation::calculate_boundary_depth("a/b/c", "/app"), Some(3));
/// assert_eq!(validation::calculate_boundary_depth("../etc", "/app"), None); // Escapes
/// ```
#[must_use]
pub fn calculate_boundary_depth(path: &str, boundary: &str) -> Option<usize> {
    calculate_boundary_depth_strict(path, boundary).ok()
}

/// Calculate the depth of a path within a boundary (strict)
///
/// Returns error if path escapes the boundary.
pub fn calculate_boundary_depth_strict(path: &str, boundary: &str) -> Result<usize, Problem> {
    // First ensure it's within the boundary
    validate_within_boundary_strict(path, boundary)?;

    let path_obj = Path::new(path);
    let mut depth: usize = 0;

    for component in path_obj.components() {
        match component {
            Component::Normal(_) => {
                depth = depth.saturating_add(1);
            }
            Component::ParentDir => {
                if depth > 0 {
                    depth = depth.saturating_sub(1);
                }
            }
            _ => {}
        }
    }

    Ok(depth)
}

/// Check if path is at the boundary root (lenient)
///
/// Returns true if path is a direct child of the boundary (depth 1).
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::validation;
///
/// assert!(validation::is_at_boundary_root("file.txt", "/app"));
/// assert!(!validation::is_at_boundary_root("subdir/file.txt", "/app"));
/// ```
#[must_use]
pub fn is_at_boundary_root(path: &str, boundary: &str) -> bool {
    calculate_boundary_depth(path, boundary) == Some(1)
}

/// Validate path is at boundary root (strict)
pub fn validate_at_boundary_root_strict(path: &str, boundary: &str) -> ValidationResult {
    let depth = calculate_boundary_depth_strict(path, boundary)?;

    if depth != 1 {
        return Err(Problem::validation(format!(
            "Path '{}' is not at the boundary root (depth: {})",
            path, depth
        )));
    }

    Ok(())
}

// ============================================================================
// Multiple Path Validation
// ============================================================================

/// Check if all paths are within the boundary (lenient)
///
/// Returns `true` only if ALL paths stay within the boundary.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::validation;
///
/// let safe_paths = &["file1.txt", "dir/file2.txt", "a/b/c.txt"];
/// let mixed_paths = &["file1.txt", "../escape.txt", "dir/file2.txt"];
///
/// assert!(validation::is_all_within_boundary(safe_paths, "/app"));
/// assert!(!validation::is_all_within_boundary(mixed_paths, "/app"));
/// ```
#[must_use]
pub fn is_all_within_boundary(paths: &[&str], boundary: &str) -> bool {
    validate_all_within_boundary_strict(paths, boundary).is_ok()
}

/// Validate all paths are within boundary (strict)
///
/// Returns error with details about first path that escapes.
pub fn validate_all_within_boundary_strict(paths: &[&str], boundary: &str) -> ValidationResult {
    // Validate boundary first
    validate_boundary_specification_strict(boundary)?;

    for (index, &path) in paths.iter().enumerate() {
        if let Err(e) = validate_within_boundary_strict(path, boundary) {
            return Err(Problem::validation(format!(
                "Path {} ('{}') violates boundary: {}",
                index, path, e
            )));
        }
    }

    Ok(())
}

// ============================================================================
// Boundary Nesting
// ============================================================================

/// Check if one boundary contains another (lenient)
///
/// Returns `true` if `inner` is contained within `outer`.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::validation;
///
/// assert!(validation::is_boundary_contained("/app", "/app/data"));
/// assert!(validation::is_boundary_contained("/app", "/app/data/user"));
/// assert!(!validation::is_boundary_contained("/app/data", "/app"));
/// ```
#[must_use]
pub fn is_boundary_contained(outer: &str, inner: &str) -> bool {
    validate_boundary_nesting_strict(outer, inner).is_ok()
}

/// Validate boundary nesting relationship (strict)
pub fn validate_boundary_nesting_strict(outer: &str, inner: &str) -> ValidationResult {
    // Validate both boundaries
    validate_boundary_specification_strict(outer)?;
    validate_boundary_specification_strict(inner)?;

    let outer_path = Path::new(outer);
    let inner_path = Path::new(inner);

    if !inner_path.starts_with(outer_path) {
        return Err(Problem::validation(format!(
            "Inner boundary '{}' is not contained within outer boundary '{}'",
            inner, outer
        )));
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ------------------------------------------------------------------------
    // Core Boundary Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_within_boundary_safe_relative() {
        assert!(is_within_boundary("file.txt", "/app/data"));
        assert!(is_within_boundary("subdir/file.txt", "/app/data"));
        assert!(is_within_boundary("a/b/c/file.txt", "/app/data"));
        assert!(is_within_boundary(".", "/app/data"));
        assert!(is_within_boundary("./file.txt", "/app/data"));
    }

    #[test]
    fn test_is_within_boundary_traversal() {
        assert!(!is_within_boundary("../file.txt", "/app/data"));
        assert!(!is_within_boundary("../../etc/passwd", "/app/data"));
        assert!(!is_within_boundary("dir/../../etc", "/app/data"));
        assert!(!is_within_boundary("a/../../../etc", "/app/data"));
    }

    #[test]
    fn test_is_within_boundary_complex_traversal() {
        // a/b/../c -> a/c - stays within boundary
        assert!(is_within_boundary("a/b/../c/file.txt", "/app"));
        // a/../a/file -> a/file - stays within boundary
        assert!(is_within_boundary("a/../a/file.txt", "/app"));
        // a/../../../etc -> escapes
        assert!(!is_within_boundary("a/../../../etc", "/app"));
    }

    #[test]
    fn test_is_within_boundary_absolute() {
        assert!(!is_within_boundary("/etc/passwd", "/app/data"));
        assert!(is_within_boundary("/app/data/file.txt", "/app/data"));
        assert!(is_within_boundary("/app/data/subdir/file.txt", "/app/data"));
    }

    #[test]
    fn test_validate_within_boundary_strict_errors() {
        let err = validate_within_boundary_strict("../escape", "/app").expect_err("test");
        assert!(err.to_string().contains("escape"));

        let err = validate_within_boundary_strict("", "/app").expect_err("test");
        assert!(err.to_string().contains("empty"));
    }

    // ------------------------------------------------------------------------
    // Boundary Specification Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_valid_boundary() {
        assert!(is_valid_boundary("/app/data"));
        assert!(is_valid_boundary("/"));
        assert!(!is_valid_boundary(""));
        assert!(!is_valid_boundary("relative/path"));
        assert!(!is_valid_boundary("/path\0null"));
    }

    #[test]
    fn test_validate_boundary_specification_strict_errors() {
        let err = validate_boundary_specification_strict("").expect_err("test");
        assert!(err.to_string().contains("empty"));

        let err = validate_boundary_specification_strict("relative").expect_err("test");
        assert!(err.to_string().contains("absolute"));

        let err = validate_boundary_specification_strict("/path\0").expect_err("test");
        assert!(err.to_string().contains("null"));
    }

    // ------------------------------------------------------------------------
    // Escape Detection Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_would_escape_boundary() {
        assert!(would_escape_boundary("../secret", "/app"));
        assert!(would_escape_boundary("../../etc", "/app"));
        assert!(!would_escape_boundary("file.txt", "/app"));
        assert!(!would_escape_boundary("dir/file.txt", "/app"));
    }

    #[test]
    fn test_calculate_escape_depth() {
        assert_eq!(calculate_escape_depth("file.txt", "/app"), 0);
        assert_eq!(calculate_escape_depth("dir/file.txt", "/app"), 0);
        assert_eq!(calculate_escape_depth("../file.txt", "/app"), 1);
        assert_eq!(calculate_escape_depth("../../etc", "/app"), 2);
        assert_eq!(calculate_escape_depth("../../../passwd", "/app"), 3);
        // Complex: a/../../../etc = -2 levels (a brings to 1, then -3)
        assert_eq!(calculate_escape_depth("a/../../../etc", "/app"), 2);
    }

    // ------------------------------------------------------------------------
    // Depth Calculation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_calculate_boundary_depth() {
        assert_eq!(calculate_boundary_depth("file.txt", "/app"), Some(1));
        assert_eq!(calculate_boundary_depth("dir/file.txt", "/app"), Some(2));
        assert_eq!(calculate_boundary_depth("a/b/c", "/app"), Some(3));
        assert_eq!(calculate_boundary_depth("a/b/c/d/e", "/app"), Some(5));
        assert_eq!(calculate_boundary_depth("../etc", "/app"), None); // Escapes
    }

    #[test]
    fn test_calculate_boundary_depth_with_traversal() {
        // a/b/../c/file.txt = a/c/file.txt = depth 3
        assert_eq!(
            calculate_boundary_depth("a/b/../c/file.txt", "/app"),
            Some(3)
        );
        // a/../b/c = b/c = depth 2
        assert_eq!(calculate_boundary_depth("a/../b/c", "/app"), Some(2));
    }

    #[test]
    fn test_is_at_boundary_root() {
        assert!(is_at_boundary_root("file.txt", "/app"));
        assert!(is_at_boundary_root("document.pdf", "/app"));
        assert!(!is_at_boundary_root("subdir/file.txt", "/app"));
        assert!(!is_at_boundary_root("a/b/file.txt", "/app"));
        assert!(!is_at_boundary_root("../outside.txt", "/app"));
    }

    // ------------------------------------------------------------------------
    // Multiple Path Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_all_within_boundary() {
        let safe_paths = &["file1.txt", "dir/file2.txt", "a/b/c.txt"];
        assert!(is_all_within_boundary(safe_paths, "/app"));

        let mixed_paths = &["file1.txt", "../escape.txt", "dir/file2.txt"];
        assert!(!is_all_within_boundary(mixed_paths, "/app"));

        let empty_paths: &[&str] = &[];
        assert!(is_all_within_boundary(empty_paths, "/app"));
    }

    #[test]
    fn test_validate_all_within_boundary_strict_error() {
        let paths = &["file.txt", "../escape", "other.txt"];
        let err = validate_all_within_boundary_strict(paths, "/app").expect_err("test");
        assert!(err.to_string().contains("1")); // Index 1 is the violator
        assert!(err.to_string().contains("../escape"));
    }

    // ------------------------------------------------------------------------
    // Boundary Nesting Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_boundary_contained() {
        assert!(is_boundary_contained("/app", "/app/data"));
        assert!(is_boundary_contained("/app", "/app/data/user"));
        assert!(is_boundary_contained("/", "/app"));
        assert!(!is_boundary_contained("/app/data", "/app"));
        assert!(!is_boundary_contained("/app", "/var"));
    }

    #[test]
    fn test_validate_boundary_nesting_strict() {
        assert!(validate_boundary_nesting_strict("/app", "/app/data").is_ok());

        let err = validate_boundary_nesting_strict("/app", "/var").expect_err("test");
        assert!(err.to_string().contains("not contained"));
    }

    // ------------------------------------------------------------------------
    // Edge Cases
    // ------------------------------------------------------------------------

    #[test]
    fn test_empty_path() {
        assert!(!is_within_boundary("", "/app"));
        assert!(validate_within_boundary_strict("", "/app").is_err());
    }

    #[test]
    fn test_root_boundary() {
        assert!(is_within_boundary("file.txt", "/"));
        assert!(is_within_boundary("/etc/passwd", "/"));
    }

    #[test]
    fn test_current_directory() {
        assert!(is_within_boundary(".", "/app"));
        assert!(is_within_boundary("./", "/app"));
        assert!(is_within_boundary("./file.txt", "/app"));
    }

    #[test]
    fn test_windows_style_paths() {
        // On Windows, backslash is a path separator, so ..\ is traversal
        // On Unix, backslash is a valid filename character, so ..\file.txt is a filename
        // We test the forward slash version which works consistently
        assert!(!is_within_boundary("../file.txt", "/app"));

        // Note: Cross-platform path handling is done in the format module.
        // For security, prefer normalizing paths to forward slashes first.
    }
}
