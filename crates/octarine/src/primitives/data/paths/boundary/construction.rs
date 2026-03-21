//! Boundary-safe path construction
//!
//! Pure construction functions for safely joining and resolving paths
//! within designated boundaries. These are **Layer 1 primitives** with
//! NO observe dependencies.
//!
//! ## Security Standards
//!
//! Follows OWASP directory jailing guidelines:
//! - Validate inputs before construction
//! - Check for injection patterns
//! - Verify results stay within boundary
//!
//! ## Important: Pure Path Operations
//!
//! These functions perform **logical** construction (string manipulation).
//! They do NOT:
//! - Access the filesystem
//! - Resolve symlinks
//! - Verify path existence
//!
//! For filesystem-aware construction, use higher-level security modules.

use super::super::common::{
    clean_path, is_any_injection_present, is_control_characters_present, is_null_bytes_present,
    is_shell_metacharacters_present,
};
use super::{sanitization, validation};
use crate::primitives::types::Problem;

// ============================================================================
// Result Type
// ============================================================================

/// Result of boundary construction
pub type ConstructionResult = Result<String, Problem>;

// ============================================================================
// Safe Join Operations
// ============================================================================

/// Join a base path and segment within a boundary (strict)
///
/// Validates both inputs and the result, ensuring the final path
/// stays within the boundary.
///
/// ## Security Checks
///
/// 1. Validates boundary specification
/// 2. Checks base and segment for injection patterns
/// 3. Checks for null bytes and control characters
/// 4. Validates result stays within boundary
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::construction;
///
/// let result = construction::join_within_boundary_strict(
///     "/app/data",
///     "docs",
///     "file.txt"
/// );
/// assert_eq!(result.expect("test"), "/app/data/docs/file.txt");
///
/// // Traversal in segment rejected
/// let result = construction::join_within_boundary_strict(
///     "/app/data",
///     "docs",
///     "../../../etc/passwd"
/// );
/// assert!(result.is_err());
/// ```
pub fn join_within_boundary_strict(
    boundary: &str,
    base: &str,
    segment: &str,
) -> ConstructionResult {
    // Validate boundary
    validation::validate_boundary_specification_strict(boundary)?;

    // Validate inputs for security issues
    validate_path_input(base, "Base")?;
    validate_path_input(segment, "Segment")?;

    // Validate boundary for injection
    if is_any_injection_present(boundary) {
        return Err(Problem::validation(
            "Boundary contains command injection patterns",
        ));
    }

    // Validate base is within boundary (or is the boundary)
    if !base.is_empty() && base != boundary && !base.starts_with(boundary) {
        // Base is relative, check it
        validation::validate_within_boundary_strict(base, boundary)?;
    }

    // Join the paths
    let joined = if base.is_empty() || base == boundary {
        format!("{}/{}", boundary.trim_end_matches('/'), segment)
    } else if base.starts_with(boundary) {
        format!("{}/{}", base.trim_end_matches('/'), segment)
    } else {
        format!(
            "{}/{}/{}",
            boundary.trim_end_matches('/'),
            base.trim_end_matches('/').trim_start_matches('/'),
            segment
        )
    };

    // Simplify (resolve . and ..)
    let simplified = clean_path(&joined);

    // Validate result stays within boundary
    if !simplified.starts_with(boundary) {
        return Err(Problem::validation(format!(
            "Result '{}' escapes boundary '{}'",
            simplified, boundary
        )));
    }

    // Final validation - check the relative part
    if let Some(relative) = simplified.strip_prefix(boundary) {
        let relative = relative.trim_start_matches('/');
        if !relative.is_empty() {
            validation::validate_within_boundary_strict(relative, boundary)?;
        }
    }

    Ok(simplified)
}

/// Join a base path and segment within a boundary (lenient)
///
/// Always returns a path within the boundary. If the operation would
/// escape the boundary, returns the base path (or boundary if base is invalid).
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::construction;
///
/// // Safe join
/// assert_eq!(
///     construction::join_within_boundary("/app", "docs", "file.txt"),
///     "/app/docs/file.txt"
/// );
///
/// // Escape attempt returns base
/// let result = construction::join_within_boundary("/app", "docs", "../../../etc");
/// assert!(result.starts_with("/app"));
/// ```
#[must_use]
pub fn join_within_boundary(boundary: &str, base: &str, segment: &str) -> String {
    match join_within_boundary_strict(boundary, base, segment) {
        Ok(path) => path,
        Err(_) => {
            // Return safest option: base if valid, otherwise boundary
            if base.starts_with(boundary) {
                base.to_string()
            } else if !boundary.is_empty() {
                boundary.to_string()
            } else {
                "/".to_string()
            }
        }
    }
}

// ============================================================================
// Safe Resolve Operations
// ============================================================================

/// Resolve a relative path against a base within a boundary (strict)
///
/// Resolves `path` relative to `base`, then validates the result
/// stays within the boundary. If `path` is absolute, validates it
/// directly against the boundary.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::construction;
///
/// // Relative resolution
/// let result = construction::resolve_relative_within_strict(
///     "/app",
///     "/app/docs",
///     "images/photo.jpg"
/// );
/// assert_eq!(result.expect("test"), "/app/docs/images/photo.jpg");
///
/// // Parent resolution within boundary
/// let result = construction::resolve_relative_within_strict(
///     "/app",
///     "/app/docs/reports",
///     "../images/photo.jpg"
/// );
/// assert_eq!(result.expect("test"), "/app/docs/images/photo.jpg");
///
/// // Escape attempt rejected
/// let result = construction::resolve_relative_within_strict(
///     "/app",
///     "/app/docs",
///     "../../../etc/passwd"
/// );
/// assert!(result.is_err());
/// ```
pub fn resolve_relative_within_strict(
    boundary: &str,
    base: &str,
    path: &str,
) -> ConstructionResult {
    // Validate boundary
    validation::validate_boundary_specification_strict(boundary)?;

    // Validate inputs
    validate_path_input(base, "Base")?;
    validate_path_input(path, "Path")?;

    // Validate boundary for injection
    if is_any_injection_present(boundary) {
        return Err(Problem::validation(
            "Boundary contains command injection patterns",
        ));
    }

    // Check if path is absolute
    let is_absolute = path.starts_with('/')
        || path.starts_with('\\')
        || (path.len() >= 2
            && path.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && path.chars().nth(1) == Some(':'));

    let resolved = if is_absolute {
        // For absolute paths, just validate and return
        if !path.starts_with(boundary) {
            return Err(Problem::validation(format!(
                "Absolute path '{}' is outside boundary '{}'",
                path, boundary
            )));
        }
        path.to_string()
    } else {
        // Resolve relative path
        let full = format!("{}/{}", base.trim_end_matches('/'), path);
        clean_path(&full)
    };

    // Validate result stays within boundary
    if !resolved.starts_with(boundary) {
        return Err(Problem::validation(format!(
            "Resolved path '{}' escapes boundary '{}'",
            resolved, boundary
        )));
    }

    Ok(resolved)
}

/// Resolve a relative path against a base within a boundary (lenient)
///
/// Always returns a path within the boundary.
#[must_use]
pub fn resolve_relative_within(boundary: &str, base: &str, path: &str) -> String {
    match resolve_relative_within_strict(boundary, base, path) {
        Ok(resolved) => resolved,
        Err(_) => {
            // Return safest option
            if base.starts_with(boundary) {
                base.to_string()
            } else if !boundary.is_empty() {
                boundary.to_string()
            } else {
                "/".to_string()
            }
        }
    }
}

// ============================================================================
// Safe Extend Operations
// ============================================================================

/// Extend a path with multiple segments within a boundary (strict)
///
/// Joins multiple segments to a base path, validating each step.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::construction;
///
/// let result = construction::extend_within_boundary_strict(
///     "/app",
///     &["data", "users", "john", "documents", "report.pdf"]
/// );
/// assert_eq!(result.expect("test"), "/app/data/users/john/documents/report.pdf");
/// ```
pub fn extend_within_boundary_strict(boundary: &str, segments: &[&str]) -> ConstructionResult {
    // Validate boundary
    validation::validate_boundary_specification_strict(boundary)?;

    if is_any_injection_present(boundary) {
        return Err(Problem::validation(
            "Boundary contains command injection patterns",
        ));
    }

    if segments.is_empty() {
        return Ok(boundary.to_string());
    }

    // Start with boundary
    let mut current = boundary.to_string();

    for (index, segment) in segments.iter().enumerate() {
        // Validate each segment
        validate_path_input(segment, &format!("Segment {}", index))?;

        // Join
        current = format!("{}/{}", current.trim_end_matches('/'), segment);
    }

    // Simplify
    let simplified = clean_path(&current);

    // Validate result
    if !simplified.starts_with(boundary) {
        return Err(Problem::validation(format!(
            "Result '{}' escapes boundary '{}'",
            simplified, boundary
        )));
    }

    Ok(simplified)
}

/// Extend a path with multiple segments within a boundary (lenient)
///
/// Always returns a path within the boundary.
#[must_use]
pub fn extend_within_boundary(boundary: &str, segments: &[&str]) -> String {
    match extend_within_boundary_strict(boundary, segments) {
        Ok(path) => path,
        Err(_) => {
            if boundary.is_empty() {
                "/".to_string()
            } else {
                boundary.to_string()
            }
        }
    }
}

// ============================================================================
// Safe Sibling Operations
// ============================================================================

/// Get a sibling path within a boundary (strict)
///
/// Given a path to a file, returns the path to a sibling with a different name.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::construction;
///
/// let result = construction::sibling_within_boundary_strict(
///     "/app",
///     "/app/docs/old.txt",
///     "new.txt"
/// );
/// assert_eq!(result.expect("test"), "/app/docs/new.txt");
/// ```
pub fn sibling_within_boundary_strict(
    boundary: &str,
    path: &str,
    sibling_name: &str,
) -> ConstructionResult {
    // Validate boundary
    validation::validate_boundary_specification_strict(boundary)?;

    // Validate inputs
    validate_path_input(path, "Path")?;
    validate_path_input(sibling_name, "Sibling name")?;

    if is_any_injection_present(boundary) {
        return Err(Problem::validation(
            "Boundary contains command injection patterns",
        ));
    }

    // Validate path is within boundary
    if !path.starts_with(boundary) {
        return Err(Problem::validation(format!(
            "Path '{}' is not within boundary '{}'",
            path, boundary
        )));
    }

    // Get parent directory
    let parent = match path.rfind('/') {
        Some(pos) if pos > 0 => &path[..pos],
        _ => boundary,
    };

    // Join parent with sibling name
    let sibling = format!("{}/{}", parent, sibling_name);
    let simplified = clean_path(&sibling);

    // Validate result
    if !simplified.starts_with(boundary) {
        return Err(Problem::validation(format!(
            "Sibling path '{}' escapes boundary '{}'",
            simplified, boundary
        )));
    }

    Ok(simplified)
}

/// Get a sibling path within a boundary (lenient)
///
/// Returns the original path if the sibling would escape.
#[must_use]
pub fn sibling_within_boundary(boundary: &str, path: &str, sibling_name: &str) -> String {
    match sibling_within_boundary_strict(boundary, path, sibling_name) {
        Ok(sibling) => sibling,
        Err(_) => {
            // Return original path as fallback
            if path.starts_with(boundary) {
                path.to_string()
            } else if !boundary.is_empty() {
                boundary.to_string()
            } else {
                "/".to_string()
            }
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Validate a path input for security issues
fn validate_path_input(input: &str, name: &str) -> Result<(), Problem> {
    if is_null_bytes_present(input) {
        return Err(Problem::validation(format!("{} contains null bytes", name)));
    }

    if is_any_injection_present(input) {
        return Err(Problem::validation(format!(
            "{} contains command injection patterns",
            name
        )));
    }

    if is_shell_metacharacters_present(input) {
        return Err(Problem::validation(format!(
            "{} contains shell metacharacters",
            name
        )));
    }

    if is_control_characters_present(input) {
        return Err(Problem::validation(format!(
            "{} contains control characters",
            name
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
    // Join Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_join_within_boundary_strict_basic() {
        let result = join_within_boundary_strict("/app", "", "file.txt").expect("test");
        assert_eq!(result, "/app/file.txt");

        let result = join_within_boundary_strict("/app", "/app/docs", "file.txt").expect("test");
        assert_eq!(result, "/app/docs/file.txt");
    }

    #[test]
    fn test_join_within_boundary_strict_nested() {
        let result = join_within_boundary_strict("/app", "docs", "reports/q1.pdf").expect("test");
        assert_eq!(result, "/app/docs/reports/q1.pdf");
    }

    #[test]
    fn test_join_within_boundary_strict_escape() {
        assert!(join_within_boundary_strict("/app", "docs", "../../../etc").is_err());
        assert!(join_within_boundary_strict("/app", "docs", "$(whoami)").is_err());
    }

    #[test]
    fn test_join_within_boundary_strict_injection_in_boundary() {
        assert!(join_within_boundary_strict("/app/$(cmd)", "docs", "file.txt").is_err());
    }

    #[test]
    fn test_join_within_boundary_lenient() {
        assert_eq!(
            join_within_boundary("/app", "docs", "file.txt"),
            "/app/docs/file.txt"
        );

        // Escape returns base
        let result = join_within_boundary("/app", "/app/docs", "../../../etc");
        assert!(result.starts_with("/app"));
    }

    // ------------------------------------------------------------------------
    // Resolve Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_resolve_relative_within_strict_basic() {
        let result = resolve_relative_within_strict("/app", "/app/docs", "file.txt").expect("test");
        assert_eq!(result, "/app/docs/file.txt");
    }

    #[test]
    fn test_resolve_relative_within_strict_parent() {
        let result =
            resolve_relative_within_strict("/app", "/app/docs/reports", "../images/photo.jpg")
                .expect("test");
        assert_eq!(result, "/app/docs/images/photo.jpg");
    }

    #[test]
    fn test_resolve_relative_within_strict_escape() {
        assert!(
            resolve_relative_within_strict("/app", "/app/docs", "../../../etc/passwd").is_err()
        );
    }

    #[test]
    fn test_resolve_relative_within_strict_absolute() {
        // Absolute path within boundary
        let result = resolve_relative_within_strict("/app", "/app/docs", "/app/images/photo.jpg")
            .expect("test");
        assert_eq!(result, "/app/images/photo.jpg");

        // Absolute path outside boundary
        assert!(resolve_relative_within_strict("/app", "/app/docs", "/etc/passwd").is_err());
    }

    #[test]
    fn test_resolve_relative_within_lenient() {
        assert_eq!(
            resolve_relative_within("/app", "/app/docs", "file.txt"),
            "/app/docs/file.txt"
        );

        // Escape returns base
        let result = resolve_relative_within("/app", "/app/docs", "../../../etc");
        assert!(result.starts_with("/app"));
    }

    // ------------------------------------------------------------------------
    // Extend Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_extend_within_boundary_strict() {
        let result =
            extend_within_boundary_strict("/app", &["data", "users", "john"]).expect("test");
        assert_eq!(result, "/app/data/users/john");
    }

    #[test]
    fn test_extend_within_boundary_strict_empty() {
        let result = extend_within_boundary_strict("/app", &[]).expect("test");
        assert_eq!(result, "/app");
    }

    #[test]
    fn test_extend_within_boundary_strict_escape() {
        assert!(extend_within_boundary_strict("/app", &["docs", "..", "..", "..", "etc"]).is_err());
    }

    #[test]
    fn test_extend_within_boundary_strict_injection() {
        assert!(extend_within_boundary_strict("/app", &["docs", "$(whoami)"]).is_err());
    }

    #[test]
    fn test_extend_within_boundary_lenient() {
        assert_eq!(
            extend_within_boundary("/app", &["docs", "file.txt"]),
            "/app/docs/file.txt"
        );

        // Escape returns boundary
        assert_eq!(extend_within_boundary("/app", &["..", "..", "etc"]), "/app");
    }

    // ------------------------------------------------------------------------
    // Sibling Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sibling_within_boundary_strict() {
        let result =
            sibling_within_boundary_strict("/app", "/app/docs/old.txt", "new.txt").expect("test");
        assert_eq!(result, "/app/docs/new.txt");
    }

    #[test]
    fn test_sibling_within_boundary_strict_escape() {
        assert!(
            sibling_within_boundary_strict("/app", "/app/docs/file.txt", "../../../etc/passwd")
                .is_err()
        );
    }

    #[test]
    fn test_sibling_within_boundary_strict_injection() {
        assert!(sibling_within_boundary_strict("/app", "/app/docs/file.txt", "$(whoami)").is_err());
    }

    #[test]
    fn test_sibling_within_boundary_lenient() {
        assert_eq!(
            sibling_within_boundary("/app", "/app/docs/old.txt", "new.txt"),
            "/app/docs/new.txt"
        );

        // Escape returns original
        let result = sibling_within_boundary("/app", "/app/docs/file.txt", "../../../etc");
        assert!(result.starts_with("/app"));
    }

    // ------------------------------------------------------------------------
    // Input Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validate_path_input_null() {
        assert!(validate_path_input("file\0.txt", "Test").is_err());
    }

    #[test]
    fn test_validate_path_input_injection() {
        assert!(validate_path_input("$(whoami)", "Test").is_err());
        assert!(validate_path_input("${HOME}", "Test").is_err());
        assert!(validate_path_input("`id`", "Test").is_err());
    }

    #[test]
    fn test_validate_path_input_metacharacters() {
        assert!(validate_path_input("file;rm", "Test").is_err());
        assert!(validate_path_input("file|cat", "Test").is_err());
    }

    #[test]
    fn test_validate_path_input_control() {
        assert!(validate_path_input("file\nname", "Test").is_err());
        assert!(validate_path_input("file\rname", "Test").is_err());
    }

    #[test]
    fn test_validate_path_input_safe() {
        assert!(validate_path_input("file.txt", "Test").is_ok());
        assert!(validate_path_input("path/to/file", "Test").is_ok());
        assert!(validate_path_input(".hidden", "Test").is_ok());
    }

    // ------------------------------------------------------------------------
    // Edge Cases
    // ------------------------------------------------------------------------

    #[test]
    fn test_empty_inputs() {
        // Empty boundary
        assert!(join_within_boundary_strict("", "docs", "file.txt").is_err());

        // Empty base is OK (uses boundary)
        let result = join_within_boundary_strict("/app", "", "file.txt").expect("test");
        assert_eq!(result, "/app/file.txt");
    }

    #[test]
    fn test_root_boundary() {
        let result = join_within_boundary_strict("/", "", "etc/passwd").expect("test");
        assert_eq!(result, "/etc/passwd");
    }

    #[test]
    fn test_complex_paths() {
        // Multiple parent refs that stay in bounds
        let result =
            resolve_relative_within_strict("/app", "/app/a/b/c/d", "../../e/../f/file.txt")
                .expect("test");
        assert_eq!(result, "/app/a/b/f/file.txt");
    }
}
