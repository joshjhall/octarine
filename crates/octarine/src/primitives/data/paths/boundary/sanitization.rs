//! Boundary sanitization for path containment enforcement
//!
//! Pure sanitization functions to constrain paths within designated boundaries.
//! These are **Layer 1 primitives** with NO observe dependencies.
//!
//! ## Security Standards
//!
//! Follows OWASP directory jailing guidelines:
//! - Constrain paths to designated boundaries
//! - Reject or clean paths that attempt escape
//! - Provide multiple strategies for different use cases
//!
//! ## Dual Function Pattern
//!
//! Functions follow strict/lenient pattern:
//! - **Strict** (`_strict` suffix): Returns `Result`, fails on violations
//! - **Lenient** (no suffix): Always returns a value, clamps to boundary
//!
//! ## Important: Pure Path Operations
//!
//! These functions perform **logical** sanitization (string manipulation).
//! They do NOT:
//! - Access the filesystem
//! - Resolve symlinks
//! - Verify path existence
//!
//! For filesystem-aware sanitization, use higher-level security modules.

use super::super::common::{
    is_any_injection_present, is_control_characters_present, is_null_bytes_present,
    is_shell_metacharacters_present,
};
use super::validation;
use crate::primitives::types::Problem;
use std::borrow::Cow;
use std::path::{Component, Path};

// ============================================================================
// Result Type
// ============================================================================

/// Result of boundary sanitization
pub type SanitizationResult = Result<String, Problem>;

// ============================================================================
// Core Sanitization Functions
// ============================================================================

/// Constrain a path to stay within a boundary (strict)
///
/// Validates the path and rejects if it would escape the boundary.
/// Also validates for command injection and dangerous patterns.
///
/// ## Security Checks
///
/// 1. Validates boundary specification
/// 2. Checks for null bytes
/// 3. Checks for command injection
/// 4. Checks for shell metacharacters
/// 5. Checks for control characters
/// 6. Validates path stays within boundary
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::sanitization;
///
/// // Safe paths pass through
/// let result = sanitization::constrain_to_boundary_strict("file.txt", "/app/data");
/// assert!(result.is_ok());
///
/// // Traversal rejected
/// let result = sanitization::constrain_to_boundary_strict("../secret", "/app/data");
/// assert!(result.is_err());
///
/// // Command injection rejected
/// let result = sanitization::constrain_to_boundary_strict("$(whoami)", "/app/data");
/// assert!(result.is_err());
/// ```
pub fn constrain_to_boundary_strict(path: &str, boundary: &str) -> SanitizationResult {
    // Validate boundary first
    validation::validate_boundary_specification_strict(boundary)?;

    // Check for empty path
    if path.is_empty() {
        return Err(Problem::validation("Path cannot be empty"));
    }

    // Security checks on path
    if is_null_bytes_present(path) {
        return Err(Problem::validation("Path contains null bytes"));
    }

    if is_any_injection_present(path) {
        return Err(Problem::validation(
            "Path contains command injection patterns",
        ));
    }

    if is_shell_metacharacters_present(path) {
        return Err(Problem::validation("Path contains shell metacharacters"));
    }

    if is_control_characters_present(path) {
        return Err(Problem::validation("Path contains control characters"));
    }

    // Security checks on boundary
    if is_any_injection_present(boundary) {
        return Err(Problem::validation(
            "Boundary contains command injection patterns",
        ));
    }

    // Validate path stays within boundary
    validation::validate_within_boundary_strict(path, boundary)?;

    Ok(path.to_string())
}

/// Constrain a path to stay within a boundary (lenient)
///
/// Always returns a safe path. If the path would escape the boundary,
/// returns the boundary itself. Also cleans dangerous patterns.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::sanitization;
///
/// // Safe path passes through
/// assert_eq!(
///     sanitization::constrain_to_boundary("file.txt", "/app/data"),
///     "/app/data/file.txt"
/// );
///
/// // Traversal clamped to boundary
/// assert_eq!(
///     sanitization::constrain_to_boundary("../etc/passwd", "/app/data"),
///     "/app/data"
/// );
/// ```
#[must_use]
pub fn constrain_to_boundary(path: &str, boundary: &str) -> String {
    match constrain_to_boundary_strict(path, boundary) {
        Ok(safe_path) => join_within_boundary(boundary, &safe_path),
        Err(_) => {
            // Return boundary as safe fallback
            if boundary.is_empty() {
                "/".to_string()
            } else {
                boundary.to_string()
            }
        }
    }
}

// ============================================================================
// Path Cleaning
// ============================================================================

/// Strip components that would escape the boundary
///
/// Strips `..` components and absolute path prefixes, keeping only
/// safe path segments.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::sanitization;
///
/// assert_eq!(sanitization::strip_escape_components("../file.txt"), "file.txt");
/// assert_eq!(sanitization::strip_escape_components("../../etc/passwd"), "etc/passwd");
/// assert_eq!(sanitization::strip_escape_components("a/../../../etc"), "etc");
/// assert_eq!(sanitization::strip_escape_components("/etc/passwd"), "etc/passwd");
/// ```
#[must_use]
pub fn strip_escape_components(path: &str) -> Cow<'_, str> {
    if path.is_empty() {
        return Cow::Borrowed(path);
    }

    let path_obj = Path::new(path);
    let mut components: Vec<&str> = Vec::new();

    for component in path_obj.components() {
        match component {
            Component::Normal(s) => {
                if let Some(s) = s.to_str() {
                    components.push(s);
                }
            }
            Component::CurDir => {
                // Skip current directory
            }
            Component::ParentDir => {
                // Pop previous component if exists, otherwise skip
                components.pop();
            }
            Component::RootDir | Component::Prefix(_) => {
                // Skip root/prefix - we're making relative
            }
        }
    }

    if components.is_empty() {
        Cow::Borrowed(".")
    } else {
        Cow::Owned(components.join("/"))
    }
}

/// Remove null bytes from path
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::sanitization;
///
/// assert_eq!(sanitization::strip_null_bytes("file\0.txt"), "file.txt");
/// assert_eq!(sanitization::strip_null_bytes("path\0/\0file"), "path/file");
/// ```
#[must_use]
pub fn strip_null_bytes(path: &str) -> Cow<'_, str> {
    if !path.contains('\0') {
        return Cow::Borrowed(path);
    }

    Cow::Owned(path.replace('\0', ""))
}

/// Strip control characters from path
///
/// Removes newlines, carriage returns, tabs, and other control characters.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::sanitization;
///
/// assert_eq!(sanitization::strip_control_chars("file\nname.txt"), "filename.txt");
/// assert_eq!(sanitization::strip_control_chars("path\t/file"), "path/file");
/// ```
#[must_use]
pub fn strip_control_chars(path: &str) -> Cow<'_, str> {
    if !path.chars().any(|c| c.is_control()) {
        return Cow::Borrowed(path);
    }

    Cow::Owned(path.chars().filter(|c| !c.is_control()).collect())
}

// ============================================================================
// Resolve Within Boundary
// ============================================================================

/// Resolve a path within a boundary (strict)
///
/// Joins the boundary and path, simplifies, and validates the result
/// stays within the boundary.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::sanitization;
///
/// let result = sanitization::resolve_within_boundary_strict("docs/file.txt", "/app");
/// assert_eq!(result.expect("test"), "/app/docs/file.txt");
///
/// let result = sanitization::resolve_within_boundary_strict("../etc", "/app");
/// assert!(result.is_err());
/// ```
pub fn resolve_within_boundary_strict(path: &str, boundary: &str) -> SanitizationResult {
    // First validate
    constrain_to_boundary_strict(path, boundary)?;

    // Then join
    Ok(join_within_boundary(boundary, path))
}

/// Resolve a path within a boundary (lenient)
///
/// Always returns a path within the boundary. If the path would escape,
/// returns the boundary itself.
#[must_use]
pub fn resolve_within_boundary(path: &str, boundary: &str) -> String {
    match resolve_within_boundary_strict(path, boundary) {
        Ok(resolved) => resolved,
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
// Multiple Boundary Enforcement
// ============================================================================

/// Enforce multiple boundary constraints (strict)
///
/// Validates the path stays within ALL specified boundaries.
/// Returns the path resolved within the most restrictive boundary.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::sanitization;
///
/// let boundaries = &["/app", "/app/data", "/app/data/user"];
/// let result = sanitization::enforce_multiple_boundaries_strict("file.txt", boundaries);
/// assert!(result.is_ok());
/// ```
pub fn enforce_multiple_boundaries_strict(path: &str, boundaries: &[&str]) -> SanitizationResult {
    if boundaries.is_empty() {
        return Err(Problem::validation(
            "At least one boundary must be specified",
        ));
    }

    // First, validate against all boundaries individually
    for boundary in boundaries {
        validation::validate_boundary_specification_strict(boundary)?;
    }

    // Security checks on path
    if is_null_bytes_present(path) {
        return Err(Problem::validation("Path contains null bytes"));
    }

    if is_any_injection_present(path) {
        return Err(Problem::validation(
            "Path contains command injection patterns",
        ));
    }

    // Sort boundaries by length (longest first) to find most restrictive
    let mut sorted_boundaries = boundaries.to_vec();
    sorted_boundaries.sort_by_key(|b| std::cmp::Reverse(b.len()));

    let most_restrictive = sorted_boundaries
        .first()
        .ok_or_else(|| Problem::validation("No boundaries provided"))?;

    // Validate against most restrictive
    constrain_to_boundary_strict(path, most_restrictive)?;

    // Verify it satisfies all boundaries
    for boundary in &sorted_boundaries {
        validation::validate_within_boundary_strict(path, boundary)?;
    }

    Ok(join_within_boundary(most_restrictive, path))
}

/// Enforce multiple boundary constraints (lenient)
///
/// Always returns a path within all boundaries.
/// If the path violates any boundary, returns the most restrictive boundary.
#[must_use]
pub fn enforce_multiple_boundaries(path: &str, boundaries: &[&str]) -> String {
    match enforce_multiple_boundaries_strict(path, boundaries) {
        Ok(safe_path) => safe_path,
        Err(_) => {
            if boundaries.is_empty() {
                "/".to_string()
            } else {
                let mut sorted = boundaries.to_vec();
                sorted.sort_by_key(|b| std::cmp::Reverse(b.len()));
                sorted
                    .first()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "/".to_string())
            }
        }
    }
}

// ============================================================================
// Jail Creation
// ============================================================================

/// Create a strict jailed path resolver
///
/// Returns a closure that validates paths within the jail boundary.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::sanitization;
///
/// let jail = sanitization::create_jail_strict("/app/data");
/// assert!(jail("docs/file.txt").is_ok());
/// assert!(jail("../escape").is_err());
/// ```
pub fn create_jail_strict(jail_root: &str) -> impl Fn(&str) -> SanitizationResult + '_ {
    move |path: &str| resolve_within_boundary_strict(path, jail_root)
}

/// Create a lenient jailed path resolver
///
/// Returns a closure that always returns a safe path within the jail.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::boundary::sanitization;
///
/// let jail = sanitization::create_jail("/app/data");
/// assert_eq!(jail("docs/file.txt"), "/app/data/docs/file.txt");
/// assert_eq!(jail("../escape"), "/app/data");
/// ```
pub fn create_jail(jail_root: &str) -> impl Fn(&str) -> String + '_ {
    move |path: &str| resolve_within_boundary(path, jail_root)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Join a boundary and path, handling edge cases
fn join_within_boundary(boundary: &str, path: &str) -> String {
    if path.is_empty() || path == "." {
        return boundary.to_string();
    }

    let path_obj = Path::new(path);

    // If path is already absolute, just return it (if it starts with boundary)
    if path_obj.is_absolute() {
        if path.starts_with(boundary) {
            return path.to_string();
        }
        // Strip absolute prefix
        let stripped = path.trim_start_matches('/').trim_start_matches('\\');
        return format!("{}/{}", boundary.trim_end_matches('/'), stripped);
    }

    // Join normally
    format!(
        "{}/{}",
        boundary.trim_end_matches('/'),
        path.trim_start_matches('/').trim_start_matches('\\')
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ------------------------------------------------------------------------
    // Constrain to Boundary Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_constrain_to_boundary_strict_safe() {
        assert!(constrain_to_boundary_strict("file.txt", "/app").is_ok());
        assert!(constrain_to_boundary_strict("dir/file.txt", "/app").is_ok());
        assert!(constrain_to_boundary_strict("a/b/c/file.txt", "/app").is_ok());
    }

    #[test]
    fn test_constrain_to_boundary_strict_traversal() {
        assert!(constrain_to_boundary_strict("../secret", "/app").is_err());
        assert!(constrain_to_boundary_strict("../../etc/passwd", "/app").is_err());
        assert!(constrain_to_boundary_strict("a/../../../etc", "/app").is_err());
    }

    #[test]
    fn test_constrain_to_boundary_strict_injection() {
        assert!(constrain_to_boundary_strict("$(whoami)", "/app").is_err());
        assert!(constrain_to_boundary_strict("${HOME}/file", "/app").is_err());
        assert!(constrain_to_boundary_strict("`id`", "/app").is_err());
        assert!(constrain_to_boundary_strict("$VAR", "/app").is_err());
    }

    #[test]
    fn test_constrain_to_boundary_strict_metacharacters() {
        assert!(constrain_to_boundary_strict("file;rm", "/app").is_err());
        assert!(constrain_to_boundary_strict("file|cat", "/app").is_err());
        assert!(constrain_to_boundary_strict("file&cmd", "/app").is_err());
    }

    #[test]
    fn test_constrain_to_boundary_strict_control_chars() {
        assert!(constrain_to_boundary_strict("file\nname", "/app").is_err());
        assert!(constrain_to_boundary_strict("file\0.txt", "/app").is_err());
    }

    #[test]
    fn test_constrain_to_boundary_strict_boundary_injection() {
        assert!(constrain_to_boundary_strict("file.txt", "/app/$(whoami)").is_err());
    }

    #[test]
    fn test_constrain_to_boundary_lenient() {
        // Safe path gets joined
        assert_eq!(
            constrain_to_boundary("file.txt", "/app/data"),
            "/app/data/file.txt"
        );

        // Unsafe paths return boundary
        assert_eq!(constrain_to_boundary("../escape", "/app/data"), "/app/data");
        assert_eq!(constrain_to_boundary("$(whoami)", "/app/data"), "/app/data");
    }

    // ------------------------------------------------------------------------
    // Path Cleaning Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_strip_escape_components() {
        assert_eq!(strip_escape_components("file.txt").as_ref(), "file.txt");
        assert_eq!(strip_escape_components("../file.txt").as_ref(), "file.txt");
        assert_eq!(
            strip_escape_components("../../etc/passwd").as_ref(),
            "etc/passwd"
        );
        assert_eq!(strip_escape_components("a/../../../etc").as_ref(), "etc");
        assert_eq!(
            strip_escape_components("/etc/passwd").as_ref(),
            "etc/passwd"
        );
        assert_eq!(strip_escape_components("./file").as_ref(), "file");
    }

    #[test]
    fn test_strip_escape_components_empty() {
        assert_eq!(strip_escape_components("").as_ref(), "");
        assert_eq!(strip_escape_components("..").as_ref(), ".");
        assert_eq!(strip_escape_components("../..").as_ref(), ".");
    }

    #[test]
    fn test_strip_null_bytes() {
        assert_eq!(strip_null_bytes("file.txt").as_ref(), "file.txt");
        assert_eq!(strip_null_bytes("file\0.txt").as_ref(), "file.txt");
        assert_eq!(strip_null_bytes("path\0/\0file").as_ref(), "path/file");
    }

    #[test]
    fn test_strip_control_chars() {
        assert_eq!(strip_control_chars("file.txt").as_ref(), "file.txt");
        assert_eq!(
            strip_control_chars("file\nname.txt").as_ref(),
            "filename.txt"
        );
        assert_eq!(strip_control_chars("path\t/file").as_ref(), "path/file");
        assert_eq!(strip_control_chars("a\rb\nc").as_ref(), "abc");
    }

    // ------------------------------------------------------------------------
    // Resolve Within Boundary Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_resolve_within_boundary_strict() {
        let result = resolve_within_boundary_strict("docs/file.txt", "/app").expect("test");
        assert_eq!(result, "/app/docs/file.txt");

        let result = resolve_within_boundary_strict("file.txt", "/app/data").expect("test");
        assert_eq!(result, "/app/data/file.txt");
    }

    #[test]
    fn test_resolve_within_boundary_strict_escape() {
        assert!(resolve_within_boundary_strict("../etc", "/app").is_err());
        assert!(resolve_within_boundary_strict("$(cmd)", "/app").is_err());
    }

    #[test]
    fn test_resolve_within_boundary_lenient() {
        assert_eq!(
            resolve_within_boundary("docs/file.txt", "/app"),
            "/app/docs/file.txt"
        );
        assert_eq!(resolve_within_boundary("../escape", "/app"), "/app");
    }

    // ------------------------------------------------------------------------
    // Multiple Boundary Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_enforce_multiple_boundaries_strict() {
        let boundaries = &["/app", "/app/data", "/app/data/user"];
        let result = enforce_multiple_boundaries_strict("file.txt", boundaries).expect("test");
        // Should use most restrictive boundary
        assert!(result.starts_with("/app/data/user"));
    }

    #[test]
    fn test_enforce_multiple_boundaries_strict_escape() {
        let boundaries = &["/app", "/app/data"];
        assert!(enforce_multiple_boundaries_strict("../escape", boundaries).is_err());
    }

    #[test]
    fn test_enforce_multiple_boundaries_lenient() {
        let boundaries = &["/app", "/app/data", "/app/data/user"];

        // Safe path
        let result = enforce_multiple_boundaries("file.txt", boundaries);
        assert!(result.starts_with("/app/data/user"));

        // Escape attempt returns most restrictive
        let result = enforce_multiple_boundaries("../escape", boundaries);
        assert_eq!(result, "/app/data/user");
    }

    #[test]
    fn test_enforce_multiple_boundaries_empty() {
        let boundaries: &[&str] = &[];
        assert!(enforce_multiple_boundaries_strict("file.txt", boundaries).is_err());
        assert_eq!(enforce_multiple_boundaries("file.txt", boundaries), "/");
    }

    // ------------------------------------------------------------------------
    // Jail Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_create_jail_strict() {
        let jail = create_jail_strict("/app/data");

        let result = jail("docs/file.txt").expect("test");
        assert_eq!(result, "/app/data/docs/file.txt");

        assert!(jail("../escape").is_err());
        assert!(jail("$(whoami)").is_err());
    }

    #[test]
    fn test_create_jail_lenient() {
        let jail = create_jail("/app/data");

        assert_eq!(jail("docs/file.txt"), "/app/data/docs/file.txt");
        assert_eq!(jail("../escape"), "/app/data");
        assert_eq!(jail("$(whoami)"), "/app/data");
    }

    // ------------------------------------------------------------------------
    // Edge Cases
    // ------------------------------------------------------------------------

    #[test]
    fn test_empty_path() {
        assert!(constrain_to_boundary_strict("", "/app").is_err());
        assert_eq!(constrain_to_boundary("", "/app"), "/app");
    }

    #[test]
    fn test_empty_boundary() {
        assert!(constrain_to_boundary_strict("file.txt", "").is_err());
        // Lenient with empty boundary returns "/"
        assert_eq!(constrain_to_boundary("file.txt", ""), "/");
    }

    #[test]
    fn test_dot_path() {
        let result = constrain_to_boundary_strict(".", "/app").expect("test");
        assert_eq!(result, ".");

        assert_eq!(resolve_within_boundary(".", "/app"), "/app");
    }

    #[test]
    fn test_absolute_path_in_boundary() {
        // Absolute path that starts with boundary
        assert!(constrain_to_boundary_strict("/app/data/file.txt", "/app/data").is_ok());
    }

    #[test]
    fn test_join_helper() {
        assert_eq!(join_within_boundary("/app", "file.txt"), "/app/file.txt");
        assert_eq!(join_within_boundary("/app/", "file.txt"), "/app/file.txt");
        assert_eq!(join_within_boundary("/app", "/file.txt"), "/app/file.txt");
        assert_eq!(join_within_boundary("/app", ""), "/app");
        assert_eq!(join_within_boundary("/app", "."), "/app");
    }
}
