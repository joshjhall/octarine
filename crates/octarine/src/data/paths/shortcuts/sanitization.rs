//! Sanitization shortcuts
//!
//! Convenience functions for path sanitization operations.

use crate::observe::Problem;

use super::super::PathBuilder;

// ============================================================
// SANITIZATION SHORTCUTS
// ============================================================

/// Sanitize a path by removing threats
///
/// Cleans the path by removing traversal patterns and dangerous characters.
/// Returns the sanitized path, or an error if sanitization fails.
///
/// For lenient filename cleaning, use [`to_safe_filename`].
pub fn sanitize_path(path: &str) -> Result<String, Problem> {
    PathBuilder::new().sanitize(path)
}

/// Sanitize a path within a boundary
///
/// Cleans the path and ensures it stays within the boundary.
pub fn sanitize_path_in_boundary(path: &str, boundary: &str) -> Result<String, Problem> {
    PathBuilder::new().boundary(boundary).sanitize(path)
}

/// Sanitize a filename
///
/// Removes dangerous characters and patterns from a filename.
/// For lenient cleaning that always returns a value, use [`to_safe_filename`].
pub fn sanitize_filename(filename: &str) -> Result<String, Problem> {
    PathBuilder::new().sanitize_filename(filename)
}

/// Get a safe filename, with fallback for empty/invalid inputs
///
/// Always returns a usable filename string.
pub fn to_safe_filename(filename: &str) -> String {
    PathBuilder::new().to_safe_filename(filename)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_sanitization_shortcuts() {
        let clean = sanitize_path("../etc/passwd").expect("should sanitize");
        assert!(!clean.contains(".."));

        let safe = sanitize_filename("../file;rm.txt").expect("should sanitize");
        assert!(!safe.contains(".."));
    }
}
