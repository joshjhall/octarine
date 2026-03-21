//! Validation helper shortcuts
//!
//! Convenience functions for boundary and extension validation.

use crate::observe::Problem;

use super::super::{BoundaryBuilder, FilenameBuilder};

// ============================================================
// VALIDATION HELPERS
// ============================================================

/// Validate filename has an allowed extension
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::validate_extension;
/// validate_extension("doc.pdf", &["pdf", "doc"]).unwrap();
/// ```
pub fn validate_extension(filename: &str, allowed: &[&str]) -> Result<(), Problem> {
    FilenameBuilder::new().validate_allowed_extension(filename, allowed)
}

/// Validate path is within a boundary directory
pub fn validate_in_boundary(path: &str, boundary: &str) -> Result<(), Problem> {
    BoundaryBuilder::new(boundary).validate_path_in_boundary(path)
}

/// Check if path would escape a boundary
pub fn would_escape_boundary(path: &str, boundary: &str) -> bool {
    !BoundaryBuilder::new(boundary).is_within(path)
}

/// Calculate how many levels a path tries to escape
pub fn calculate_escape_depth(path: &str, boundary: &str) -> usize {
    BoundaryBuilder::new(boundary).calculate_escape_depth(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validation_helpers() {
        assert!(validate_extension("doc.pdf", &["pdf", "doc"]).is_ok());
        assert!(validate_extension("doc.exe", &["pdf", "doc"]).is_err());
    }

    #[test]
    fn test_boundary_helpers() {
        assert!(would_escape_boundary("../secret", "/app"));
        assert!(!would_escape_boundary("data/file", "/app"));
    }
}
