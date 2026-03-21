//! Combined operation shortcuts
//!
//! Convenience functions for common path operation workflows.

use crate::observe::Problem;

use super::super::{BoundaryBuilder, FilenameBuilder, PathBuilder, PathContextBuilder};

// ============================================================
// COMBINED OPERATIONS (Common Workflows)
// ============================================================

/// Validate and sanitize a user-uploaded filename with allowed extensions
///
/// Combines upload validation with extension whitelist checking.
/// Returns sanitized filename if valid, error otherwise.
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::validate_upload;
/// let safe = validate_upload("report.pdf", &["pdf", "doc", "docx"]).unwrap();
/// assert_eq!(safe, "report.pdf");
/// ```
pub fn validate_upload(filename: &str, allowed_extensions: &[&str]) -> Result<String, Problem> {
    let fb = FilenameBuilder::new();

    // Check extension is allowed
    if !fb.is_extension_allowed(filename, allowed_extensions) {
        return Err(Problem::validation(format!(
            "File extension not allowed. Allowed: {:?}",
            allowed_extensions
        )));
    }

    // Validate upload safety
    fb.validate_upload_safe(filename)?;

    // Return sanitized filename
    fb.sanitize(filename)
}

/// Expand home directory and sanitize the result
///
/// Combines `~/path` expansion with security sanitization.
/// Uses standard sanitization (not strict) since home expansion
/// produces absolute paths by design.
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::expand_and_sanitize;
/// let safe = expand_and_sanitize("~/Documents/file.txt").unwrap();
/// assert!(safe.ends_with("/Documents/file.txt"));
/// ```
pub fn expand_and_sanitize(path: &str) -> Result<String, Problem> {
    let expanded = PathBuilder::new().expand_home(path)?;
    PathBuilder::new().sanitize(&expanded)
}

/// Build a safe file path with validation
///
/// Builds a path and validates it's safe in one call.
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::safe_file_path;
/// let path = safe_file_path("/app/uploads", "document.pdf").unwrap();
/// assert_eq!(path, "/app/uploads/document.pdf");
/// ```
pub fn safe_file_path(directory: &str, filename: &str) -> Result<String, Problem> {
    // Sanitize filename first
    let safe_filename = FilenameBuilder::new().sanitize(filename)?;

    // Build the path
    PathBuilder::new().build_file_path(directory, &safe_filename)
}

/// Build a safe path within a boundary
///
/// Builds a path ensuring it stays within the boundary directory.
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::safe_path_in_boundary;
/// let path = safe_path_in_boundary("/app/data", &["users", "uploads", "file.txt"]).unwrap();
/// assert!(path.starts_with("/app/data"));
/// ```
pub fn safe_path_in_boundary(boundary: &str, components: &[&str]) -> Result<String, Problem> {
    // Build the path
    let path = PathBuilder::new().build_path(boundary, components)?;

    // Validate it's within boundary
    BoundaryBuilder::new(boundary).validate_path_in_boundary(&path)?;

    Ok(path)
}

/// Check if a path is safe for a specific context
///
/// Auto-detects context (env, ssh, credential, etc.) and validates appropriately.
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::is_safe_for_context;
/// assert!(is_safe_for_context(".env.production"));
/// assert!(is_safe_for_context(".ssh/config"));
/// ```
pub fn is_safe_for_context(path: &str) -> bool {
    PathContextBuilder::new().sanitize_auto(path).is_ok()
}

/// Sanitize path based on auto-detected context
///
/// Detects if path is env, ssh, credential, or general and applies appropriate sanitization.
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::sanitize_for_context;
/// let safe = sanitize_for_context(".ssh/id_rsa").unwrap(); // Uses SSH sanitization
/// let safe = sanitize_for_context(".env.local").unwrap();  // Uses env sanitization
/// ```
pub fn sanitize_for_context(path: &str) -> Result<String, Problem> {
    PathContextBuilder::new().sanitize_auto(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_combined_operations() {
        let safe = validate_upload("report.pdf", &["pdf", "doc"]).expect("valid upload");
        assert_eq!(safe, "report.pdf");

        let path = safe_file_path("/uploads", "doc.pdf").expect("valid path");
        assert_eq!(path, "/uploads/doc.pdf");

        assert!(is_safe_for_context(".env.local"));
    }
}
