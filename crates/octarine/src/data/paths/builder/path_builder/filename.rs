//! Filename operation delegators for [`PathBuilder`].
//!
//! Methods that delegate to [`FilenameBuilder`] for validation,
//! sanitization, and accessor operations on file names.

use super::super::FilenameBuilder;
use super::super::PathBuilder;
use crate::observe::Problem;
use crate::primitives::data::paths::PathBuilder as PrimitivePathBuilder;

impl PathBuilder {
    /// Validate a filename
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the filename:
    /// - Is invalid (empty, too long, or contains invalid characters)
    /// - Is unsafe (contains traversal or dangerous patterns)
    pub fn validate_filename(&self, filename: &str) -> Result<(), Problem> {
        let fb = FilenameBuilder::new();
        if !fb.is_valid(filename) {
            return Err(Problem::validation(format!(
                "Invalid filename: {}",
                filename
            )));
        }
        if !fb.is_safe(filename) {
            return Err(Problem::validation(format!(
                "Unsafe filename: {}",
                filename
            )));
        }
        Ok(())
    }

    /// Validate a filename for uploads
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the filename is not safe for uploads
    /// (contains dangerous extensions, hidden prefixes, or security threats).
    pub fn validate_upload_filename(&self, filename: &str) -> Result<(), Problem> {
        let fb = FilenameBuilder::new();
        if !fb.is_upload_safe(filename) {
            return Err(Problem::validation(format!(
                "Unsafe upload filename: {}",
                filename
            )));
        }
        Ok(())
    }

    /// Sanitize a filename
    ///
    /// Removes dangerous characters and patterns from a filename.
    /// For lenient cleaning that always returns a value, use [`Self::to_safe_filename`].
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if the filename cannot be safely sanitized
    /// or would become empty/invalid after removing dangerous content.
    pub fn sanitize_filename(&self, filename: &str) -> Result<String, Problem> {
        FilenameBuilder::new().sanitize(filename)
    }

    /// Get a safe filename
    #[must_use]
    pub fn to_safe_filename(&self, filename: &str) -> String {
        FilenameBuilder::new().to_safe_filename(filename)
    }

    /// Get filename from path
    #[must_use]
    pub fn filename<'a>(&self, path: &'a str) -> &'a str {
        PrimitivePathBuilder::new().filename(path)
    }

    /// Get file extension
    #[must_use]
    pub fn find_extension<'a>(&self, path: &'a str) -> Option<&'a str> {
        PrimitivePathBuilder::new().find_extension(path)
    }

    /// Get filename stem
    #[must_use]
    pub fn stem<'a>(&self, path: &'a str) -> &'a str {
        PrimitivePathBuilder::new().stem(path)
    }
}
