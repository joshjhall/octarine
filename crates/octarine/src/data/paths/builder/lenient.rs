//! Lenient sanitization builder with observability
//!
//! Provides sanitization operations that always return a valid value
//! instead of returning errors on invalid input.
//!
//! # Strict vs Lenient
//!
//! - **Strict** (`sanitize_*`): Returns `Result<String, Problem>` - errors on threats
//! - **Lenient** (`clean_*`): Returns `String` - removes threats, always succeeds
//!
//! # Examples
//!
//! ```rust
//! use octarine::data::paths::LenientBuilder;
//!
//! let lenient = LenientBuilder::new();
//!
//! // Clean paths - always returns a value
//! let safe = lenient.clean_path("../../../etc/passwd");
//! assert!(!safe.contains(".."));
//!
//! // Clean user input - more aggressive
//! let safe = lenient.clean_user_path("/etc/passwd");
//! assert!(!safe.starts_with('/'));
//!
//! // Clean filenames
//! let safe = lenient.clean_filename("");
//! assert_eq!(safe, "unnamed");
//! ```

use crate::observe::metrics::increment;

use super::super::lenient;

crate::define_metrics! {
    paths_cleaned => "data.paths.lenient.paths_cleaned",
    filenames_cleaned => "data.paths.lenient.filenames_cleaned",
}

/// Lenient sanitization builder with observability
///
/// Provides sanitization that always returns a valid value.
#[derive(Debug, Clone, Default)]
pub struct LenientBuilder {
    emit_events: bool,
}

impl LenientBuilder {
    /// Create a new lenient builder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self { emit_events: true }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self { emit_events: false }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // Path Cleaning
    // ========================================================================

    /// Clean a path - always returns a safe value
    ///
    /// Unlike strict sanitization which returns an error on threats,
    /// this function removes threats and returns a cleaned path.
    /// If the path is completely invalid, returns an empty string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use octarine::data::paths::LenientBuilder;
    /// let lenient = LenientBuilder::new();
    ///
    /// let safe = lenient.clean_path("../../../etc/passwd");
    /// assert!(!safe.contains(".."));
    ///
    /// let safe = lenient.clean_path("$(whoami)/file");
    /// assert!(!safe.contains("$("));
    /// ```
    #[must_use]
    pub fn clean_path(&self, path: &str) -> String {
        let result = lenient::clean_path(path);
        if self.emit_events {
            increment(metric_names::paths_cleaned());
        }
        result
    }

    /// Clean a user-provided path - always returns a safe value
    ///
    /// More aggressive cleaning for untrusted user input:
    /// - Removes absolute path prefixes
    /// - Removes Windows drive letters
    /// - Removes all traversal patterns
    ///
    /// # Examples
    ///
    /// ```rust
    /// use octarine::data::paths::LenientBuilder;
    /// let lenient = LenientBuilder::new();
    ///
    /// let safe = lenient.clean_user_path("/etc/passwd");
    /// assert!(!safe.starts_with('/'));
    ///
    /// let safe = lenient.clean_user_path("C:\\Windows\\System32");
    /// // Returns path without drive letter
    /// ```
    #[must_use]
    pub fn clean_user_path(&self, path: &str) -> String {
        lenient::clean_user_path(path)
    }

    // ========================================================================
    // Filename Cleaning
    // ========================================================================

    /// Clean a filename - always returns a safe filename
    ///
    /// Removes dangerous characters. Returns "unnamed" for empty input.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use octarine::data::paths::LenientBuilder;
    /// let lenient = LenientBuilder::new();
    ///
    /// let safe = lenient.clean_filename("file<>:\"|?*.txt");
    /// // Dangerous characters removed
    ///
    /// let safe = lenient.clean_filename("");
    /// assert_eq!(safe, "unnamed");
    /// ```
    #[must_use]
    pub fn clean_filename(&self, filename: &str) -> String {
        let result = lenient::clean_filename(filename);
        if self.emit_events {
            increment(metric_names::filenames_cleaned());
        }
        result
    }

    // ========================================================================
    // Separator Cleaning
    // ========================================================================

    /// Clean path separators - normalize to Unix style
    ///
    /// Converts backslashes to forward slashes and collapses multiple slashes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use octarine::data::paths::LenientBuilder;
    /// let lenient = LenientBuilder::new();
    ///
    /// let normalized = lenient.clean_separators("path\\to\\file");
    /// assert_eq!(normalized, "path/to/file");
    ///
    /// let normalized = lenient.clean_separators("path//double//slash");
    /// assert_eq!(normalized, "path/double/slash");
    /// ```
    #[must_use]
    pub fn clean_separators(&self, path: &str) -> String {
        lenient::clean_separators(path)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = LenientBuilder::new();
        assert!(builder.emit_events);

        let silent = LenientBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = LenientBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_clean_path_safe_input() {
        let lenient = LenientBuilder::silent();

        assert_eq!(lenient.clean_path("safe/path.txt"), "safe/path.txt");
        assert_eq!(lenient.clean_path("/absolute/path"), "/absolute/path");
    }

    #[test]
    fn test_clean_path_removes_traversal() {
        let lenient = LenientBuilder::silent();

        let result = lenient.clean_path("../../../etc/passwd");
        assert!(!result.contains(".."));
    }

    #[test]
    fn test_clean_path_removes_injection() {
        let lenient = LenientBuilder::silent();

        let result = lenient.clean_path("$(whoami)/file");
        assert!(!result.contains("$("));
    }

    #[test]
    fn test_clean_path_removes_null_bytes() {
        let lenient = LenientBuilder::silent();

        let result = lenient.clean_path("file\0.txt");
        assert!(!result.contains('\0'));
    }

    #[test]
    fn test_clean_path_empty() {
        let lenient = LenientBuilder::silent();

        assert_eq!(lenient.clean_path(""), "");
    }

    #[test]
    fn test_clean_user_path_removes_absolute() {
        let lenient = LenientBuilder::silent();

        let result = lenient.clean_user_path("/etc/passwd");
        assert!(!result.starts_with('/'));
    }

    #[test]
    fn test_clean_user_path_removes_traversal() {
        let lenient = LenientBuilder::silent();

        let result = lenient.clean_user_path("../../../etc/passwd");
        assert!(!result.contains(".."));
    }

    #[test]
    fn test_clean_filename_valid() {
        let lenient = LenientBuilder::silent();

        assert_eq!(lenient.clean_filename("document.pdf"), "document.pdf");
    }

    #[test]
    fn test_clean_filename_removes_dangerous() {
        let lenient = LenientBuilder::silent();

        let result = lenient.clean_filename("file<>:\"|?*.txt");
        assert!(!result.contains('<'));
        assert!(!result.contains('>'));
    }

    #[test]
    fn test_clean_filename_empty() {
        let lenient = LenientBuilder::silent();

        assert_eq!(lenient.clean_filename(""), "unnamed");
    }

    #[test]
    fn test_clean_separators() {
        let lenient = LenientBuilder::silent();

        assert_eq!(lenient.clean_separators("path\\to\\file"), "path/to/file");
        assert_eq!(
            lenient.clean_separators("path//double//slash"),
            "path/double/slash"
        );
    }
}
