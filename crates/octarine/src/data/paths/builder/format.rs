//! Path format operations builder with observability
//!
//! Wraps `primitives::data::paths::FormatBuilder` with observe instrumentation.
//!
//! Provides format detection, conversion, and normalization.
//!
//! # Supported Formats
//!
//! - **Unix**: Forward slashes, absolute starts with `/`
//! - **Windows**: Backslashes, drive letters like `C:\`
//! - **PowerShell**: Forward slashes with drive letters `C:/`
//! - **WSL**: Unix format with `/mnt/c/` for Windows drives
//! - **Portable**: Format-agnostic relative paths
//!
//! # Examples
//!
//! ```rust
//! use octarine::data::paths::FormatBuilder;
//!
//! let fmt = FormatBuilder::new();
//!
//! // Detection
//! assert!(fmt.is_wsl_path("/mnt/c/Users"));
//! assert!(fmt.is_drive_letter_present("C:\\Windows"));
//!
//! // Conversion
//! let unix = fmt.convert_to_unix("path\\to\\file");
//! let windows = fmt.convert_to_windows("path/to/file");
//! let wsl = fmt.convert_to_wsl("C:\\Users");
//! ```

use std::borrow::Cow;

use crate::observe::metrics::{MetricName, increment};
use crate::primitives::data::paths::FormatBuilder as PrimitiveFormatBuilder;

// Re-export PathFormat and SeparatorStyle from local types module
pub use crate::data::paths::types::{PathFormat, SeparatorStyle};

// Pre-validated metric names
#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn format_detected() -> MetricName {
        MetricName::new("data.paths.format.format_detected").expect("valid metric name")
    }

    pub fn converted() -> MetricName {
        MetricName::new("data.paths.format.converted").expect("valid metric name")
    }
}

/// Path format operations builder with observability
///
/// Provides format detection and conversion with audit trail.
#[derive(Debug, Clone, Default)]
pub struct FormatBuilder {
    emit_events: bool,
}

impl FormatBuilder {
    /// Create a new format builder with observe events enabled
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
    // Format Detection
    // ========================================================================

    /// Detect the format of a path
    #[must_use]
    pub fn detect(&self, path: &str) -> PathFormat {
        let format = PrimitiveFormatBuilder::new().detect(path).into();
        if self.emit_events {
            increment(metric_names::format_detected());
        }
        format
    }

    /// Detect the separator style of a path
    #[must_use]
    pub fn detect_separator_style(&self, path: &str) -> SeparatorStyle {
        PrimitiveFormatBuilder::new()
            .detect_separator_style(path)
            .into()
    }

    /// Check if path has mixed separators (both / and \)
    #[must_use]
    pub fn is_mixed_separators_present(&self, path: &str) -> bool {
        PrimitiveFormatBuilder::new().is_mixed_separators_present(path)
    }

    /// Check if path has redundant separators (//)
    #[must_use]
    pub fn is_redundant_separators_present(&self, path: &str) -> bool {
        PrimitiveFormatBuilder::new().is_redundant_separators_present(path)
    }

    /// Check if path has trailing separator
    #[must_use]
    pub fn is_trailing_separator_present(&self, path: &str) -> bool {
        PrimitiveFormatBuilder::new().is_trailing_separator_present(path)
    }

    /// Check if path has leading dot-slash (./)
    #[must_use]
    pub fn is_leading_dot_slash_present(&self, path: &str) -> bool {
        PrimitiveFormatBuilder::new().is_leading_dot_slash_present(path)
    }

    /// Check if path has any format issues
    #[must_use]
    pub fn is_format_issues_present(&self, path: &str) -> bool {
        PrimitiveFormatBuilder::new().is_format_issues_present(path)
    }

    /// Check if path has consistent format (no mixed separators)
    #[must_use]
    pub fn is_consistent_format(&self, path: &str) -> bool {
        PrimitiveFormatBuilder::new().is_consistent_format(path)
    }

    /// Check if path has Windows-style separators (backslashes)
    #[must_use]
    pub fn is_windows_separators_present(&self, path: &str) -> bool {
        PrimitiveFormatBuilder::new().is_windows_separators_present(path)
    }

    /// Check if path has POSIX-style separators (forward slashes)
    #[must_use]
    pub fn is_posix_separators_present(&self, path: &str) -> bool {
        PrimitiveFormatBuilder::new().is_posix_separators_present(path)
    }

    /// Check if path exceeds platform length limits
    #[must_use]
    pub fn exceeds_length_limit(&self, path: &str) -> bool {
        PrimitiveFormatBuilder::new().exceeds_length_limit(path)
    }

    // ========================================================================
    // Path Type Detection
    // ========================================================================

    /// Check if path has Windows drive letter
    #[must_use]
    pub fn is_drive_letter_present(&self, path: &str) -> bool {
        PrimitiveFormatBuilder::new().is_drive_letter_present(path)
    }

    /// Check if path is UNC path (\\server\share)
    #[must_use]
    pub fn is_unc_path(&self, path: &str) -> bool {
        PrimitiveFormatBuilder::new().is_unc_path(path)
    }

    /// Check if path is WSL path (/mnt/c/)
    #[must_use]
    pub fn is_wsl_path(&self, path: &str) -> bool {
        PrimitiveFormatBuilder::new().is_wsl_path(path)
    }

    /// Find drive letter from Windows path (e.g., 'C' from "C:\")
    #[must_use]
    pub fn find_drive_letter(&self, path: &str) -> Option<char> {
        PrimitiveFormatBuilder::new().find_drive_letter(path)
    }

    /// Find drive letter from WSL path (e.g., 'c' from "/mnt/c/")
    #[must_use]
    pub fn find_wsl_drive_letter(&self, path: &str) -> Option<char> {
        PrimitiveFormatBuilder::new().find_wsl_drive_letter(path)
    }

    // ========================================================================
    // Separator Conversion
    // ========================================================================

    /// Convert path to Unix format (forward slashes)
    #[must_use]
    pub fn convert_to_unix<'a>(&self, path: &'a str) -> Cow<'a, str> {
        PrimitiveFormatBuilder::new().convert_to_unix(path)
    }

    /// Convert path to Windows format (backslashes)
    #[must_use]
    pub fn convert_to_windows<'a>(&self, path: &'a str) -> Cow<'a, str> {
        PrimitiveFormatBuilder::new().convert_to_windows(path)
    }

    /// Normalize separators (convert to forward slashes, collapse duplicates)
    #[must_use]
    pub fn normalize_separators<'a>(&self, path: &'a str) -> Cow<'a, str> {
        PrimitiveFormatBuilder::new().normalize_separators(path)
    }

    /// Convert path to native format for current platform
    #[must_use]
    pub fn convert_to_native<'a>(&self, path: &'a str) -> Cow<'a, str> {
        PrimitiveFormatBuilder::new().convert_to_native(path)
    }

    /// Strip redundant separators (e.g., // -> /)
    #[must_use]
    pub fn strip_redundant_separators<'a>(&self, path: &'a str) -> Cow<'a, str> {
        PrimitiveFormatBuilder::new().strip_redundant_separators(path)
    }

    /// Strip trailing separator from path
    #[must_use]
    pub fn strip_trailing_separator<'a>(&self, path: &'a str) -> &'a str {
        PrimitiveFormatBuilder::new().strip_trailing_separator(path)
    }

    /// Ensure path has trailing separator
    #[must_use]
    pub fn ensure_trailing_separator<'a>(&self, path: &'a str) -> Cow<'a, str> {
        PrimitiveFormatBuilder::new().ensure_trailing_separator(path)
    }

    /// Strip leading dot-slash (./) from path
    #[must_use]
    pub fn strip_leading_dot_slash<'a>(&self, path: &'a str) -> &'a str {
        PrimitiveFormatBuilder::new().strip_leading_dot_slash(path)
    }

    // ========================================================================
    // Cross-Platform Conversion
    // ========================================================================

    /// Convert Windows path to WSL path
    ///
    /// `C:\Users\file` -> `/mnt/c/Users/file`
    #[must_use]
    pub fn convert_to_wsl(&self, path: &str) -> Option<String> {
        PrimitiveFormatBuilder::new().convert_to_wsl(path)
    }

    /// Convert WSL path to Windows path
    ///
    /// `/mnt/c/Users/file` -> `C:\Users\file`
    #[must_use]
    pub fn wsl_to_windows(&self, path: &str) -> Option<String> {
        PrimitiveFormatBuilder::new().wsl_to_windows(path)
    }

    /// Convert to portable format (remove drive letters, use forward slashes)
    #[must_use]
    pub fn convert_to_portable<'a>(&self, path: &'a str) -> Cow<'a, str> {
        PrimitiveFormatBuilder::new().convert_to_portable(path)
    }

    /// Convert Windows drive path to Unix-style (C:\ -> /c/)
    #[must_use]
    pub fn windows_to_unix(&self, path: &str) -> Option<String> {
        PrimitiveFormatBuilder::new().windows_to_unix(path)
    }

    /// Convert path to a specific format
    #[must_use]
    pub fn convert<'a>(&self, path: &'a str, target: PathFormat) -> Cow<'a, str> {
        let result = PrimitiveFormatBuilder::new().convert(path, target.into());
        if self.emit_events {
            increment(metric_names::converted());
        }
        result
    }

    // ========================================================================
    // Batch Operations
    // ========================================================================

    /// Convert multiple paths to Unix format
    #[must_use]
    pub fn convert_batch_to_unix(&self, paths: &[&str]) -> Vec<String> {
        paths
            .iter()
            .map(|p| self.convert_to_unix(p).into_owned())
            .collect()
    }

    /// Convert multiple paths to Windows format
    #[must_use]
    pub fn convert_batch_to_windows(&self, paths: &[&str]) -> Vec<String> {
        paths
            .iter()
            .map(|p| self.convert_to_windows(p).into_owned())
            .collect()
    }

    /// Normalize separators for multiple paths
    #[must_use]
    pub fn normalize_batch(&self, paths: &[&str]) -> Vec<String> {
        paths
            .iter()
            .map(|p| self.normalize_separators(p).into_owned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = FormatBuilder::new();
        assert!(builder.emit_events);

        let silent = FormatBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = FormatBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_format_detection() {
        let fmt = FormatBuilder::silent();

        assert_eq!(fmt.detect("/mnt/c/Users"), PathFormat::Wsl);
        assert_eq!(fmt.detect("C:\\Windows"), PathFormat::Windows);
        assert_eq!(fmt.detect("C:/Windows"), PathFormat::PowerShell);
        assert_eq!(fmt.detect("/etc/passwd"), PathFormat::Unix);
        assert_eq!(fmt.detect("relative/path"), PathFormat::Portable);
    }

    #[test]
    fn test_format_issues() {
        let fmt = FormatBuilder::silent();

        assert!(fmt.is_mixed_separators_present("path/to\\file"));
        assert!(fmt.is_redundant_separators_present("path//to/file"));
        assert!(fmt.is_trailing_separator_present("path/to/dir/"));
        assert!(fmt.is_leading_dot_slash_present("./path"));
        assert!(fmt.is_format_issues_present("path//to\\file/"));
        assert!(fmt.is_consistent_format("path/to/file"));
    }

    #[test]
    fn test_path_type_detection() {
        let fmt = FormatBuilder::silent();

        assert!(fmt.is_drive_letter_present("C:\\Windows"));
        assert!(fmt.is_unc_path("\\\\server\\share"));
        assert!(fmt.is_wsl_path("/mnt/c/Users"));
    }

    #[test]
    fn test_separator_conversion() {
        let fmt = FormatBuilder::silent();

        assert_eq!(
            fmt.convert_to_unix("path\\to\\file").as_ref(),
            "path/to/file"
        );
        assert_eq!(
            fmt.convert_to_windows("path/to/file").as_ref(),
            "path\\to\\file"
        );
        assert_eq!(
            fmt.normalize_separators("path/to\\file/test").as_ref(),
            "path/to/file/test"
        );
    }

    #[test]
    fn test_cross_platform_conversion() {
        let fmt = FormatBuilder::silent();

        assert_eq!(
            fmt.convert_to_wsl("C:\\Users\\file"),
            Some("/mnt/c/Users/file".to_string())
        );
        assert_eq!(
            fmt.wsl_to_windows("/mnt/c/Users/file"),
            Some("C:\\Users\\file".to_string())
        );
    }

    #[test]
    fn test_batch_operations() {
        let fmt = FormatBuilder::silent();

        let paths = &["path\\one", "path\\two"];
        let unix = fmt.convert_batch_to_unix(paths);
        assert_eq!(unix, vec!["path/one", "path/two"]);
    }
}
