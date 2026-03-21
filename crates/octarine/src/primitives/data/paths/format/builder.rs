//! Format builder API
//!
//! Provides a builder interface for path format detection and conversion operations.
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only

use std::borrow::Cow;

use super::conversion;
use super::detection::{self, PathFormat, SeparatorStyle};

/// Builder for path format detection and conversion operations
///
/// Provides a fluent interface for detecting path formats and converting
/// between different path format styles (Unix, Windows, WSL, etc.).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::format::FormatBuilder;
/// use octarine::primitives::paths::format::detection::PathFormat;
///
/// let format = FormatBuilder::new();
///
/// // Detection
/// assert_eq!(format.detect("C:\\Windows"), PathFormat::Windows);
/// assert_eq!(format.detect("/mnt/c/Users"), PathFormat::Wsl);
///
/// // Conversion
/// assert_eq!(format.convert_to_unix("path\\to\\file"), "path/to/file");
/// assert_eq!(format.convert_to_wsl("C:\\Users\\file"), Some("/mnt/c/Users/file".to_string()));
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct FormatBuilder;

impl FormatBuilder {
    /// Create a new format builder
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    // ========================================================================
    // Format Detection
    // ========================================================================

    /// Detect the format of a path
    ///
    /// # Arguments
    ///
    /// * `path` - Path to analyze
    ///
    /// # Returns
    ///
    /// `PathFormat` indicating the detected format
    #[must_use]
    pub fn detect(&self, path: &str) -> PathFormat {
        detection::detect_format(path)
    }

    /// Detect the separator style used in a path
    ///
    /// # Arguments
    ///
    /// * `path` - Path to analyze
    ///
    /// # Returns
    ///
    /// `SeparatorStyle` indicating the separator pattern
    #[must_use]
    pub fn detect_separator_style(&self, path: &str) -> SeparatorStyle {
        detection::detect_separator_style(path)
    }

    // ========================================================================
    // Format Checks
    // ========================================================================

    /// Check if path has mixed separators
    #[must_use]
    pub fn is_mixed_separators_present(&self, path: &str) -> bool {
        detection::is_mixed_separators_present(path)
    }

    /// Check if path has redundant separators
    #[must_use]
    pub fn is_redundant_separators_present(&self, path: &str) -> bool {
        detection::is_redundant_separators_present(path)
    }

    /// Check if path has trailing separator
    #[must_use]
    pub fn is_trailing_separator_present(&self, path: &str) -> bool {
        detection::is_trailing_separator_present(path)
    }

    /// Check if path has leading dot-slash (./)
    #[must_use]
    pub fn is_leading_dot_slash_present(&self, path: &str) -> bool {
        detection::is_leading_dot_slash_present(path)
    }

    /// Check if path has Windows separators (backslashes)
    #[must_use]
    pub fn is_windows_separators_present(&self, path: &str) -> bool {
        detection::is_windows_separators_present(path)
    }

    /// Check if path has POSIX separators (forward slashes)
    #[must_use]
    pub fn is_posix_separators_present(&self, path: &str) -> bool {
        detection::is_posix_separators_present(path)
    }

    /// Check if path has any format issues
    #[must_use]
    pub fn is_format_issues_present(&self, path: &str) -> bool {
        detection::is_format_issues_present(path)
    }

    /// Check if path is in a consistent format
    #[must_use]
    pub fn is_consistent_format(&self, path: &str) -> bool {
        detection::is_consistent_format(path)
    }

    /// Check if path exceeds length limit
    #[must_use]
    pub fn exceeds_length_limit(&self, path: &str) -> bool {
        detection::exceeds_length_limit(path)
    }

    // ========================================================================
    // Path Type Detection
    // ========================================================================

    /// Check if path has a Windows drive letter
    #[must_use]
    pub fn is_drive_letter_present(&self, path: &str) -> bool {
        detection::is_drive_letter_present(path)
    }

    /// Check if path is a UNC path
    #[must_use]
    pub fn is_unc_path(&self, path: &str) -> bool {
        detection::is_unc_path(path)
    }

    /// Check if path is a WSL mount path
    #[must_use]
    pub fn is_wsl_path(&self, path: &str) -> bool {
        detection::is_wsl_path(path)
    }

    /// Find drive letter from Windows path
    #[must_use]
    pub fn find_drive_letter(&self, path: &str) -> Option<char> {
        detection::find_drive_letter(path)
    }

    /// Find drive letter from WSL path
    #[must_use]
    pub fn find_wsl_drive_letter(&self, path: &str) -> Option<char> {
        detection::find_wsl_drive_letter(path)
    }

    // ========================================================================
    // Separator Conversion
    // ========================================================================

    /// Convert path to Unix-style (forward slashes)
    #[must_use]
    pub fn convert_to_unix<'a>(&self, path: &'a str) -> Cow<'a, str> {
        conversion::to_unix(path)
    }

    /// Convert path to Windows-style (backslashes)
    #[must_use]
    pub fn convert_to_windows<'a>(&self, path: &'a str) -> Cow<'a, str> {
        conversion::to_windows(path)
    }

    /// Convert path to native platform style
    #[must_use]
    pub fn convert_to_native<'a>(&self, path: &'a str) -> Cow<'a, str> {
        conversion::to_native(path)
    }

    /// Normalize separators to a single style
    #[must_use]
    pub fn normalize_separators<'a>(&self, path: &'a str) -> Cow<'a, str> {
        conversion::normalize_separators(path)
    }

    // ========================================================================
    // Separator Cleanup
    // ========================================================================

    /// Strip redundant separators from path
    #[must_use]
    pub fn strip_redundant_separators<'a>(&self, path: &'a str) -> Cow<'a, str> {
        conversion::strip_redundant_separators(path)
    }

    /// Strip trailing separator from path
    #[must_use]
    pub fn strip_trailing_separator<'a>(&self, path: &'a str) -> &'a str {
        conversion::strip_trailing_separator(path)
    }

    /// Ensure path has trailing separator
    #[must_use]
    pub fn ensure_trailing_separator<'a>(&self, path: &'a str) -> Cow<'a, str> {
        conversion::ensure_trailing_separator(path)
    }

    /// Strip leading dot-slash from path
    #[must_use]
    pub fn strip_leading_dot_slash<'a>(&self, path: &'a str) -> &'a str {
        conversion::strip_leading_dot_slash(path)
    }

    // ========================================================================
    // Cross-Platform Conversion
    // ========================================================================

    /// Convert Windows drive path to WSL format
    ///
    /// Converts `C:\path` to `/mnt/c/path`.
    #[must_use]
    pub fn convert_to_wsl(&self, path: &str) -> Option<String> {
        conversion::windows_drive_to_wsl(path)
    }

    /// Convert Windows drive path to Unix format (without drive letter)
    ///
    /// Converts `C:\path` to `/path`.
    #[must_use]
    pub fn windows_to_unix(&self, path: &str) -> Option<String> {
        conversion::windows_drive_to_unix(path)
    }

    /// Convert WSL path to Windows drive format
    ///
    /// Converts `/mnt/c/path` to `C:\path`.
    #[must_use]
    pub fn wsl_to_windows(&self, path: &str) -> Option<String> {
        conversion::wsl_to_windows_drive(path)
    }

    /// Convert path to portable format
    ///
    /// Removes platform-specific elements and normalizes.
    #[must_use]
    pub fn convert_to_portable<'a>(&self, path: &'a str) -> Cow<'a, str> {
        conversion::to_portable(path)
    }

    /// Convert path to target format
    ///
    /// General-purpose conversion to any supported format.
    #[must_use]
    pub fn convert<'a>(&self, path: &'a str, target: PathFormat) -> Cow<'a, str> {
        conversion::convert_to_format(path, target)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_new() {
        let builder = FormatBuilder::new();
        assert_eq!(builder.detect("/etc/passwd"), PathFormat::Unix);
    }

    #[test]
    fn test_builder_default() {
        let builder = FormatBuilder;
        assert_eq!(builder.detect("C:\\Windows"), PathFormat::Windows);
    }

    // Detection tests
    #[test]
    fn test_builder_detect() {
        let builder = FormatBuilder::new();

        assert_eq!(builder.detect("/mnt/c/Users"), PathFormat::Wsl);
        assert_eq!(builder.detect("C:\\Windows"), PathFormat::Windows);
        assert_eq!(builder.detect("C:/Windows"), PathFormat::PowerShell);
        assert_eq!(builder.detect("/etc/passwd"), PathFormat::Unix);
        assert_eq!(builder.detect("relative/path"), PathFormat::Portable);
    }

    #[test]
    fn test_builder_detect_separator_style() {
        let builder = FormatBuilder::new();

        assert_eq!(
            builder.detect_separator_style("path/to/file"),
            SeparatorStyle::Forward
        );
        assert_eq!(
            builder.detect_separator_style("path\\to\\file"),
            SeparatorStyle::Back
        );
        assert_eq!(
            builder.detect_separator_style("path/to\\file"),
            SeparatorStyle::Mixed
        );
        assert_eq!(
            builder.detect_separator_style("file.txt"),
            SeparatorStyle::None
        );
    }

    // Format check tests
    #[test]
    fn test_builder_format_checks() {
        let builder = FormatBuilder::new();

        assert!(builder.is_mixed_separators_present("path/to\\file"));
        assert!(!builder.is_mixed_separators_present("path/to/file"));

        assert!(builder.is_redundant_separators_present("path//to/file"));
        assert!(!builder.is_redundant_separators_present("path/to/file"));

        assert!(builder.is_trailing_separator_present("path/to/dir/"));
        assert!(!builder.is_trailing_separator_present("path/to/file"));

        assert!(builder.is_leading_dot_slash_present("./path"));
        assert!(!builder.is_leading_dot_slash_present("path"));
    }

    #[test]
    fn test_builder_has_format_issues() {
        let builder = FormatBuilder::new();

        assert!(builder.is_format_issues_present("path//to\\file/"));
        assert!(!builder.is_format_issues_present("path/to/file"));

        assert!(builder.is_consistent_format("path/to/file"));
        assert!(!builder.is_consistent_format("path/to\\file"));
    }

    // Path type detection tests
    #[test]
    fn test_builder_path_type_detection() {
        let builder = FormatBuilder::new();

        assert!(builder.is_drive_letter_present("C:\\Windows"));
        assert!(!builder.is_drive_letter_present("/home/user"));

        assert!(builder.is_unc_path("\\\\server\\share"));
        assert!(!builder.is_unc_path("C:\\Windows"));

        assert!(builder.is_wsl_path("/mnt/c/Users"));
        assert!(!builder.is_wsl_path("/home/user"));
    }

    #[test]
    fn test_builder_find_drive_letter() {
        let builder = FormatBuilder::new();

        assert_eq!(builder.find_drive_letter("C:\\Windows"), Some('C'));
        assert_eq!(builder.find_drive_letter("d:/data"), Some('D'));
        assert_eq!(builder.find_drive_letter("/home"), None);

        assert_eq!(builder.find_wsl_drive_letter("/mnt/c/Users"), Some('C'));
        assert_eq!(builder.find_wsl_drive_letter("/home"), None);
    }

    // Separator conversion tests
    #[test]
    fn test_builder_separator_conversion() {
        let builder = FormatBuilder::new();

        assert_eq!(
            builder.convert_to_unix("path\\to\\file").as_ref(),
            "path/to/file"
        );
        assert_eq!(
            builder.convert_to_windows("path/to/file").as_ref(),
            "path\\to\\file"
        );
    }

    #[test]
    fn test_builder_normalize_separators() {
        let builder = FormatBuilder::new();

        assert_eq!(
            builder.normalize_separators("path/to\\file/test").as_ref(),
            "path/to/file/test"
        );
    }

    // Separator cleanup tests
    #[test]
    fn test_builder_separator_cleanup() {
        let builder = FormatBuilder::new();

        assert_eq!(
            builder.strip_redundant_separators("path//to/file").as_ref(),
            "path/to/file"
        );
        assert_eq!(
            builder.strip_trailing_separator("path/to/dir/"),
            "path/to/dir"
        );
        assert_eq!(
            builder.ensure_trailing_separator("path/to/dir").as_ref(),
            "path/to/dir/"
        );
        assert_eq!(
            builder.strip_leading_dot_slash("./path/to/file"),
            "path/to/file"
        );
    }

    // Cross-platform conversion tests
    #[test]
    fn test_builder_cross_platform() {
        let builder = FormatBuilder::new();

        assert_eq!(
            builder.convert_to_wsl("C:\\Users\\file"),
            Some("/mnt/c/Users/file".to_string())
        );
        assert_eq!(
            builder.windows_to_unix("C:\\Users\\file"),
            Some("/Users/file".to_string())
        );
        assert_eq!(
            builder.wsl_to_windows("/mnt/c/Users/file"),
            Some("C:\\Users\\file".to_string())
        );
    }

    #[test]
    fn test_builder_convert_to_portable() {
        let builder = FormatBuilder::new();

        assert_eq!(
            builder.convert_to_portable("C:\\Users\\file").as_ref(),
            "Users/file"
        );
        assert_eq!(builder.convert_to_portable("/mnt/c/data").as_ref(), "data");
    }

    #[test]
    fn test_builder_convert() {
        let builder = FormatBuilder::new();

        assert_eq!(
            builder.convert("C:\\Users", PathFormat::Wsl).as_ref(),
            "/mnt/c/Users"
        );
        assert_eq!(
            builder
                .convert("/mnt/c/Users", PathFormat::Windows)
                .as_ref(),
            "C:\\Users"
        );
        assert_eq!(
            builder.convert("path\\to\\file", PathFormat::Unix).as_ref(),
            "path/to/file"
        );
    }
}
