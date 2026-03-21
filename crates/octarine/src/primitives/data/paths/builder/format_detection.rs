//! Path format detection methods
//!
//! Methods for detecting path formats, separators, and cross-platform conversion.

use std::borrow::Cow;

use super::super::format;
use super::core::PathBuilder;

impl PathBuilder {
    /// Detect the path format (Unix, Windows, WSL, PowerShell, Portable)
    ///
    /// Delegates to [`format::detect_format`].
    #[must_use]
    pub fn detect_format(&self, path: &str) -> format::PathFormat {
        format::detect_format(path)
    }

    /// Detect the separator style used in a path
    ///
    /// Delegates to [`format::detect_separator_style`].
    #[must_use]
    pub fn detect_separator_style(&self, path: &str) -> format::SeparatorStyle {
        format::detect_separator_style(path)
    }

    /// Check if path has any format issues (mixed separators, redundant, etc.)
    ///
    /// Delegates to [`format::is_format_issues_present`].
    #[must_use]
    pub fn is_format_issues_present(&self, path: &str) -> bool {
        format::is_format_issues_present(path)
    }

    /// Check if path is in a consistent format
    ///
    /// Delegates to [`format::is_consistent_format`].
    #[must_use]
    pub fn is_consistent_format(&self, path: &str) -> bool {
        format::is_consistent_format(path)
    }

    /// Check if path has leading dot-slash (./)
    ///
    /// Delegates to [`format::is_leading_dot_slash_present`].
    #[must_use]
    pub fn is_leading_dot_slash_present(&self, path: &str) -> bool {
        format::is_leading_dot_slash_present(path)
    }

    /// Check if path is a WSL mount path (/mnt/c/...)
    ///
    /// Delegates to [`format::is_wsl_path`].
    #[must_use]
    pub fn is_wsl_path(&self, path: &str) -> bool {
        format::is_wsl_path(path)
    }

    /// Convert Windows drive path to WSL format
    ///
    /// Converts `C:\path` to `/mnt/c/path`.
    /// Returns `None` if path doesn't have a drive letter.
    ///
    /// Delegates to [`format::windows_drive_to_wsl`].
    #[must_use]
    pub fn to_wsl(&self, path: &str) -> Option<String> {
        format::windows_drive_to_wsl(path)
    }

    /// Convert WSL path to Windows drive format
    ///
    /// Converts `/mnt/c/path` to `C:\path`.
    /// Returns `None` if path isn't a WSL path.
    ///
    /// Delegates to [`format::wsl_to_windows_drive`].
    #[must_use]
    pub fn wsl_to_windows(&self, path: &str) -> Option<String> {
        format::wsl_to_windows_drive(path)
    }

    /// Convert path to portable format
    ///
    /// Removes platform-specific elements (drive letters, /mnt/X/).
    /// Normalizes separators and removes redundancy.
    ///
    /// Delegates to [`format::to_portable`].
    #[must_use]
    pub fn to_portable<'a>(&self, path: &'a str) -> Cow<'a, str> {
        format::to_portable(path)
    }

    /// Convert path to specified format
    ///
    /// General-purpose conversion between supported formats.
    ///
    /// Delegates to [`format::convert_to_format`].
    #[must_use]
    pub fn convert_format<'a>(&self, path: &'a str, target: format::PathFormat) -> Cow<'a, str> {
        format::convert_to_format(path, target)
    }

    /// Normalize separators to a single style
    ///
    /// Converts mixed separators to the dominant style.
    ///
    /// Delegates to [`format::normalize_separators`].
    #[must_use]
    pub fn normalize_separators<'a>(&self, path: &'a str) -> Cow<'a, str> {
        format::normalize_separators(path)
    }

    /// Strip redundant separators from path
    ///
    /// Converts sequences of separators to single separators.
    ///
    /// Delegates to [`format::strip_redundant_separators`].
    #[must_use]
    pub fn strip_redundant_separators<'a>(&self, path: &'a str) -> Cow<'a, str> {
        format::strip_redundant_separators(path)
    }

    /// Strip trailing separator from path
    ///
    /// Delegates to [`format::strip_trailing_separator`].
    #[must_use]
    pub fn strip_trailing_separator<'a>(&self, path: &'a str) -> &'a str {
        format::strip_trailing_separator(path)
    }

    /// Ensure path has trailing separator
    ///
    /// Delegates to [`format::ensure_trailing_separator`].
    #[must_use]
    pub fn ensure_trailing_separator<'a>(&self, path: &'a str) -> Cow<'a, str> {
        format::ensure_trailing_separator(path)
    }

    /// Strip leading dot-slash from path
    ///
    /// Delegates to [`format::strip_leading_dot_slash`].
    #[must_use]
    pub fn strip_leading_dot_slash<'a>(&self, path: &'a str) -> &'a str {
        format::strip_leading_dot_slash(path)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection() {
        let builder = PathBuilder::new();

        assert_eq!(
            builder.detect_format("/mnt/c/Users"),
            format::PathFormat::Wsl
        );
        assert_eq!(
            builder.detect_format("C:\\Windows"),
            format::PathFormat::Windows
        );
        assert_eq!(
            builder.detect_format("C:/Windows"),
            format::PathFormat::PowerShell
        );
        assert_eq!(
            builder.detect_format("/etc/passwd"),
            format::PathFormat::Unix
        );
        assert_eq!(
            builder.detect_format("relative/path"),
            format::PathFormat::Portable
        );
    }

    #[test]
    fn test_separator_style_detection() {
        let builder = PathBuilder::new();

        assert_eq!(
            builder.detect_separator_style("path/to/file"),
            format::SeparatorStyle::Forward
        );
        assert_eq!(
            builder.detect_separator_style("path\\to\\file"),
            format::SeparatorStyle::Back
        );
        assert_eq!(
            builder.detect_separator_style("path/to\\file"),
            format::SeparatorStyle::Mixed
        );
    }

    #[test]
    fn test_format_issue_detection() {
        let builder = PathBuilder::new();

        assert!(builder.is_format_issues_present("path//to\\file/"));
        assert!(!builder.is_format_issues_present("path/to/file"));

        assert!(builder.is_consistent_format("path/to/file"));
        assert!(!builder.is_consistent_format("path/to\\file"));

        assert!(builder.is_leading_dot_slash_present("./path"));
        assert!(!builder.is_leading_dot_slash_present("path"));
    }

    #[test]
    fn test_cross_platform_conversion() {
        let builder = PathBuilder::new();

        // Windows to WSL
        assert_eq!(
            builder.to_wsl("C:\\Users\\file"),
            Some("/mnt/c/Users/file".to_string())
        );

        // WSL to Windows
        assert_eq!(
            builder.wsl_to_windows("/mnt/c/Users/file"),
            Some("C:\\Users\\file".to_string())
        );

        // To portable
        assert_eq!(
            builder.to_portable("C:\\Users\\file").as_ref(),
            "Users/file"
        );
        assert_eq!(builder.to_portable("/mnt/c/data").as_ref(), "data");

        // Format conversion
        assert_eq!(
            builder
                .convert_format("C:\\Users", format::PathFormat::Wsl)
                .as_ref(),
            "/mnt/c/Users"
        );
    }

    #[test]
    fn test_separator_operations() {
        let builder = PathBuilder::new();

        // Normalize separators
        assert_eq!(
            builder.normalize_separators("path/to\\file/test").as_ref(),
            "path/to/file/test"
        );

        // Strip redundant
        assert_eq!(
            builder
                .strip_redundant_separators("path//to///file")
                .as_ref(),
            "path/to/file"
        );

        // Trailing separator
        assert_eq!(
            builder.strip_trailing_separator("path/to/dir/"),
            "path/to/dir"
        );
        assert_eq!(
            builder.ensure_trailing_separator("path/to/dir").as_ref(),
            "path/to/dir/"
        );

        // Leading dot-slash
        assert_eq!(
            builder.strip_leading_dot_slash("./path/to/file"),
            "path/to/file"
        );
    }

    #[test]
    fn test_is_wsl_path() {
        let builder = PathBuilder::new();

        assert!(builder.is_wsl_path("/mnt/c/Users"));
        assert!(builder.is_wsl_path("/mnt/d/data"));
        assert!(!builder.is_wsl_path("/home/user"));
        assert!(!builder.is_wsl_path("C:\\Windows"));
    }
}
