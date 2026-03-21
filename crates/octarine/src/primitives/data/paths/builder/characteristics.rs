//! Path characteristic detection
//!
//! Methods for checking path properties like absolute/relative, portable, etc.

use super::super::characteristic;
use super::core::PathBuilder;

impl PathBuilder {
    /// Check if path is absolute
    ///
    /// Detects absolute paths on any platform:
    /// - Unix: Starts with `/`
    /// - Windows: Drive letter or UNC path
    ///
    /// Delegates to [`characteristic::is_absolute`].
    #[must_use]
    pub fn is_absolute(&self, path: &str) -> bool {
        characteristic::is_absolute(path)
    }

    /// Check if path is relative
    ///
    /// A path is relative if it's not absolute.
    /// Delegates to [`characteristic::is_relative`].
    #[must_use]
    pub fn is_relative(&self, path: &str) -> bool {
        characteristic::is_relative(path)
    }

    /// Check if path is portable (works on both Windows and Unix)
    ///
    /// A portable path:
    /// - Uses only forward slashes
    /// - No drive letters
    /// - No UNC paths
    /// - Is relative
    ///
    /// Delegates to [`characteristic::is_portable`].
    #[must_use]
    pub fn is_portable(&self, path: &str) -> bool {
        characteristic::is_portable(path)
    }

    /// Check if path is Unix-style
    ///
    /// Delegates to [`characteristic::is_unix_path`].
    #[must_use]
    pub fn is_unix_style(&self, path: &str) -> bool {
        characteristic::is_unix_path(path)
    }

    /// Check if path is Windows-style
    ///
    /// Delegates to [`characteristic::is_windows_path`].
    #[must_use]
    pub fn is_windows_style(&self, path: &str) -> bool {
        characteristic::is_windows_path(path)
    }

    /// Check if path has mixed separators
    ///
    /// Delegates to [`characteristic::is_mixed_separators_present`].
    #[must_use]
    pub fn is_mixed_separators_present(&self, path: &str) -> bool {
        characteristic::is_mixed_separators_present(path)
    }

    /// Check if any path component is hidden
    ///
    /// Delegates to [`characteristic::is_hidden_component_present`].
    #[must_use]
    pub fn is_hidden_component_present(&self, path: &str) -> bool {
        characteristic::is_hidden_component_present(path)
    }

    /// Check if path refers to hidden file/directory
    ///
    /// On Unix, hidden files start with a dot.
    /// On Windows, hidden files are a filesystem attribute (not detectable from path).
    ///
    /// Delegates to [`characteristic::is_hidden`].
    #[must_use]
    pub fn is_hidden(&self, path: &str) -> bool {
        characteristic::is_hidden(path)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_is_absolute_relative() {
        let builder = PathBuilder::new();

        assert!(builder.is_absolute("/etc/passwd"));
        assert!(builder.is_absolute("C:\\Windows"));
        assert!(builder.is_absolute("\\\\server\\share"));

        assert!(builder.is_relative("path/to/file"));
        assert!(builder.is_relative("./file"));
        assert!(builder.is_relative("file.txt"));
    }

    #[test]
    fn test_is_portable() {
        let builder = PathBuilder::new();

        assert!(builder.is_portable("path/to/file"));
        assert!(builder.is_portable("./file"));

        assert!(!builder.is_portable("/etc/passwd"));
        assert!(!builder.is_portable("C:\\Windows"));
        assert!(!builder.is_portable("path\\to\\file"));
    }

    #[test]
    fn test_is_unix_windows_style() {
        let builder = PathBuilder::new();

        assert!(builder.is_unix_style("/etc/passwd"));
        assert!(builder.is_unix_style("path/to/file"));

        assert!(builder.is_windows_style("C:\\Windows"));
        assert!(builder.is_windows_style("path\\to\\file"));
    }

    #[test]
    fn test_is_mixed_separators_present() {
        let builder = PathBuilder::new();

        assert!(builder.is_mixed_separators_present("path/to\\file"));
        assert!(builder.is_mixed_separators_present("C:\\path/file"));

        assert!(!builder.is_mixed_separators_present("path/to/file"));
        assert!(!builder.is_mixed_separators_present("path\\to\\file"));
    }

    #[test]
    fn test_is_hidden() {
        let builder = PathBuilder::new();

        assert!(builder.is_hidden(".hidden"));
        assert!(builder.is_hidden("/path/to/.hidden"));
        assert!(builder.is_hidden(".config"));
        assert!(builder.is_hidden("/home/user/.bashrc"));

        assert!(!builder.is_hidden("visible"));
        assert!(!builder.is_hidden(".config/file"));
        assert!(!builder.is_hidden("."));
        assert!(!builder.is_hidden(".."));
    }

    #[test]
    fn test_is_hidden_component_present() {
        let builder = PathBuilder::new();

        assert!(builder.is_hidden_component_present("/path/.hidden/file"));
        assert!(builder.is_hidden_component_present(".config/settings"));

        assert!(!builder.is_hidden_component_present("/path/to/file"));
    }
}
