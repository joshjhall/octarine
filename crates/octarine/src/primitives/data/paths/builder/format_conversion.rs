//! Format conversion methods
//!
//! Methods for converting paths between Unix and Windows formats.

use super::super::common;
use super::core::PathBuilder;

impl PathBuilder {
    /// Convert path to Unix format (forward slashes)
    #[must_use]
    pub fn to_unix(&self, path: &str) -> String {
        common::to_forward_slashes(path).into_owned()
    }

    /// Convert path to Windows format (backslashes)
    #[must_use]
    pub fn to_windows(&self, path: &str) -> String {
        common::to_backslashes(path).into_owned()
    }

    /// Normalize path for Unix
    ///
    /// Converts separators and removes redundant elements.
    #[must_use]
    pub fn normalize_unix(&self, path: &str) -> String {
        common::normalize_unix(path).into_owned()
    }

    /// Normalize path for Windows
    ///
    /// Converts separators and removes redundant elements.
    #[must_use]
    pub fn normalize_windows(&self, path: &str) -> String {
        common::normalize_windows(path).into_owned()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_to_unix() {
        let builder = PathBuilder::new();

        assert_eq!(builder.to_unix("path\\to\\file"), "path/to/file");
        assert_eq!(
            builder.to_unix("C:\\Windows\\System32"),
            "C:/Windows/System32"
        );
        assert_eq!(builder.to_unix("path/to/file"), "path/to/file");
    }

    #[test]
    fn test_to_windows() {
        let builder = PathBuilder::new();

        assert_eq!(builder.to_windows("path/to/file"), "path\\to\\file");
        assert_eq!(builder.to_windows("/home/user/file"), "\\home\\user\\file");
        assert_eq!(builder.to_windows("path\\to\\file"), "path\\to\\file");
    }

    #[test]
    fn test_normalize_unix() {
        let builder = PathBuilder::new();

        assert_eq!(builder.normalize_unix("path\\to\\file"), "path/to/file");
        assert_eq!(builder.normalize_unix("path//to//file"), "path/to/file");
    }

    #[test]
    fn test_normalize_windows() {
        let builder = PathBuilder::new();

        assert_eq!(builder.normalize_windows("path/to/file"), "path\\to\\file");
        assert_eq!(
            builder.normalize_windows("path\\\\to\\\\file"),
            "path\\to\\file"
        );
    }
}
