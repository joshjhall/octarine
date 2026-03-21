//! Path type and platform detection
//!
//! Methods for detecting path types and platforms.

use super::super::characteristic;
use super::super::types::{PathType, Platform};
use super::core::PathBuilder;

impl PathBuilder {
    /// Detect the type/format of a path
    ///
    /// Returns the detected path type (Unix/Windows, absolute/relative).
    /// Delegates to [`characteristic::detect_path_type`].
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let builder = PathBuilder::new();
    /// assert_eq!(builder.detect_path_type("/etc/passwd"), PathType::UnixAbsolute);
    /// assert_eq!(builder.detect_path_type("C:\\Windows"), PathType::WindowsAbsolute);
    /// ```
    #[must_use]
    pub fn detect_path_type(&self, path: &str) -> PathType {
        characteristic::detect_path_type(path)
    }

    /// Detect platform from path format
    ///
    /// Returns the detected platform based on path conventions.
    /// Delegates to [`characteristic::detect_platform`].
    #[must_use]
    pub fn detect_platform(&self, path: &str) -> Platform {
        characteristic::detect_platform(path)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_path_type_unix() {
        let builder = PathBuilder::new();

        assert_eq!(
            builder.detect_path_type("/etc/passwd"),
            PathType::UnixAbsolute
        );
        assert_eq!(builder.detect_path_type("/"), PathType::UnixAbsolute);
        assert_eq!(
            builder.detect_path_type("/home/user/file.txt"),
            PathType::UnixAbsolute
        );

        assert_eq!(
            builder.detect_path_type("path/to/file"),
            PathType::UnixRelative
        );
        assert_eq!(builder.detect_path_type("./file"), PathType::UnixRelative);
        assert_eq!(builder.detect_path_type("file.txt"), PathType::UnixRelative);
    }

    #[test]
    fn test_detect_path_type_windows() {
        let builder = PathBuilder::new();

        assert_eq!(
            builder.detect_path_type("C:\\Windows"),
            PathType::WindowsAbsolute
        );
        assert_eq!(builder.detect_path_type("D:\\"), PathType::WindowsAbsolute);
        assert_eq!(
            builder.detect_path_type("\\\\server\\share"),
            PathType::WindowsUnc
        );
        assert_eq!(
            builder.detect_path_type("path\\to\\file"),
            PathType::WindowsRelative
        );
    }

    #[test]
    fn test_detect_path_type_empty() {
        let builder = PathBuilder::new();
        assert_eq!(builder.detect_path_type(""), PathType::Unknown);
    }

    #[test]
    fn test_detect_platform() {
        let builder = PathBuilder::new();

        assert_eq!(builder.detect_platform("/etc/passwd"), Platform::Unix);
        assert_eq!(builder.detect_platform("C:\\Windows"), Platform::Windows);
        assert_eq!(builder.detect_platform("path/to/file"), Platform::Unix);
    }
}
