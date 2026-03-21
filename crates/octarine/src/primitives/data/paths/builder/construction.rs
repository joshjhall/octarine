//! Path construction methods
//!
//! Methods for joining, splitting, and manipulating paths.

use super::super::common;
use super::super::types::Platform;
use super::core::PathBuilder;

impl PathBuilder {
    /// Join two path segments
    ///
    /// Uses Unix separators by default.
    #[must_use]
    pub fn join(&self, base: &str, path: &str) -> String {
        match self.platform {
            Platform::Windows => common::join_windows(base, path),
            Platform::Unix | Platform::Auto => common::join_unix(base, path),
        }
    }

    /// Join two paths using Unix separators
    #[must_use]
    pub fn join_unix(&self, base: &str, path: &str) -> String {
        common::join_unix(base, path)
    }

    /// Join two paths using Windows separators
    #[must_use]
    pub fn join_windows(&self, base: &str, path: &str) -> String {
        common::join_windows(base, path)
    }

    /// Get parent directory
    #[must_use]
    pub fn find_parent<'a>(&self, path: &'a str) -> Option<&'a str> {
        common::find_parent(path)
    }

    /// Get filename component
    #[must_use]
    pub fn filename<'a>(&self, path: &'a str) -> &'a str {
        common::filename(path)
    }

    /// Get file stem (filename without extension)
    #[must_use]
    pub fn stem<'a>(&self, path: &'a str) -> &'a str {
        common::stem(path)
    }

    /// Get file extension
    #[must_use]
    pub fn find_extension<'a>(&self, path: &'a str) -> Option<&'a str> {
        common::find_extension(path)
    }

    /// Split path into components
    #[must_use]
    pub fn split<'a>(&self, path: &'a str) -> Vec<&'a str> {
        common::split(path)
    }

    /// Get ancestors (parent paths) of a path
    ///
    /// Returns a vector of parent paths from immediate parent to root.
    #[must_use]
    pub fn ancestors<'a>(&self, path: &'a str) -> Vec<&'a str> {
        common::ancestors(path)
    }

    /// Clean path by resolving `.` and `..` components
    ///
    /// This is a logical operation - does not access the filesystem.
    #[must_use]
    pub fn clean_path(&self, path: &str) -> String {
        common::clean_path(path)
    }

    /// Convert a relative path to absolute by resolving against a base
    #[must_use]
    pub fn to_absolute_path(&self, base: &str, path: &str) -> String {
        common::to_absolute_path(base, path)
    }

    /// Convert an absolute path to a relative path from one location to another
    #[must_use]
    pub fn to_relative_path(&self, from: &str, to: &str) -> String {
        common::to_relative_path(from, to)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_join() {
        let builder = PathBuilder::new();
        assert_eq!(builder.join("base", "file.txt"), "base/file.txt");
        assert_eq!(
            builder.join("/home/user", "file.txt"),
            "/home/user/file.txt"
        );
    }

    #[test]
    fn test_join_platform() {
        let unix_builder = PathBuilder::for_platform(Platform::Unix);
        assert_eq!(unix_builder.join("base", "file"), "base/file");

        let win_builder = PathBuilder::for_platform(Platform::Windows);
        assert_eq!(win_builder.join("base", "file"), "base\\file");
    }

    #[test]
    fn test_join_unix_windows() {
        let builder = PathBuilder::new();

        assert_eq!(builder.join_unix("base", "file"), "base/file");
        assert_eq!(builder.join_windows("base", "file"), "base\\file");
    }

    #[test]
    fn test_find_parent() {
        let builder = PathBuilder::new();

        assert_eq!(
            builder.find_parent("/home/user/file.txt"),
            Some("/home/user")
        );
        // Trailing slash is preserved - parent of /home/user/ is /home/user
        assert_eq!(builder.find_parent("/home/user/"), Some("/home/user"));
        // Single component after root - parent is root
        assert_eq!(builder.find_parent("/home"), Some("/"));
        assert_eq!(builder.find_parent("/"), None);
    }

    #[test]
    fn test_filename() {
        let builder = PathBuilder::new();

        assert_eq!(builder.filename("/home/user/file.txt"), "file.txt");
        assert_eq!(builder.filename("file.txt"), "file.txt");
        // Note: trailing slash is stripped, then filename is extracted
        assert_eq!(builder.filename("/home/user/"), "");
    }

    #[test]
    fn test_stem() {
        let builder = PathBuilder::new();

        assert_eq!(builder.stem("/home/user/file.txt"), "file");
        assert_eq!(builder.stem("archive.tar.gz"), "archive.tar");
        assert_eq!(builder.stem("noext"), "noext");
    }

    #[test]
    fn test_extension() {
        let builder = PathBuilder::new();

        assert_eq!(builder.find_extension("/home/user/file.txt"), Some("txt"));
        assert_eq!(builder.find_extension("archive.tar.gz"), Some("gz"));
        assert_eq!(builder.find_extension("noext"), None);
    }

    #[test]
    fn test_split() {
        let builder = PathBuilder::new();

        // split includes empty string for leading separator
        let parts = builder.split("/home/user/file");
        assert!(parts.contains(&"home"));
        assert!(parts.contains(&"user"));
        assert!(parts.contains(&"file"));

        assert_eq!(builder.split("path/to/file"), vec!["path", "to", "file"]);
    }

    #[test]
    fn test_ancestors() {
        let builder = PathBuilder::new();

        let ancestors = builder.ancestors("/home/user/file.txt");
        assert!(ancestors.contains(&"/home/user"));
        assert!(ancestors.contains(&"/home"));
    }

    #[test]
    fn test_clean_path() {
        let builder = PathBuilder::new();

        assert_eq!(
            builder.clean_path("path/to/../other/./file"),
            "path/other/file"
        );
        assert_eq!(builder.clean_path("./path/./to/file"), "path/to/file");
    }

    #[test]
    fn test_to_absolute_path() {
        let builder = PathBuilder::new();

        assert_eq!(
            builder.to_absolute_path("/home/user", "file.txt"),
            "/home/user/file.txt"
        );
    }

    #[test]
    fn test_to_relative_path() {
        let builder = PathBuilder::new();

        let relative = builder.to_relative_path("/home/user", "/home/user/docs/file.txt");
        assert!(relative.contains("docs"));
    }
}
