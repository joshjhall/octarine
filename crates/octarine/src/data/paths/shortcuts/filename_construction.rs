//! Filename construction shortcuts
//!
//! Convenience functions for creating and manipulating filenames.

use super::super::FilenameBuilder;

// ============================================================
// FILENAME CONSTRUCTION SHORTCUTS
// ============================================================

/// Set the extension of a filename
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::set_extension;
/// let name = set_extension("document.txt", "pdf");
/// assert_eq!(name, "document.pdf");
/// ```
pub fn set_extension(filename: &str, extension: &str) -> String {
    FilenameBuilder::new().set_extension(filename, extension)
}

/// Add an extension to a filename
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::add_extension;
/// let name = add_extension("archive.tar", "gz");
/// assert_eq!(name, "archive.tar.gz");
/// ```
pub fn add_extension(filename: &str, extension: &str) -> String {
    FilenameBuilder::new().add_extension(filename, extension)
}

/// Remove the extension from a filename
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::strip_extension;
/// let name = strip_extension("document.pdf");
/// assert_eq!(name, "document");
/// ```
pub fn strip_extension(filename: &str) -> String {
    FilenameBuilder::new().strip_extension(filename)
}

/// Create a numbered filename (file_1.txt, file_2.txt, etc.)
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::numbered_filename;
/// let name = numbered_filename("backup.sql", 3);
/// assert_eq!(name, "backup_3.sql");
/// ```
pub fn numbered_filename(filename: &str, number: u32) -> String {
    FilenameBuilder::new().with_number(filename, number)
}

/// Create a timestamped filename
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::timestamped_filename;
/// let name = timestamped_filename("log", "txt");
/// // Returns something like "log_20231215_143052.txt"
/// assert!(name.starts_with("log_"));
/// assert!(name.ends_with(".txt"));
/// ```
pub fn timestamped_filename(prefix: &str, extension: &str) -> String {
    FilenameBuilder::new().with_timestamp(prefix, extension)
}

/// Create a UUID-based filename
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::uuid_filename;
/// let name = uuid_filename("upload", "jpg");
/// // Returns something like "upload_550e8400-e29b-41d4-a716-446655440000.jpg"
/// assert!(name.starts_with("upload_"));
/// assert!(name.ends_with(".jpg"));
/// ```
pub fn uuid_filename(prefix: &str, extension: &str) -> String {
    FilenameBuilder::new().with_uuid(prefix, extension)
}

/// Shell-escape a filename for safe command-line use
///
/// # Examples
///
/// ```rust
/// use octarine::data::paths::shell_escape_filename;
/// let escaped = shell_escape_filename("file with spaces.txt");
/// assert_eq!(escaped, "'file with spaces.txt'");
/// ```
pub fn shell_escape_filename(filename: &str) -> String {
    FilenameBuilder::new().shell_escape(filename)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_filename_construction() {
        assert_eq!(set_extension("doc.txt", "pdf"), "doc.pdf");
        assert_eq!(add_extension("archive.tar", "gz"), "archive.tar.gz");
        assert_eq!(strip_extension("doc.pdf"), "doc");
        assert_eq!(numbered_filename("backup.sql", 3), "backup_3.sql");
    }

    #[test]
    fn test_shell_escape() {
        let escaped = shell_escape_filename("file with spaces.txt");
        assert_eq!(escaped, "'file with spaces.txt'");
    }
}
