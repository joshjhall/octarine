//! Character removal functions
//!
//! Functions to remove specific dangerous characters from filenames.

use std::borrow::Cow;

use super::super::detection;

use super::is_bidi_char;

// ============================================================================
// Character Removal Functions
// ============================================================================

/// Strip null bytes from filename
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::strip_null_bytes("file\0.txt").as_ref(), "file.txt");
/// ```
#[must_use]
pub fn strip_null_bytes(filename: &str) -> Cow<'_, str> {
    if detection::is_null_bytes_present(filename) {
        Cow::Owned(filename.replace('\0', ""))
    } else {
        Cow::Borrowed(filename)
    }
}

/// Strip control characters from filename
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::strip_control_chars("file\n.txt").as_ref(), "file.txt");
/// ```
#[must_use]
pub fn strip_control_chars(filename: &str) -> Cow<'_, str> {
    if detection::is_control_characters_present(filename) {
        Cow::Owned(filename.chars().filter(|c| !c.is_ascii_control()).collect())
    } else {
        Cow::Borrowed(filename)
    }
}

/// Strip path separators from filename
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::strip_path_separators("foo/bar.txt").as_ref(), "foobar.txt");
/// ```
#[must_use]
pub fn strip_path_separators(filename: &str) -> Cow<'_, str> {
    if detection::is_path_separators_present(filename) {
        Cow::Owned(
            filename
                .chars()
                .filter(|&c| c != '/' && c != '\\')
                .collect(),
        )
    } else {
        Cow::Borrowed(filename)
    }
}

/// Strip shell metacharacters from filename
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::strip_shell_chars("file;rm.txt").as_ref(), "filerm.txt");
/// ```
#[must_use]
pub fn strip_shell_chars(filename: &str) -> Cow<'_, str> {
    if detection::is_dangerous_shell_chars_present(filename) {
        Cow::Owned(
            filename
                .chars()
                .filter(|c| !detection::DANGEROUS_SHELL_CHARS.contains(c))
                .collect(),
        )
    } else {
        Cow::Borrowed(filename)
    }
}

/// Strip Windows reserved characters from filename
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::strip_reserved_windows_chars("file<name>.txt").as_ref(), "filename.txt");
/// ```
#[must_use]
pub fn strip_reserved_windows_chars(filename: &str) -> Cow<'_, str> {
    if detection::is_reserved_windows_chars_present(filename) {
        Cow::Owned(
            filename
                .chars()
                .filter(|c| !detection::RESERVED_WINDOWS_CHARS.contains(c))
                .collect(),
        )
    } else {
        Cow::Borrowed(filename)
    }
}

/// Strip non-ASCII characters from filename
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::strip_non_ascii("文件file.txt").as_ref(), "file.txt");
/// ```
#[must_use]
pub fn strip_non_ascii(filename: &str) -> Cow<'_, str> {
    if detection::is_non_ascii_present(filename) {
        Cow::Owned(filename.chars().filter(|c| c.is_ascii()).collect())
    } else {
        Cow::Borrowed(filename)
    }
}

/// Strip bidirectional control characters from filename
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::strip_bidi_chars("file\u{202E}.txt").as_ref(), "file.txt");
/// ```
#[must_use]
pub fn strip_bidi_chars(filename: &str) -> Cow<'_, str> {
    if detection::is_bidi_control_present(filename) {
        Cow::Owned(filename.chars().filter(|&c| !is_bidi_char(c)).collect())
    } else {
        Cow::Borrowed(filename)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_strip_null_bytes() {
        assert_eq!(strip_null_bytes("file\0.txt").as_ref(), "file.txt");
        assert_eq!(strip_null_bytes("file.txt").as_ref(), "file.txt");
    }

    #[test]
    fn test_strip_control_chars() {
        assert_eq!(strip_control_chars("file\n.txt").as_ref(), "file.txt");
        assert_eq!(strip_control_chars("file\r\n.txt").as_ref(), "file.txt");
        assert_eq!(strip_control_chars("file.txt").as_ref(), "file.txt");
    }

    #[test]
    fn test_strip_path_separators() {
        assert_eq!(strip_path_separators("foo/bar.txt").as_ref(), "foobar.txt");
        assert_eq!(strip_path_separators("foo\\bar.txt").as_ref(), "foobar.txt");
        assert_eq!(strip_path_separators("file.txt").as_ref(), "file.txt");
    }

    #[test]
    fn test_strip_shell_chars() {
        assert_eq!(strip_shell_chars("file;rm.txt").as_ref(), "filerm.txt");
        assert_eq!(strip_shell_chars("file|cat.txt").as_ref(), "filecat.txt");
        assert_eq!(strip_shell_chars("file.txt").as_ref(), "file.txt");
    }

    #[test]
    fn test_strip_reserved_windows_chars() {
        assert_eq!(
            strip_reserved_windows_chars("file<name>.txt").as_ref(),
            "filename.txt"
        );
        assert_eq!(
            strip_reserved_windows_chars("file:stream.txt").as_ref(),
            "filestream.txt"
        );
    }

    #[test]
    fn test_strip_non_ascii() {
        assert_eq!(strip_non_ascii("文件file.txt").as_ref(), "file.txt");
        assert_eq!(strip_non_ascii("café.txt").as_ref(), "caf.txt");
        assert_eq!(strip_non_ascii("file.txt").as_ref(), "file.txt");
    }

    #[test]
    fn test_strip_bidi_chars() {
        assert_eq!(strip_bidi_chars("file\u{202E}.txt").as_ref(), "file.txt");
        assert_eq!(strip_bidi_chars("file.txt").as_ref(), "file.txt");
    }
}
