//! Dangerous character detection functions
//!
//! Functions to detect dangerous characters in filenames.

use super::constants::{DANGEROUS_SHELL_CHARS, RESERVED_WINDOWS_CHARS};

// ============================================================================
// Dangerous Character Detection
// ============================================================================

/// Check if filename contains null bytes
///
/// Null bytes can truncate strings in C APIs, potentially
/// allowing security bypasses.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert!(detection::is_null_bytes_present("file\0.txt"));
/// assert!(!detection::is_null_bytes_present("file.txt"));
/// ```
#[must_use]
pub fn is_null_bytes_present(filename: &str) -> bool {
    filename.contains('\0')
}

/// Check if filename contains control characters
///
/// Control characters (ASCII 0-31, 127) can cause parsing issues
/// and log injection attacks.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert!(detection::is_control_characters_present("file\n.txt"));
/// assert!(detection::is_control_characters_present("file\r.txt"));
/// assert!(!detection::is_control_characters_present("file.txt"));
/// ```
#[must_use]
pub fn is_control_characters_present(filename: &str) -> bool {
    filename.chars().any(|c| c.is_ascii_control())
}

/// Check if filename contains dangerous shell characters
///
/// These characters can enable command injection in shell contexts.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert!(detection::is_dangerous_shell_chars_present("file;rm.txt"));
/// assert!(detection::is_dangerous_shell_chars_present("file|cat.txt"));
/// assert!(detection::is_dangerous_shell_chars_present("$(cmd).txt"));
/// assert!(!detection::is_dangerous_shell_chars_present("file.txt"));
/// ```
#[must_use]
pub fn is_dangerous_shell_chars_present(filename: &str) -> bool {
    filename.chars().any(|c| DANGEROUS_SHELL_CHARS.contains(&c))
}

/// Check if filename contains Windows reserved characters
///
/// These characters are not allowed in Windows filenames.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert!(detection::is_reserved_windows_chars_present("file<name>.txt"));
/// assert!(detection::is_reserved_windows_chars_present("file:stream.txt"));
/// assert!(!detection::is_reserved_windows_chars_present("file.txt"));
/// ```
#[must_use]
pub fn is_reserved_windows_chars_present(filename: &str) -> bool {
    filename
        .chars()
        .any(|c| RESERVED_WINDOWS_CHARS.contains(&c))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_null_bytes_present() {
        assert!(is_null_bytes_present("file\0.txt"));
        assert!(is_null_bytes_present("file\0"));
        assert!(!is_null_bytes_present("file.txt"));
    }

    #[test]
    fn test_is_control_characters_present() {
        assert!(is_control_characters_present("file\n.txt"));
        assert!(is_control_characters_present("file\r.txt"));
        assert!(is_control_characters_present("file\t.txt"));
        assert!(is_control_characters_present("file\x1b.txt")); // ESC
        assert!(!is_control_characters_present("file.txt"));
    }

    #[test]
    fn test_is_dangerous_shell_chars_present() {
        assert!(is_dangerous_shell_chars_present("file;rm.txt"));
        assert!(is_dangerous_shell_chars_present("file|cat.txt"));
        assert!(is_dangerous_shell_chars_present("file&bg.txt"));
        assert!(is_dangerous_shell_chars_present("file$var.txt"));
        assert!(is_dangerous_shell_chars_present("file`cmd`.txt"));
        assert!(!is_dangerous_shell_chars_present("file.txt"));
        assert!(!is_dangerous_shell_chars_present("file-name_123.txt"));
    }

    #[test]
    fn test_is_reserved_windows_chars_present() {
        assert!(is_reserved_windows_chars_present("file<name>.txt"));
        assert!(is_reserved_windows_chars_present("file:stream.txt"));
        assert!(is_reserved_windows_chars_present("file|name.txt"));
        assert!(is_reserved_windows_chars_present("file?.txt"));
        assert!(is_reserved_windows_chars_present("file*.txt"));
        assert!(!is_reserved_windows_chars_present("file.txt"));
    }
}
