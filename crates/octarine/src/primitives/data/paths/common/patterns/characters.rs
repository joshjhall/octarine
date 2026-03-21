//! Character validation patterns
//!
//! Core detection functions for dangerous characters in paths.
//! These are pure functions with NO observe dependencies.
//!
//! ## Coverage
//!
//! - Null bytes: `\0` (CWE-158)
//! - Control characters: `\n`, `\r`, `\t`, ASCII 0x00-0x1F, 0x7F
//! - Empty/whitespace-only input validation
//!
//! ## Design Principles
//!
//! 1. **Pure Functions**: No logging, no side effects
//! 2. **Detection Only**: Returns bool, no Result types
//! 3. **Reusable**: Used by validation and sanitization layers
//!
//! ## Security Standards
//!
//! - CWE-158: Null Byte Injection
//! - CWE-707: Improper Neutralization

// ============================================================================
// Empty/Whitespace Detection
// ============================================================================

/// Check if path is empty
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::characters;
///
/// assert!(characters::is_empty(""));
/// assert!(!characters::is_empty("file.txt"));
/// ```
#[must_use]
pub fn is_empty(path: &str) -> bool {
    path.is_empty()
}

/// Check if path is whitespace-only
///
/// Whitespace-only paths are invalid as they cannot represent valid
/// filesystem paths and may indicate input sanitization bypass attempts.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::characters;
///
/// assert!(characters::is_whitespace_only("   "));
/// assert!(characters::is_whitespace_only("\t\n"));
/// assert!(!characters::is_whitespace_only("file.txt"));
/// assert!(!characters::is_whitespace_only("")); // Empty is different
/// ```
#[must_use]
pub fn is_whitespace_only(path: &str) -> bool {
    !path.is_empty() && path.trim().is_empty()
}

/// Check if path is empty or whitespace-only
///
/// Combined check for invalid empty paths.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::characters;
///
/// assert!(characters::is_empty_or_whitespace(""));
/// assert!(characters::is_empty_or_whitespace("   "));
/// assert!(!characters::is_empty_or_whitespace("file.txt"));
/// ```
#[must_use]
pub fn is_empty_or_whitespace(path: &str) -> bool {
    path.trim().is_empty()
}

// ============================================================================
// Null Byte Detection
// ============================================================================

/// Check for null bytes in path
///
/// Null bytes can truncate strings in C APIs and bypass security checks.
/// This is a critical security check (CWE-158: Null Byte Injection).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::characters;
///
/// assert!(characters::is_null_bytes_present("file\0.txt"));
/// assert!(characters::is_null_bytes_present("\0"));
/// assert!(!characters::is_null_bytes_present("safe/path"));
/// ```
#[must_use]
pub fn is_null_bytes_present(path: &str) -> bool {
    path.contains('\0')
}

// ============================================================================
// Control Character Detection
// ============================================================================

/// Check if path contains a newline character
///
/// Newlines can break parsing and inject log entries.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::characters;
///
/// assert!(characters::is_newline_present("file\n.txt"));
/// assert!(characters::is_newline_present("path\ninjection"));
/// assert!(!characters::is_newline_present("safe/path"));
/// ```
#[must_use]
pub fn is_newline_present(path: &str) -> bool {
    path.contains('\n')
}

/// Check if path contains a carriage return
///
/// Carriage returns can break parsing, especially on Windows.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::characters;
///
/// assert!(characters::is_carriage_return_present("file\r.txt"));
/// assert!(characters::is_carriage_return_present("path\r\n")); // CRLF
/// assert!(!characters::is_carriage_return_present("safe/path"));
/// ```
#[must_use]
pub fn is_carriage_return_present(path: &str) -> bool {
    path.contains('\r')
}

/// Check if path contains a tab character
///
/// Tabs can break parsing in shell commands and configuration files.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::characters;
///
/// assert!(characters::is_tab_present("file\t.txt"));
/// assert!(!characters::is_tab_present("safe/path"));
/// ```
#[must_use]
pub fn is_tab_present(path: &str) -> bool {
    path.contains('\t')
}

/// Check if path contains any control characters
///
/// Detects ASCII control characters (0x00-0x1F, 0x7F) that can:
/// - Break parsing
/// - Inject log entries
/// - Bypass security filters
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::characters;
///
/// assert!(characters::is_control_characters_present("file\n.txt"));
/// assert!(characters::is_control_characters_present("path\r\n"));
/// assert!(characters::is_control_characters_present("file\t.txt"));
/// assert!(characters::is_control_characters_present("\x00")); // null
/// assert!(characters::is_control_characters_present("\x1F")); // ASCII control
/// assert!(characters::is_control_characters_present("\x7F")); // DEL
/// assert!(!characters::is_control_characters_present("safe/path"));
/// ```
#[must_use]
pub fn is_control_characters_present(path: &str) -> bool {
    path.chars().any(|c| c.is_control())
}

/// Check if path contains control characters excluding null
///
/// Sometimes null bytes are checked separately. This function
/// checks for other control characters.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::characters;
///
/// assert!(characters::is_control_characters_present_except_null("file\n.txt"));
/// assert!(!characters::is_control_characters_present_except_null("\x00")); // null excluded
/// assert!(!characters::is_control_characters_present_except_null("safe/path"));
/// ```
#[must_use]
pub fn is_control_characters_present_except_null(path: &str) -> bool {
    path.chars().any(|c| c.is_control() && c != '\0')
}

// ============================================================================
// Combined Detection
// ============================================================================

/// Check if path contains dangerous characters
///
/// Comprehensive check combining:
/// - Null bytes
/// - Control characters
///
/// This is the primary dangerous character detection function.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::characters;
///
/// assert!(characters::is_dangerous_characters_present("file\0.txt"));
/// assert!(characters::is_dangerous_characters_present("path\n.txt"));
/// assert!(characters::is_dangerous_characters_present("\t\r"));
/// assert!(!characters::is_dangerous_characters_present("safe/path"));
/// ```
#[must_use]
pub fn is_dangerous_characters_present(path: &str) -> bool {
    // Control characters include null, newline, carriage return, tab, etc.
    is_control_characters_present(path)
}

// ============================================================================
// Platform-Specific Character Detection
// ============================================================================

/// Characters that are invalid in Windows filenames
const WINDOWS_INVALID_CHARS: &[char] = &['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

/// Characters that are invalid in Windows filenames (excluding path separators)
const WINDOWS_INVALID_FILENAME_CHARS: &[char] = &['<', '>', ':', '"', '|', '?', '*'];

/// Check if path contains characters invalid on Windows
///
/// Windows has stricter filename character requirements than Unix.
/// This detects characters that cannot appear in Windows filenames.
///
/// **Note**: This includes `/` and `\` which are path separators.
/// For filename-only validation, use [`is_windows_invalid_filename_chars_present`].
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::characters;
///
/// assert!(characters::is_windows_invalid_chars_present("file<name>.txt"));
/// assert!(characters::is_windows_invalid_chars_present("file:stream"));
/// assert!(characters::is_windows_invalid_chars_present("file?name"));
/// assert!(!characters::is_windows_invalid_chars_present("safe_file.txt"));
/// ```
#[must_use]
pub fn is_windows_invalid_chars_present(path: &str) -> bool {
    path.chars().any(|c| WINDOWS_INVALID_CHARS.contains(&c))
}

/// Check if filename contains characters invalid on Windows
///
/// Like [`is_windows_invalid_chars_present`] but excludes path separators,
/// making it suitable for validating individual filename components.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::characters;
///
/// assert!(characters::is_windows_invalid_filename_chars_present("file<name>.txt"));
/// assert!(characters::is_windows_invalid_filename_chars_present("file:stream"));
/// assert!(!characters::is_windows_invalid_filename_chars_present("path/to/file")); // Separators OK
/// ```
#[must_use]
pub fn is_windows_invalid_filename_chars_present(path: &str) -> bool {
    path.chars()
        .any(|c| WINDOWS_INVALID_FILENAME_CHARS.contains(&c))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Empty/whitespace tests
    #[test]
    fn test_is_empty() {
        assert!(is_empty(""));
        assert!(!is_empty(" "));
        assert!(!is_empty("file.txt"));
    }

    #[test]
    fn test_is_whitespace_only() {
        assert!(is_whitespace_only("   "));
        assert!(is_whitespace_only("\t"));
        assert!(is_whitespace_only("\n"));
        assert!(is_whitespace_only(" \t \n "));
        assert!(!is_whitespace_only("")); // Empty is not whitespace-only
        assert!(!is_whitespace_only("file.txt"));
        assert!(!is_whitespace_only(" file ")); // Has non-whitespace
    }

    #[test]
    fn test_is_empty_or_whitespace() {
        assert!(is_empty_or_whitespace(""));
        assert!(is_empty_or_whitespace("   "));
        assert!(is_empty_or_whitespace("\t\n"));
        assert!(!is_empty_or_whitespace("file.txt"));
    }

    // Null byte tests
    #[test]
    fn test_is_null_bytes_present() {
        assert!(is_null_bytes_present("file\0.txt"));
        assert!(is_null_bytes_present("\0"));
        assert!(is_null_bytes_present("prefix\0suffix"));
        assert!(!is_null_bytes_present("safe/path"));
        assert!(!is_null_bytes_present(""));
    }

    // Control character tests
    #[test]
    fn test_is_newline_present() {
        assert!(is_newline_present("file\n.txt"));
        assert!(is_newline_present("\n"));
        assert!(is_newline_present("line1\nline2"));
        assert!(!is_newline_present("safe/path"));
    }

    #[test]
    fn test_is_carriage_return_present() {
        assert!(is_carriage_return_present("file\r.txt"));
        assert!(is_carriage_return_present("\r"));
        assert!(is_carriage_return_present("line\r\n")); // CRLF
        assert!(!is_carriage_return_present("safe/path"));
    }

    #[test]
    fn test_is_tab_present() {
        assert!(is_tab_present("file\t.txt"));
        assert!(is_tab_present("\t"));
        assert!(is_tab_present("col1\tcol2"));
        assert!(!is_tab_present("safe/path"));
    }

    #[test]
    fn test_is_control_characters_present() {
        assert!(is_control_characters_present("\x00")); // null
        assert!(is_control_characters_present("\x01")); // SOH
        assert!(is_control_characters_present("\x1F")); // US
        assert!(is_control_characters_present("\x7F")); // DEL
        assert!(is_control_characters_present("\n"));
        assert!(is_control_characters_present("\r"));
        assert!(is_control_characters_present("\t"));
        assert!(!is_control_characters_present("safe/path"));
        assert!(!is_control_characters_present("file.txt"));
    }

    #[test]
    fn test_is_control_characters_present_except_null() {
        assert!(is_control_characters_present_except_null("\n"));
        assert!(is_control_characters_present_except_null("\r"));
        assert!(is_control_characters_present_except_null("\t"));
        assert!(!is_control_characters_present_except_null("\x00")); // null excluded
        assert!(!is_control_characters_present_except_null("safe/path"));
    }

    // Combined detection tests
    #[test]
    fn test_is_dangerous_characters_present() {
        assert!(is_dangerous_characters_present("file\0.txt"));
        assert!(is_dangerous_characters_present("path\n.txt"));
        assert!(is_dangerous_characters_present("\t\r"));
        assert!(is_dangerous_characters_present("\x1F"));
        assert!(!is_dangerous_characters_present("safe/path"));
        assert!(!is_dangerous_characters_present("file.txt"));
    }

    // Windows-specific tests
    #[test]
    fn test_is_windows_invalid_chars_present() {
        assert!(is_windows_invalid_chars_present("file<name>.txt"));
        assert!(is_windows_invalid_chars_present("file>name.txt"));
        assert!(is_windows_invalid_chars_present("file:stream")); // ADS separator
        assert!(is_windows_invalid_chars_present("file\"name.txt"));
        assert!(is_windows_invalid_chars_present("file|name.txt"));
        assert!(is_windows_invalid_chars_present("file?name.txt"));
        assert!(is_windows_invalid_chars_present("file*name.txt"));
        assert!(is_windows_invalid_chars_present("path/to/file")); // Forward slash
        assert!(is_windows_invalid_chars_present("path\\to\\file")); // Backslash
        assert!(!is_windows_invalid_chars_present("safe_file.txt"));
        assert!(!is_windows_invalid_chars_present("file-name.txt"));
    }

    #[test]
    fn test_is_windows_invalid_filename_chars_present() {
        assert!(is_windows_invalid_filename_chars_present("file<name>.txt"));
        assert!(is_windows_invalid_filename_chars_present("file:stream"));
        // Separators are OK for filename validation (they split paths)
        assert!(!is_windows_invalid_filename_chars_present("path/to/file"));
        assert!(!is_windows_invalid_filename_chars_present("path\\to\\file"));
        assert!(!is_windows_invalid_filename_chars_present("safe_file.txt"));
    }

    // Edge cases
    #[test]
    fn test_empty_string() {
        assert!(is_empty(""));
        assert!(!is_null_bytes_present(""));
        assert!(!is_control_characters_present(""));
        assert!(!is_dangerous_characters_present(""));
        assert!(!is_windows_invalid_chars_present(""));
    }

    #[test]
    fn test_unicode() {
        // Unicode characters are generally fine
        assert!(!is_dangerous_characters_present("file_\u{00E9}.txt")); // e with accent
        assert!(!is_dangerous_characters_present("\u{1F600}")); // emoji
        assert!(!is_control_characters_present("\u{00E9}"));
    }

    #[test]
    fn test_multiple_issues() {
        // Path with multiple dangerous characters
        assert!(is_dangerous_characters_present("file\0\n\r\t.txt"));
        assert!(is_null_bytes_present("file\0\n\r\t.txt"));
        assert!(is_newline_present("file\0\n\r\t.txt"));
        assert!(is_carriage_return_present("file\0\n\r\t.txt"));
        assert!(is_tab_present("file\0\n\r\t.txt"));
    }
}
