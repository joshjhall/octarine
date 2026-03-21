//! Shortcut functions for common text sanitization operations
//!
//! These functions provide a simplified API for the most common text
//! operations. For more control, use [`TextBuilder`].
//!
//! All shortcuts include observe instrumentation for compliance-grade audit trails.
//!
//! # Usage
//!
//! Shortcuts are namespaced under `octarine::data::text`:
//!
//! ```ignore
//! use octarine::data::text::{sanitize_for_log, is_log_safe};
//!
//! if !is_log_safe(user_input) {
//!     let safe = sanitize_for_log(user_input);
//! }
//! ```

// Allow dead_code: These are public API shortcuts that will be used by consumers
#![allow(dead_code)]

use std::borrow::Cow;

use super::TextBuilder;

// ============================================================================
// Detection Shortcuts
// ============================================================================

/// Check if text is safe for log output without modification
///
/// Returns `true` if the text contains no characters that would need
/// sanitization with default options.
///
/// # Example
///
/// ```ignore
/// use octarine::data::text::is_log_safe;
///
/// if is_log_safe(user_input) {
///     println!("Safe: {}", user_input);
/// } else {
///     println!("Needs sanitization");
/// }
/// ```
pub fn is_log_safe(input: &str) -> bool {
    TextBuilder::new(input).is_log_safe()
}

/// Check if text contains dangerous control characters
///
/// Returns `true` if text contains null bytes, ANSI escapes, or other
/// dangerous control characters (excludes safe whitespace like tab, newline).
///
/// # Example
///
/// ```ignore
/// use octarine::data::text::is_dangerous;
///
/// if is_dangerous(user_input) {
///     // Log a warning and sanitize
/// }
/// ```
pub fn is_dangerous(input: &str) -> bool {
    TextBuilder::new(input).is_dangerous_control_chars_present()
}

/// Check if text contains any control characters
///
/// Returns `true` if text contains any ASCII control characters (0x00-0x1F, 0x7F).
pub fn is_control_chars_present(input: &str) -> bool {
    TextBuilder::new(input).is_control_chars_present()
}

/// Check if text contains ANSI escape sequences
pub fn is_ansi_present(input: &str) -> bool {
    TextBuilder::new(input).is_ansi_escapes_present()
}

// ============================================================================
// Sanitization Shortcuts
// ============================================================================

/// Sanitize text for safe log output using default options
///
/// Default behavior:
/// - Escapes newlines as `\n`
/// - Escapes carriage returns as `\r`
/// - Strips ANSI escape sequences
/// - Removes dangerous control characters
///
/// # Example
///
/// ```ignore
/// use octarine::data::text::sanitize_for_log;
///
/// let safe = sanitize_for_log("User\ninput");
/// assert_eq!(safe, "User\\ninput");
/// ```
pub fn sanitize_for_log(input: &str) -> Cow<'_, str> {
    TextBuilder::new(input).sanitize_for_log().finish()
}

/// Sanitize text with strict options (escapes everything including tabs)
///
/// Strict behavior:
/// - Escapes newlines, carriage returns, AND tabs
/// - Strips ANSI escape sequences
/// - Removes all control characters
/// - ASCII-only output (escapes unicode)
/// - Length limited to 10000 chars
///
/// # Example
///
/// ```ignore
/// use octarine::data::text::sanitize_strict;
///
/// let safe = sanitize_strict("Col1\tCol2\nRow2");
/// assert_eq!(safe, "Col1\\tCol2\\nRow2");
/// ```
pub fn sanitize_strict(input: &str) -> Cow<'_, str> {
    TextBuilder::new(input)
        .with_strict_config()
        .sanitize_for_log()
        .finish()
}

/// Sanitize text with relaxed options (preserves newlines)
///
/// Relaxed behavior:
/// - Preserves newlines
/// - Escapes carriage returns
/// - Strips ANSI escape sequences
/// - Removes dangerous control characters (uses replacement char)
/// - Allows unicode
///
/// # Example
///
/// ```ignore
/// use octarine::data::text::sanitize_relaxed;
///
/// let safe = sanitize_relaxed("Line1\nLine2");
/// assert_eq!(safe, "Line1\nLine2");
/// ```
pub fn sanitize_relaxed(input: &str) -> Cow<'_, str> {
    TextBuilder::new(input)
        .with_relaxed_config()
        .sanitize_for_log()
        .finish()
}

/// Sanitize text for JSON string embedding
///
/// JSON-safe behavior:
/// - Escapes newlines, carriage returns, and tabs
/// - Strips ANSI escape sequences
/// - Removes control characters
/// - Allows unicode
///
/// # Example
///
/// ```ignore
/// use octarine::data::text::sanitize_for_json;
///
/// let safe = sanitize_for_json("value\twith\ttabs");
/// assert_eq!(safe, "value\\twith\\ttabs");
/// ```
pub fn sanitize_for_json(input: &str) -> Cow<'_, str> {
    TextBuilder::new(input)
        .with_json_config()
        .sanitize_for_log()
        .finish()
}

// ============================================================================
// Stripping Shortcuts
// ============================================================================

/// Strip ANSI escape sequences from text
///
/// Only removes ANSI escapes, preserves other characters including newlines.
///
/// # Example
///
/// ```ignore
/// use octarine::data::text::strip_ansi;
///
/// let plain = strip_ansi("\x1B[31mred\x1B[0m text");
/// assert_eq!(plain, "red text");
/// ```
pub fn strip_ansi(input: &str) -> Cow<'_, str> {
    TextBuilder::new(input).strip_ansi().finish()
}

/// Strip dangerous control characters (keeps tab, newline, CR)
///
/// # Example
///
/// ```ignore
/// use octarine::data::text::strip_control_chars;
///
/// let clean = strip_control_chars("hello\x00\x07world");
/// assert_eq!(clean, "helloworld");
/// ```
pub fn strip_control_chars(input: &str) -> Cow<'_, str> {
    TextBuilder::new(input).strip_control_chars().finish()
}

// ============================================================================
// Escaping Shortcuts
// ============================================================================

/// Escape line breaks as literal `\n` and `\r`
///
/// # Example
///
/// ```ignore
/// use octarine::data::text::escape_line_breaks;
///
/// let escaped = escape_line_breaks("line1\nline2\r\nline3");
/// assert_eq!(escaped, "line1\\nline2\\r\\nline3");
/// ```
pub fn escape_line_breaks(input: &str) -> Cow<'_, str> {
    TextBuilder::new(input).escape_line_breaks().finish()
}

// ============================================================================
// Truncation Shortcuts
// ============================================================================

/// Truncate text to maximum length with default suffix "..."
///
/// # Example
///
/// ```ignore
/// use octarine::data::text::truncate;
///
/// let short = truncate("Hello, World!", 10);
/// assert_eq!(short, "Hello, ...");
/// ```
pub fn truncate(input: &str, max_length: usize) -> Cow<'_, str> {
    TextBuilder::new(input).truncate(max_length).finish()
}

/// Truncate text with custom suffix
///
/// # Example
///
/// ```ignore
/// use octarine::data::text::truncate_with_suffix;
///
/// let short = truncate_with_suffix("Hello, World!", 12, "[...]");
/// assert_eq!(short, "Hello, [...]");
/// ```
pub fn truncate_with_suffix<'a>(input: &'a str, max_length: usize, suffix: &str) -> Cow<'a, str> {
    TextBuilder::new(input)
        .truncate_with_suffix(max_length, suffix)
        .finish()
}

// ============================================================================
// Combined Shortcuts
// ============================================================================

/// Sanitize and truncate text for log output
///
/// Combines default sanitization with truncation - common for log field processing.
///
/// # Example
///
/// ```ignore
/// use octarine::data::text::sanitize_and_truncate;
///
/// let safe = sanitize_and_truncate("Long\ninput\nwith\nmany\nlines", 20);
/// ```
pub fn sanitize_and_truncate(input: &str, max_length: usize) -> Cow<'_, str> {
    TextBuilder::new(input)
        .sanitize_for_log()
        .truncate(max_length)
        .finish()
}

/// Strip ANSI and sanitize for log output
///
/// Common pattern for processing terminal output before logging.
///
/// # Example
///
/// ```ignore
/// use octarine::data::text::clean_terminal_output;
///
/// let clean = clean_terminal_output("\x1B[31mError:\x1B[0m failed\n");
/// assert_eq!(clean, "Error: failed\\n");
/// ```
pub fn clean_terminal_output(input: &str) -> Cow<'_, str> {
    TextBuilder::new(input)
        .strip_ansi()
        .sanitize_for_log()
        .finish()
}

/// Prepare text for single-line log entry
///
/// Strips ANSI, removes dangerous chars, escapes line breaks, and truncates.
/// Use for user-provided text that must fit in a single log line.
///
/// # Example
///
/// ```ignore
/// use octarine::data::text::prepare_log_field;
///
/// let field = prepare_log_field(user_input, 100);
/// log::info!("User input: {}", field);
/// ```
pub fn prepare_log_field(input: &str, max_length: usize) -> Cow<'_, str> {
    TextBuilder::new(input)
        .strip_ansi()
        .strip_control_chars()
        .escape_line_breaks()
        .truncate(max_length)
        .finish()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_log_safe() {
        assert!(is_log_safe("Hello, World!"));
        assert!(!is_log_safe("has\nnewline"));
    }

    #[test]
    fn test_is_dangerous() {
        assert!(is_dangerous("has\x00null"));
        assert!(!is_dangerous("has\nnewline")); // newline is not "dangerous"
        assert!(!is_dangerous("clean text"));
    }

    #[test]
    fn test_sanitize_for_log() {
        assert_eq!(sanitize_for_log("User\ninput"), "User\\ninput");
        assert_eq!(sanitize_for_log("clean"), "clean");
    }

    #[test]
    fn test_sanitize_strict() {
        assert_eq!(sanitize_strict("Tab\there"), "Tab\\there");
        assert_eq!(sanitize_strict("line\nbreak"), "line\\nbreak");
    }

    #[test]
    fn test_sanitize_relaxed() {
        assert_eq!(sanitize_relaxed("line1\nline2"), "line1\nline2");
    }

    #[test]
    fn test_sanitize_for_json() {
        assert_eq!(sanitize_for_json("tab\there"), "tab\\there");
    }

    #[test]
    fn test_strip_ansi() {
        assert_eq!(strip_ansi("\x1B[31mred\x1B[0m"), "red");
    }

    #[test]
    fn test_strip_control_chars() {
        assert_eq!(strip_control_chars("hello\x00world"), "helloworld");
    }

    #[test]
    fn test_escape_line_breaks() {
        assert_eq!(escape_line_breaks("a\nb\rc"), "a\\nb\\rc");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("Hello, World!", 10), "Hello, ...");
        assert_eq!(truncate("Short", 10), "Short");
    }

    #[test]
    fn test_truncate_with_suffix() {
        assert_eq!(
            truncate_with_suffix("Hello, World!", 12, "[...]"),
            "Hello, [...]"
        );
    }

    #[test]
    fn test_sanitize_and_truncate() {
        let result = sanitize_and_truncate("Long\ninput", 15);
        assert!(result.len() <= 15);
        assert!(!result.contains('\n'));
    }

    #[test]
    fn test_clean_terminal_output() {
        assert_eq!(clean_terminal_output("\x1B[31mError\x1B[0m\n"), "Error\\n");
    }

    #[test]
    fn test_prepare_log_field() {
        let result = prepare_log_field("\x1B[31mLong error\nmessage\x00here", 20);
        assert!(result.len() <= 20);
        assert!(!result.contains('\x1B'));
        assert!(!result.contains('\x00'));
        assert!(!result.contains('\n'));
    }
}
