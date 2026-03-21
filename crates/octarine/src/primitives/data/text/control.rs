//! Control Character Detection
//!
//! Pure detection functions for dangerous control characters in text.

// Allow dead_code: These are Layer 1 primitives that will be used by observe module
#![allow(dead_code)]
// Allow expect_used in lazy_static regex initialization (will only panic if regex is invalid)
#![allow(clippy::expect_used)]
//! These primitives are used by the log sanitization module and can be used
//! independently for detecting potentially dangerous content.
//!
//! ## Security Background
//!
//! Control characters (ASCII 0x00-0x1F and 0x7F) can be used for:
//! - **Log injection**: Creating fake log entries
//! - **Terminal manipulation**: ANSI escapes to hide content or execute commands
//! - **String truncation**: Null bytes can truncate in C APIs
//! - **Protocol injection**: CRLF injection in HTTP headers
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::primitives::data::text::{
//!     is_control_chars_present, is_ansi_escapes_present, is_crlf_present,
//! };
//!
//! // Check for any control characters
//! assert!(is_control_chars_present("hello\x00world"));
//!
//! // Check for ANSI escape sequences
//! assert!(is_ansi_escapes_present("\x1B[31mred text\x1B[0m"));
//!
//! // Check for CRLF injection
//! assert!(is_crlf_present("header\r\ninjected"));
//! ```

use once_cell::sync::Lazy;
use regex::Regex;

// ============================================================================
// ANSI Escape Pattern
// ============================================================================

/// Pattern for ANSI escape sequences
///
/// Matches:
/// - CSI sequences: ESC [ ... (parameters) ... letter (e.g., colors, cursor)
/// - OSC sequences: ESC ] ... BEL/ST (e.g., window titles)
/// - Simple sequences: ESC letter (e.g., ESC c for reset)
static ANSI_ESCAPE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    // This pattern matches:
    // 1. CSI sequences: \x1B\[[\x30-\x3F]*[\x20-\x2F]*[\x40-\x7E]
    // 2. OSC sequences: \x1B\][^\x07\x1B]*(?:\x07|\x1B\\)
    // 3. Simple escapes: \x1B[a-zA-Z@`] (letters, @ and backtick)
    Regex::new(r"(?:\x1B\[[\x30-\x3F]*[\x20-\x2F]*[\x40-\x7E]|\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)|\x1B[a-zA-Z@`])")
        .expect("Invalid ANSI escape regex pattern")
});

// ============================================================================
// Control Character Detection
// ============================================================================

/// Check if string contains any control characters
///
/// Control characters are ASCII 0x00-0x1F and 0x7F. This function considers
/// all control characters dangerous, including tab, newline, and carriage return.
///
/// For a more permissive check that allows common whitespace, use
/// [`is_dangerous_control_chars_present`].
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::is_control_chars_present;
///
/// assert!(is_control_chars_present("hello\x00world"));  // Null byte
/// assert!(is_control_chars_present("test\x1B[31m"));    // ANSI escape
/// assert!(is_control_chars_present("line1\nline2"));    // Newline
/// assert!(!is_control_chars_present("hello world"));    // Clean
/// ```
#[inline]
pub fn is_control_chars_present(s: &str) -> bool {
    s.bytes().any(is_control_byte)
}

/// Check if string contains dangerous control characters
///
/// This is more permissive than [`is_control_chars_present`], allowing:
/// - Tab (0x09)
/// - Newline (0x0A)
/// - Carriage return (0x0D)
///
/// These are often legitimate in text but may still need escaping in logs.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::is_dangerous_control_chars_present;
///
/// assert!(is_dangerous_control_chars_present("hello\x00world"));  // Null - dangerous
/// assert!(is_dangerous_control_chars_present("test\x1B[31m"));    // ESC - dangerous
/// assert!(!is_dangerous_control_chars_present("line1\nline2"));   // Newline - OK
/// assert!(!is_dangerous_control_chars_present("col1\tcol2"));     // Tab - OK
/// ```
#[inline]
pub fn is_dangerous_control_chars_present(s: &str) -> bool {
    s.bytes().any(is_dangerous_control_byte)
}

/// Check if string contains null bytes
///
/// Null bytes (0x00) can truncate strings in C APIs, potentially allowing
/// attackers to bypass validation or hide malicious content.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::is_null_bytes_present;
///
/// assert!(is_null_bytes_present("file.txt\x00.exe"));
/// assert!(!is_null_bytes_present("file.txt"));
/// ```
#[inline]
pub fn is_null_bytes_present(s: &str) -> bool {
    s.bytes().any(|b| b == 0)
}

/// Check if string contains ANSI escape sequences
///
/// ANSI escapes start with ESC (0x1B) and can:
/// - Change terminal colors (hiding content)
/// - Move the cursor (overwriting previous output)
/// - Execute terminal commands in some terminals
/// - Set window titles (phishing)
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::is_ansi_escapes_present;
///
/// assert!(is_ansi_escapes_present("\x1B[31mred\x1B[0m"));     // Color codes
/// assert!(is_ansi_escapes_present("\x1B]0;title\x07"));       // Window title
/// assert!(is_ansi_escapes_present("\x1Bc"));                   // Terminal reset
/// assert!(!is_ansi_escapes_present("plain text"));
/// ```
#[inline]
pub fn is_ansi_escapes_present(s: &str) -> bool {
    // Quick check: if no ESC character, no ANSI escapes possible
    if !s.contains('\x1B') {
        return false;
    }
    ANSI_ESCAPE_PATTERN.is_match(s)
}

/// Check if string contains CRLF sequences
///
/// CRLF (\r\n) sequences or standalone CR/LF can be used for:
/// - HTTP response splitting (header injection)
/// - Log injection (creating fake log entries)
/// - Protocol injection in text-based protocols
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::is_crlf_present;
///
/// assert!(is_crlf_present("header\r\nContent-Type: text/html"));
/// assert!(is_crlf_present("line1\nline2"));   // Standalone LF
/// assert!(is_crlf_present("text\rmore"));     // Standalone CR
/// assert!(!is_crlf_present("no line breaks"));
/// ```
#[inline]
pub fn is_crlf_present(s: &str) -> bool {
    s.bytes().any(|b| b == b'\r' || b == b'\n')
}

/// Check if string contains newlines only (not carriage returns)
///
/// Useful for detecting log injection without flagging CRLF in HTTP contexts.
#[inline]
pub fn is_newlines_present(s: &str) -> bool {
    s.bytes().any(|b| b == b'\n')
}

/// Check if string contains carriage returns only (not newlines)
#[inline]
pub fn is_carriage_returns_present(s: &str) -> bool {
    s.bytes().any(|b| b == b'\r')
}

/// Check if string contains terminal cursor control sequences
///
/// Cursor controls can hide malicious content by:
/// - Moving cursor to overwrite previous output
/// - Scrolling content off screen
/// - Clearing lines or screen regions
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::is_cursor_controls_present;
///
/// assert!(is_cursor_controls_present("\x1B[2J"));    // Clear screen
/// assert!(is_cursor_controls_present("\x1B[H"));     // Cursor home
/// assert!(is_cursor_controls_present("\x1B[5A"));    // Cursor up 5
/// ```
#[inline]
pub fn is_cursor_controls_present(s: &str) -> bool {
    // Quick check for ESC
    if !s.contains('\x1B') {
        return false;
    }

    // Quick check for CSI sequence marker
    if !s.contains("\x1B[") {
        return false;
    }

    // Check for cursor control patterns using iterator-based approach
    // CSI sequences: ESC [ params command
    let bytes = s.as_bytes();

    // Use windows to safely iterate over byte pairs/triples
    for window in bytes.windows(3) {
        // Look for CSI start: ESC [
        if let [0x1B, b'[', first_byte] = window {
            // Check if first_byte after CSI is a cursor control command
            // (may be the command itself if no parameters)
            if matches!(
                first_byte,
                b'A'..=b'D' | b'H' | b'f' | b'J' | b'K' | b's' | b'u' | b'G'
            ) {
                return true;
            }
        }
    }

    // Also check for commands after parameters (e.g., ESC[5A)
    // Using regex for more complex patterns would be cleaner, but
    // we use a simple scan for common cursor control suffixes
    for line in s.split('\x1B') {
        if let Some(rest) = line.strip_prefix('[') {
            // Skip parameters (digits and semicolons)
            let cmd_start = rest
                .bytes()
                .position(|b| !b.is_ascii_digit() && b != b';')
                .unwrap_or(rest.len());

            if let Some(&cmd) = rest.as_bytes().get(cmd_start)
                && matches!(
                    cmd,
                    b'A'..=b'D' | b'H' | b'f' | b'J' | b'K' | b's' | b'u' | b'G'
                )
            {
                return true;
            }
        }
    }

    false
}

/// Check if string contains any bell characters
///
/// Bell characters (0x07) can be annoying in logs and are sometimes used
/// in terminal escape sequence terminators.
#[inline]
pub fn is_bell_present(s: &str) -> bool {
    s.bytes().any(|b| b == 0x07)
}

/// Check if string contains backspace characters
///
/// Backspace (0x08) can be used to overwrite previous characters,
/// potentially hiding content in terminals.
#[inline]
pub fn is_backspace_present(s: &str) -> bool {
    s.bytes().any(|b| b == 0x08)
}

// ============================================================================
// Character Classification
// ============================================================================

/// Check if a byte is a control character (0x00-0x1F or 0x7F)
#[inline]
pub const fn is_control_byte(b: u8) -> bool {
    b < 0x20 || b == 0x7F
}

/// Check if a byte is a dangerous control character
///
/// Excludes commonly allowed whitespace: Tab (0x09), LF (0x0A), CR (0x0D)
#[inline]
pub const fn is_dangerous_control_byte(b: u8) -> bool {
    (b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D) || b == 0x7F
}

/// Check if character is a printable ASCII character (0x20-0x7E)
#[inline]
pub const fn is_printable_ascii(c: char) -> bool {
    matches!(c, ' '..='~')
}

/// Check if character is safe for log output
///
/// Safe characters are:
/// - Printable ASCII (0x20-0x7E)
/// - Tab (0x09) when allowed
/// - Unicode letters/numbers when unicode is allowed
///
/// # Arguments
///
/// * `c` - The character to check
/// * `allow_tab` - Whether to consider tab (0x09) as safe
/// * `allow_unicode` - Whether to allow non-ASCII unicode characters
#[inline]
pub fn is_log_safe_char(c: char, allow_tab: bool, allow_unicode: bool) -> bool {
    // Printable ASCII is always safe (0x20-0x7E, i.e., ' ' to '~')
    if matches!(c, ' '..='~') {
        return true;
    }

    // Tab is conditionally safe
    if c == '\t' && allow_tab {
        return true;
    }

    // Unicode letters/numbers are conditionally safe
    if allow_unicode && !c.is_ascii() {
        // Allow unicode letters, numbers, and common punctuation
        // Exclude control characters and special formatting characters
        return c.is_alphanumeric()
            || c.is_whitespace()  // Unicode whitespace (not ASCII control)
            || matches!(c, '·' | '•' | '–' | '—' | '\'' | '"' | '…');
    }

    false
}

/// Count the number of control characters in a string
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::count_control_chars;
///
/// assert_eq!(count_control_chars("hello"), 0);
/// assert_eq!(count_control_chars("hello\x00\x01world"), 2);
/// ```
#[inline]
pub fn count_control_chars(s: &str) -> usize {
    s.bytes().filter(|&b| is_control_byte(b)).count()
}

/// Detect positions of control characters in a string
///
/// Returns byte positions of all control characters.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::detect_control_char_positions;
///
/// let positions = detect_control_char_positions("a\x00b\x01c");
/// assert_eq!(positions, vec![1, 3]);
/// ```
pub fn detect_control_char_positions(s: &str) -> Vec<usize> {
    s.bytes()
        .enumerate()
        .filter(|(_, b)| is_control_byte(*b))
        .map(|(i, _)| i)
        .collect()
}

// ============================================================================
// Unicode Safety Detection
// ============================================================================

/// Check if string contains zero-width characters
///
/// Zero-width characters can be used to hide content:
/// - U+200B Zero Width Space
/// - U+200C Zero Width Non-Joiner
/// - U+200D Zero Width Joiner
/// - U+FEFF Byte Order Mark (when not at start)
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::is_zero_width_chars_present;
///
/// assert!(is_zero_width_chars_present("hidden\u{200B}text"));
/// assert!(!is_zero_width_chars_present("normal text"));
/// ```
pub fn is_zero_width_chars_present(s: &str) -> bool {
    s.chars()
        .any(|c| matches!(c, '\u{200B}'..='\u{200D}' | '\u{FEFF}' | '\u{2060}'))
}

/// Check if string contains bidirectional override characters
///
/// Bidi overrides can reorder text display to hide malicious content:
/// - U+202A Left-to-Right Embedding
/// - U+202B Right-to-Left Embedding
/// - U+202C Pop Directional Formatting
/// - U+202D Left-to-Right Override
/// - U+202E Right-to-Left Override
/// - U+2066-U+2069 Isolates
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::is_bidi_overrides_present;
///
/// // This can make "evil.exe" appear as "exe.live"
/// assert!(is_bidi_overrides_present("see\u{202E}exe.live"));
/// ```
pub fn is_bidi_overrides_present(s: &str) -> bool {
    s.chars()
        .any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    // --- Control Character Detection Tests ---

    #[test]
    fn test_is_control_chars_present() {
        assert!(is_control_chars_present("hello\x00world"));
        assert!(is_control_chars_present("test\x1Besc"));
        assert!(is_control_chars_present("line\nbreak"));
        assert!(is_control_chars_present("tab\there"));
        assert!(is_control_chars_present("cr\rhere"));
        assert!(!is_control_chars_present("clean text"));
        assert!(!is_control_chars_present("numbers 123"));
        assert!(!is_control_chars_present("symbols !@#$%"));
    }

    #[test]
    fn test_is_dangerous_control_chars_present() {
        // Dangerous
        assert!(is_dangerous_control_chars_present("hello\x00world"));
        assert!(is_dangerous_control_chars_present("test\x1Besc"));
        assert!(is_dangerous_control_chars_present("bell\x07ring"));

        // Not dangerous (common whitespace)
        assert!(!is_dangerous_control_chars_present("line\nbreak"));
        assert!(!is_dangerous_control_chars_present("tab\there"));
        assert!(!is_dangerous_control_chars_present("cr\rhere"));
        assert!(!is_dangerous_control_chars_present("clean text"));
    }

    #[test]
    fn test_is_null_bytes_present() {
        assert!(is_null_bytes_present("file.txt\x00.exe"));
        assert!(is_null_bytes_present("\x00start"));
        assert!(is_null_bytes_present("end\x00"));
        assert!(!is_null_bytes_present("normal.txt"));
    }

    #[test]
    fn test_is_ansi_escapes_present() {
        // CSI sequences
        assert!(is_ansi_escapes_present("\x1B[31mred\x1B[0m"));
        assert!(is_ansi_escapes_present("\x1B[1;2;3mtest"));
        assert!(is_ansi_escapes_present("\x1B[2J")); // Clear screen

        // OSC sequences
        assert!(is_ansi_escapes_present("\x1B]0;window title\x07"));

        // Simple escapes
        assert!(is_ansi_escapes_present("\x1Bc")); // Reset

        // Not ANSI escapes
        assert!(!is_ansi_escapes_present("plain text"));
        assert!(!is_ansi_escapes_present("ESC key"));
    }

    #[test]
    fn test_is_crlf_present() {
        assert!(is_crlf_present("header\r\nvalue"));
        assert!(is_crlf_present("line1\nline2"));
        assert!(is_crlf_present("text\rmore"));
        assert!(!is_crlf_present("single line"));
    }

    #[test]
    fn test_is_cursor_controls_present() {
        assert!(is_cursor_controls_present("\x1B[2J")); // Clear screen
        assert!(is_cursor_controls_present("\x1B[H")); // Cursor home
        assert!(is_cursor_controls_present("\x1B[5A")); // Cursor up 5
        assert!(is_cursor_controls_present("\x1B[10B")); // Cursor down 10
        assert!(is_cursor_controls_present("\x1B[K")); // Erase to end of line

        // Color codes are not cursor controls
        assert!(!is_cursor_controls_present("\x1B[31m")); // Just color
        assert!(!is_cursor_controls_present("plain text"));
    }

    #[test]
    fn test_is_bell_present() {
        assert!(is_bell_present("alert\x07!"));
        assert!(!is_bell_present("normal"));
    }

    #[test]
    fn test_is_backspace_present() {
        assert!(is_backspace_present("type\x08delete"));
        assert!(!is_backspace_present("normal"));
    }

    // --- Character Classification Tests ---

    #[test]
    fn test_is_control_byte() {
        assert!(is_control_byte(0x00));
        assert!(is_control_byte(0x09)); // Tab
        assert!(is_control_byte(0x0A)); // LF
        assert!(is_control_byte(0x0D)); // CR
        assert!(is_control_byte(0x1B)); // ESC
        assert!(is_control_byte(0x7F)); // DEL

        assert!(!is_control_byte(0x20)); // Space
        assert!(!is_control_byte(b'A'));
        assert!(!is_control_byte(0x7E)); // Tilde
    }

    #[test]
    fn test_is_dangerous_control_byte() {
        assert!(is_dangerous_control_byte(0x00)); // Null
        assert!(is_dangerous_control_byte(0x07)); // Bell
        assert!(is_dangerous_control_byte(0x1B)); // ESC
        assert!(is_dangerous_control_byte(0x7F)); // DEL

        // Not dangerous (common whitespace)
        assert!(!is_dangerous_control_byte(0x09)); // Tab
        assert!(!is_dangerous_control_byte(0x0A)); // LF
        assert!(!is_dangerous_control_byte(0x0D)); // CR
    }

    #[test]
    fn test_is_printable_ascii() {
        assert!(is_printable_ascii(' '));
        assert!(is_printable_ascii('A'));
        assert!(is_printable_ascii('z'));
        assert!(is_printable_ascii('~'));

        assert!(!is_printable_ascii('\t'));
        assert!(!is_printable_ascii('\n'));
        assert!(!is_printable_ascii('\x7F'));
    }

    #[test]
    fn test_is_log_safe_char() {
        // Printable ASCII always safe
        assert!(is_log_safe_char('A', false, false));
        assert!(is_log_safe_char(' ', false, false));

        // Tab depends on allow_tab
        assert!(!is_log_safe_char('\t', false, false));
        assert!(is_log_safe_char('\t', true, false));

        // Unicode depends on allow_unicode
        assert!(!is_log_safe_char('日', false, false));
        assert!(is_log_safe_char('日', false, true));

        // Control chars never safe
        assert!(!is_log_safe_char('\x00', true, true));
        assert!(!is_log_safe_char('\x1B', true, true));
    }

    #[test]
    fn test_count_control_chars() {
        assert_eq!(count_control_chars("hello"), 0);
        assert_eq!(count_control_chars("hello\x00\x01world"), 2);
        assert_eq!(count_control_chars("\x00\x01\x02"), 3);
    }

    #[test]
    fn test_detect_control_char_positions() {
        let positions = detect_control_char_positions("a\x00b\x01c");
        assert_eq!(positions, vec![1, 3]);

        let empty = detect_control_char_positions("clean");
        assert!(empty.is_empty());
    }

    // --- Unicode Safety Tests ---

    #[test]
    fn test_is_zero_width_chars_present() {
        assert!(is_zero_width_chars_present("hidden\u{200B}text"));
        assert!(is_zero_width_chars_present("\u{FEFF}bom"));
        assert!(is_zero_width_chars_present("join\u{200D}er"));
        assert!(!is_zero_width_chars_present("normal text"));
    }

    #[test]
    fn test_is_bidi_overrides_present() {
        assert!(is_bidi_overrides_present("see\u{202E}exe.live"));
        assert!(is_bidi_overrides_present("\u{202A}LRE"));
        assert!(is_bidi_overrides_present("\u{2066}isolate"));
        assert!(!is_bidi_overrides_present("normal text"));
    }

    // --- Edge Cases ---

    #[test]
    fn test_empty_string() {
        assert!(!is_control_chars_present(""));
        assert!(!is_dangerous_control_chars_present(""));
        assert!(!is_null_bytes_present(""));
        assert!(!is_ansi_escapes_present(""));
        assert!(!is_crlf_present(""));
        assert!(!is_cursor_controls_present(""));
        assert_eq!(count_control_chars(""), 0);
    }

    #[test]
    fn test_only_control_chars() {
        assert!(is_control_chars_present("\x00\x01\x02\x03"));
        assert_eq!(count_control_chars("\x00\x01\x02\x03"), 4);
    }

    #[test]
    fn test_mixed_ansi_and_text() {
        let s = "Normal \x1B[31mRED\x1B[0m Normal";
        assert!(is_ansi_escapes_present(s));
        assert!(!is_cursor_controls_present(s)); // Colors aren't cursor controls
    }
}
