//! Log Injection Prevention
//!
//! Pure sanitization functions for safe log output. This module prevents:

// Allow dead_code: These are Layer 1 primitives that will be used by observe module
#![allow(dead_code)]
//! - **Log forging**: Injecting fake log entries via newlines
//! - **CRLF injection**: Creating new log lines to hide attacks
//! - **Control character injection**: Terminal escapes, cursor manipulation
//! - **ANSI escape injection**: Color codes that could hide content
//!
//! ## Architecture
//!
//! This is a Layer 1 primitive with no rust-core dependencies.
//! It's used by the observe module (Layer 2) for log output sanitization.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::primitives::data::text::*;
//!
//! // Basic sanitization with default options
//! let safe = sanitize_for_log("User input\nFake log entry");
//! assert_eq!(safe, "User input\\nFake log entry");
//!
//! // Strip ANSI escapes
//! let safe = sanitize_for_log("\x1B[31mRed text\x1B[0m");
//! assert_eq!(safe, "Red text");
//!
//! // Custom options
//! let options = TextConfig::strict();
//! let safe = sanitize_for_log_with_config(input, &options);
//! ```

use std::borrow::Cow;

use super::control::{
    is_ansi_escapes_present, is_control_chars_present, is_dangerous_control_byte, is_log_safe_char,
};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for TextBuilder operations
///
/// Controls how text is sanitized for safe output.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::TextConfig;
///
/// // Default - escape newlines, remove ANSI, remove control chars
/// let config = TextConfig::default();
///
/// // Strict - escape everything, ASCII only, length limited
/// let config = TextConfig::strict();
///
/// // Relaxed - allow newlines, keep unicode
/// let config = TextConfig::relaxed();
///
/// // JSON-safe - escape for JSON string embedding
/// let config = TextConfig::json_safe();
/// ```
#[derive(Debug, Clone)]
pub struct TextConfig {
    /// Escape newlines as literal `\n` (default: true)
    pub escape_newlines: bool,

    /// Escape carriage returns as literal `\r` (default: true)
    pub escape_carriage_returns: bool,

    /// Escape tabs as literal `\t` (default: false)
    pub escape_tabs: bool,

    /// Remove ANSI escape sequences (default: true)
    pub remove_ansi_escapes: bool,

    /// Remove other control characters (default: true)
    pub remove_control_chars: bool,

    /// Replace control chars with unicode replacement char instead of removing
    pub use_replacement_char: bool,

    /// Maximum output length, 0 = no limit (default: 0)
    pub max_length: usize,

    /// Truncation suffix when max_length exceeded (default: "...")
    pub truncation_suffix: &'static str,

    /// Allow unicode characters (default: true)
    pub allow_unicode: bool,

    /// Escape unicode for ASCII-only output (default: false)
    pub escape_unicode: bool,
}

impl Default for TextConfig {
    fn default() -> Self {
        Self {
            escape_newlines: true,
            escape_carriage_returns: true,
            escape_tabs: false,
            remove_ansi_escapes: true,
            remove_control_chars: true,
            use_replacement_char: false,
            max_length: 0,
            truncation_suffix: "...",
            allow_unicode: true,
            escape_unicode: false,
        }
    }
}

impl TextConfig {
    /// Strict options - escape everything, ASCII only, length limited
    ///
    /// Use for high-security environments where all output must be
    /// predictable and safe for any downstream consumer.
    pub fn strict() -> Self {
        Self {
            escape_newlines: true,
            escape_carriage_returns: true,
            escape_tabs: true,
            remove_ansi_escapes: true,
            remove_control_chars: true,
            use_replacement_char: false,
            max_length: 10000,
            truncation_suffix: "...[truncated]",
            allow_unicode: false,
            escape_unicode: true,
        }
    }

    /// Relaxed options - allow newlines, keep unicode
    ///
    /// Use for development/debugging where readability is more important
    /// than strict safety. Still removes dangerous control characters.
    pub fn relaxed() -> Self {
        Self {
            escape_newlines: false,
            escape_carriage_returns: true,
            escape_tabs: false,
            remove_ansi_escapes: true,
            remove_control_chars: true,
            use_replacement_char: true,
            max_length: 0,
            truncation_suffix: "...",
            allow_unicode: true,
            escape_unicode: false,
        }
    }

    /// JSON-safe options - escape for JSON string embedding
    ///
    /// Use when log output will be embedded in JSON. Escapes all
    /// characters that would break JSON string syntax.
    pub fn json_safe() -> Self {
        Self {
            escape_newlines: true,
            escape_carriage_returns: true,
            escape_tabs: true,
            remove_ansi_escapes: true,
            remove_control_chars: true,
            use_replacement_char: false,
            max_length: 0,
            truncation_suffix: "...",
            allow_unicode: true,
            escape_unicode: false,
        }
    }

    /// Builder method to set max length
    #[must_use]
    pub fn with_max_length(mut self, max_length: usize) -> Self {
        self.max_length = max_length;
        self
    }

    /// Builder method to set truncation suffix
    #[must_use]
    pub fn with_truncation_suffix(mut self, suffix: &'static str) -> Self {
        self.truncation_suffix = suffix;
        self
    }

    /// Builder method to enable replacement char mode
    ///
    /// When enabled, control characters are replaced with the Unicode
    /// replacement character (U+FFFD) instead of being removed.
    #[must_use]
    pub fn with_replacement_char(mut self, enabled: bool) -> Self {
        self.use_replacement_char = enabled;
        self
    }
}

// ============================================================================
// Main Sanitization Functions
// ============================================================================

/// Sanitize string for safe log output with default options
///
/// Default behavior:
/// - Escapes newlines as `\n`
/// - Escapes carriage returns as `\r`
/// - Removes ANSI escape sequences
/// - Removes other control characters
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::sanitize_for_log;
///
/// let safe = sanitize_for_log("User login\nUser: admin");
/// assert_eq!(safe, "User login\\nUser: admin");
///
/// let safe = sanitize_for_log("test\x1B[31mred\x1B[0m");
/// assert_eq!(safe, "testred");
/// ```
#[inline]
pub fn sanitize_for_log(input: &str) -> Cow<'_, str> {
    sanitize_for_log_with_config(input, &TextConfig::default())
}

/// Sanitize string for log output with custom options
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::{sanitize_for_log_with_config, TextConfig};
///
/// let options = TextConfig::strict();
/// let safe = sanitize_for_log_with_config("User\tinput", &options);
/// assert_eq!(safe, "User\\tinput");
/// ```
pub fn sanitize_for_log_with_config<'a>(input: &'a str, options: &TextConfig) -> Cow<'a, str> {
    // Early return if input is empty
    if input.is_empty() {
        return Cow::Borrowed(input);
    }

    // Quick check: if no modifications needed, return borrowed
    if !needs_sanitization(input, options) {
        // Handle max_length even if no other modifications needed
        if options.max_length > 0 && input.len() > options.max_length {
            return truncate_for_log(input, options.max_length, options.truncation_suffix);
        }
        return Cow::Borrowed(input);
    }

    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        // Check for ANSI escape sequences
        if c == '\x1B' && options.remove_ansi_escapes {
            // Skip the escape sequence
            skip_ansi_sequence(&mut chars);
            continue;
        }

        // Handle specific characters
        match c {
            '\n' if options.escape_newlines => {
                result.push_str("\\n");
            }
            '\r' if options.escape_carriage_returns => {
                result.push_str("\\r");
            }
            '\t' if options.escape_tabs => {
                result.push_str("\\t");
            }
            _ if c.is_ascii() && is_dangerous_control_byte(c as u8) => {
                if options.remove_control_chars {
                    if options.use_replacement_char {
                        result.push('\u{FFFD}');
                    }
                    // else: skip (remove)
                } else {
                    result.push(c);
                }
            }
            _ if !c.is_ascii() && !options.allow_unicode => {
                if options.escape_unicode {
                    // Escape as \uXXXX
                    for unit in c.encode_utf16(&mut [0; 2]) {
                        result.push_str(&format!("\\u{:04X}", unit));
                    }
                } else if options.use_replacement_char {
                    result.push('\u{FFFD}');
                }
                // else: skip (remove)
            }
            _ => {
                result.push(c);
            }
        }

        // Check length limit
        if options.max_length > 0 && result.len() >= options.max_length {
            // Truncate and add suffix
            result.truncate(
                options
                    .max_length
                    .saturating_sub(options.truncation_suffix.len()),
            );
            result.push_str(options.truncation_suffix);
            break;
        }
    }

    Cow::Owned(result)
}

/// Check if input needs sanitization
fn needs_sanitization(input: &str, options: &TextConfig) -> bool {
    // Check for ANSI escapes
    if options.remove_ansi_escapes && is_ansi_escapes_present(input) {
        return true;
    }

    // Check for control characters that need handling
    if options.escape_newlines && input.contains('\n') {
        return true;
    }
    if options.escape_carriage_returns && input.contains('\r') {
        return true;
    }
    if options.escape_tabs && input.contains('\t') {
        return true;
    }
    if options.remove_control_chars && is_control_chars_present(input) {
        return true;
    }

    // Check for unicode if not allowed
    if !options.allow_unicode && !input.is_ascii() {
        return true;
    }

    false
}

/// Skip an ANSI escape sequence in the character stream
fn skip_ansi_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    match chars.peek() {
        Some('[') => {
            // CSI sequence: ESC [ params command
            chars.next(); // consume '['
            while let Some(&c) = chars.peek() {
                chars.next();
                // CSI ends with a letter (0x40-0x7E)
                if c.is_ascii_alphabetic() || c == '@' || c == '`' {
                    break;
                }
            }
        }
        Some(']') => {
            // OSC sequence: ESC ] ... (BEL or ST)
            chars.next(); // consume ']'
            while let Some(&c) = chars.peek() {
                chars.next();
                if c == '\x07' {
                    // BEL terminates
                    break;
                }
                if c == '\x1B' {
                    // ST (ESC \) might terminate
                    if chars.peek() == Some(&'\\') {
                        chars.next();
                        break;
                    }
                }
            }
        }
        Some(c) if c.is_ascii_alphabetic() || *c == '@' || *c == '`' => {
            // Simple escape: ESC <letter>
            chars.next();
        }
        _ => {
            // Unknown escape, just consume ESC
        }
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Escape newlines and carriage returns only
///
/// Lighter-weight function when full sanitization isn't needed.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::escape_line_breaks;
///
/// let safe = escape_line_breaks("line1\nline2\r\nline3");
/// assert_eq!(safe, "line1\\nline2\\r\\nline3");
/// ```
pub fn escape_line_breaks(input: &str) -> Cow<'_, str> {
    if !input.contains('\n') && !input.contains('\r') {
        return Cow::Borrowed(input);
    }

    let mut result = String::with_capacity(input.len().saturating_add(10));
    for c in input.chars() {
        match c {
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            _ => result.push(c),
        }
    }
    Cow::Owned(result)
}

/// Remove ANSI escape sequences only
///
/// Preserves other content including newlines.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::strip_ansi_escapes;
///
/// let clean = strip_ansi_escapes("\x1B[31mRed\x1B[0m text");
/// assert_eq!(clean, "Red text");
/// ```
pub fn strip_ansi_escapes(input: &str) -> Cow<'_, str> {
    if !is_ansi_escapes_present(input) {
        return Cow::Borrowed(input);
    }

    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1B' {
            skip_ansi_sequence(&mut chars);
        } else {
            result.push(c);
        }
    }

    Cow::Owned(result)
}

/// Remove all control characters
///
/// Removes ASCII 0x00-0x1F and 0x7F except tab, newline, CR.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::strip_control_chars;
///
/// let clean = strip_control_chars("hello\x00\x07world");
/// assert_eq!(clean, "helloworld");
/// ```
pub fn strip_control_chars(input: &str) -> Cow<'_, str> {
    if !input.bytes().any(is_dangerous_control_byte) {
        return Cow::Borrowed(input);
    }

    let result: String = input
        .chars()
        .filter(|&c| !c.is_ascii() || !is_dangerous_control_byte(c as u8))
        .collect();

    Cow::Owned(result)
}

/// Truncate string to maximum length with suffix
///
/// Handles unicode grapheme clusters correctly (doesn't cut in the middle).
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::truncate_for_log;
///
/// let short = truncate_for_log("Hello, World!", 10, "...");
/// assert_eq!(short, "Hello, ...");
/// ```
pub fn truncate_for_log<'a>(input: &'a str, max_length: usize, suffix: &str) -> Cow<'a, str> {
    if input.len() <= max_length {
        return Cow::Borrowed(input);
    }

    if max_length <= suffix.len() {
        return Cow::Owned(suffix.chars().take(max_length).collect());
    }

    // SAFETY: We've already checked max_length > suffix.len() above
    let target_len = max_length.saturating_sub(suffix.len());

    // Find a safe truncation point (don't cut in middle of unicode char)
    let mut truncate_at = 0;
    for (i, _) in input.char_indices() {
        if i > target_len {
            break;
        }
        truncate_at = i;
    }

    // Handle case where first char is longer than target
    if truncate_at == 0 && !input.is_empty() {
        // Take the first char if possible
        if let Some((i, _)) = input.char_indices().nth(1) {
            truncate_at = i;
        } else {
            truncate_at = input.len();
        }
    }

    let mut result = String::with_capacity(max_length);
    // SAFETY: truncate_at is always from char_indices(), guaranteeing valid UTF-8 boundary
    if let Some(prefix) = input.get(..truncate_at) {
        result.push_str(prefix);
    }
    result.push_str(suffix);
    Cow::Owned(result)
}

// ============================================================================
// Shortcut Functions for Observe Module
// ============================================================================

/// Quick sanitize for event messages (default options)
///
/// Use for the main message field of log events.
#[inline]
pub fn sanitize_event_message(msg: &str) -> Cow<'_, str> {
    sanitize_for_log(msg)
}

/// Quick sanitize for metadata values (strict, limited length)
///
/// Use for context/metadata fields that should be compact and safe.
#[inline]
pub fn sanitize_metadata_value(value: &str) -> Cow<'_, str> {
    let options = TextConfig::strict().with_max_length(1000);
    sanitize_for_log_with_config(value, &options)
}

/// Quick sanitize for context fields (JSON-safe)
///
/// Use for fields that will be serialized to JSON.
#[inline]
pub fn sanitize_context_field(field: &str) -> Cow<'_, str> {
    sanitize_for_log_with_config(field, &TextConfig::json_safe())
}

/// Check if a string is safe for log output without modification
///
/// Returns true if the string contains no characters that would need
/// sanitization with the default options.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::data::text::is_log_safe;
///
/// assert!(is_log_safe("Hello, World!"));
/// assert!(!is_log_safe("Hello\nWorld"));
/// assert!(!is_log_safe("\x1B[31mRed\x1B[0m"));
/// ```
pub fn is_log_safe(input: &str) -> bool {
    input.chars().all(|c| is_log_safe_char(c, true, true))
        && !is_ansi_escapes_present(input)
        && !input.contains('\n')
        && !input.contains('\r')
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // --- Default Sanitization Tests ---

    #[test]
    fn test_sanitize_clean_input() {
        let input = "Hello, World!";
        let result = sanitize_for_log(input);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, "Hello, World!");
    }

    #[test]
    fn test_sanitize_newlines() {
        assert_eq!(sanitize_for_log("line1\nline2"), "line1\\nline2");
        assert_eq!(sanitize_for_log("multi\nline\ntext"), "multi\\nline\\ntext");
    }

    #[test]
    fn test_sanitize_carriage_returns() {
        assert_eq!(sanitize_for_log("text\rmore"), "text\\rmore");
        assert_eq!(sanitize_for_log("crlf\r\nhere"), "crlf\\r\\nhere");
    }

    #[test]
    fn test_sanitize_ansi_escapes() {
        assert_eq!(sanitize_for_log("\x1B[31mred\x1B[0m"), "red");
        assert_eq!(
            sanitize_for_log("before\x1B[1mbold\x1B[0mafter"),
            "beforeboldafter"
        );
        assert_eq!(sanitize_for_log("\x1B[2J"), ""); // Clear screen
    }

    #[test]
    fn test_sanitize_control_chars() {
        assert_eq!(sanitize_for_log("hello\x00world"), "helloworld");
        assert_eq!(sanitize_for_log("\x07bell"), "bell");
        assert_eq!(sanitize_for_log("back\x08space"), "backspace");
    }

    #[test]
    fn test_sanitize_mixed() {
        let input = "User: admin\n\x1B[31mPassword: \x00secret\x1B[0m";
        let result = sanitize_for_log(input);
        assert_eq!(result, "User: admin\\nPassword: secret");
    }

    // --- Options Tests ---

    #[test]
    fn test_strict_options() {
        let options = TextConfig::strict();
        let result = sanitize_for_log_with_config("Tab\there", &options);
        assert_eq!(result, "Tab\\there");
    }

    #[test]
    fn test_relaxed_options() {
        let options = TextConfig::relaxed();
        let result = sanitize_for_log_with_config("line1\nline2", &options);
        assert_eq!(result, "line1\nline2"); // Newlines preserved
    }

    #[test]
    fn test_json_safe_options() {
        let options = TextConfig::json_safe();
        let result = sanitize_for_log_with_config("tab\there\nnewline", &options);
        assert_eq!(result, "tab\\there\\nnewline");
    }

    #[test]
    fn test_max_length() {
        let options = TextConfig::default().with_max_length(10);
        let result = sanitize_for_log_with_config("Hello, World!", &options);
        assert_eq!(result, "Hello, ...");
    }

    #[test]
    fn test_max_length_exact() {
        let options = TextConfig::default().with_max_length(5);
        let result = sanitize_for_log_with_config("Hello", &options);
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_unicode_handling() {
        // Default allows unicode
        assert_eq!(sanitize_for_log("日本語"), "日本語");

        // Strict removes unicode
        let options = TextConfig::strict();
        let result = sanitize_for_log_with_config("日本語", &options);
        assert!(result.starts_with("\\u"));
    }

    // --- Convenience Function Tests ---

    #[test]
    fn test_escape_line_breaks() {
        assert_eq!(escape_line_breaks("no breaks"), "no breaks");
        assert_eq!(escape_line_breaks("line1\nline2"), "line1\\nline2");
        assert_eq!(escape_line_breaks("cr\rhere"), "cr\\rhere");
        assert_eq!(escape_line_breaks("crlf\r\nhere"), "crlf\\r\\nhere");
    }

    #[test]
    fn test_strip_ansi_escapes() {
        assert_eq!(strip_ansi_escapes("plain"), "plain");
        assert_eq!(strip_ansi_escapes("\x1B[31mred\x1B[0m"), "red");
        assert_eq!(strip_ansi_escapes("\x1B]0;title\x07"), "");
    }

    #[test]
    fn test_strip_control_chars() {
        assert_eq!(strip_control_chars("clean"), "clean");
        assert_eq!(strip_control_chars("hello\x00world"), "helloworld");
        assert_eq!(strip_control_chars("\x07bell\x08back"), "bellback");
    }

    #[test]
    fn test_truncate_for_log() {
        assert_eq!(truncate_for_log("short", 10, "..."), "short");
        assert_eq!(truncate_for_log("Hello, World!", 10, "..."), "Hello, ...");
        assert_eq!(truncate_for_log("Hello", 3, ".."), "H..");
    }

    #[test]
    fn test_truncate_unicode() {
        // Should not cut in middle of unicode char
        let result = truncate_for_log("日本語テスト", 10, "...");
        assert!(result.is_char_boundary(result.len() - 3)); // Valid UTF-8
    }

    // --- Shortcut Function Tests ---

    #[test]
    fn test_sanitize_event_message() {
        assert_eq!(sanitize_event_message("safe message"), "safe message");
        assert_eq!(sanitize_event_message("line1\nline2"), "line1\\nline2");
    }

    #[test]
    fn test_sanitize_metadata_value() {
        let result = sanitize_metadata_value("value\twith\ttabs");
        assert_eq!(result, "value\\twith\\ttabs");
    }

    #[test]
    fn test_sanitize_context_field() {
        let result = sanitize_context_field("field\nvalue");
        assert_eq!(result, "field\\nvalue");
    }

    #[test]
    fn test_is_log_safe() {
        assert!(is_log_safe("Hello, World!"));
        assert!(is_log_safe("Numbers: 123"));
        assert!(!is_log_safe("has\nnewline"));
        assert!(!is_log_safe("\x1B[31mcolor"));
        assert!(!is_log_safe("null\x00byte"));
    }

    // --- Edge Cases ---

    #[test]
    fn test_empty_string() {
        assert_eq!(sanitize_for_log(""), "");
        assert!(matches!(sanitize_for_log(""), Cow::Borrowed(_)));
    }

    #[test]
    fn test_only_control_chars() {
        assert_eq!(sanitize_for_log("\x00\x01\x02"), "");
    }

    #[test]
    fn test_only_ansi() {
        assert_eq!(sanitize_for_log("\x1B[31m\x1B[0m"), "");
    }

    #[test]
    fn test_replacement_char_mode() {
        let options = TextConfig::default().with_replacement_char(true);
        let result = sanitize_for_log_with_config("hello\x00world", &options);
        assert_eq!(result, "hello\u{FFFD}world");
    }

    #[test]
    fn test_osc_sequence() {
        // OSC (Operating System Command) sequences set window title etc.
        let input = "\x1B]0;malicious title\x07";
        assert_eq!(sanitize_for_log(input), "");
    }

    #[test]
    fn test_cursor_controls() {
        // Cursor movement shouldn't appear in logs
        assert_eq!(sanitize_for_log("\x1B[2J"), ""); // Clear screen
        assert_eq!(sanitize_for_log("\x1B[H"), ""); // Cursor home
        assert_eq!(sanitize_for_log("\x1B[5A"), ""); // Cursor up
    }

    #[test]
    fn test_cow_optimization() {
        // Clean input should return borrowed
        let input = "clean input";
        let result = sanitize_for_log(input);
        assert!(matches!(result, Cow::Borrowed(_)));

        // Dirty input should return owned
        let input = "dirty\ninput";
        let result = sanitize_for_log(input);
        assert!(matches!(result, Cow::Owned(_)));
    }
}
