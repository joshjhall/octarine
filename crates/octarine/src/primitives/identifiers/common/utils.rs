//! Common identifier validation primitives
//!
//! Shared validation functions used across identifier modules:
//! - Start character validation (alphabetic or underscore)
//! - Valid character checking (with configurable allowed special chars)
//! - Injection pattern detection (command injection, variable expansion)
//!
//! ## Design Principles
//!
//! - **No logging**: Pure validation functions
//! - **Configurable**: Different identifier types have different allowed characters
//! - **Security-focused**: Command injection detection

/// Check if identifier starts with valid character
///
/// Valid start characters are:
/// - ASCII alphabetic (a-z, A-Z)
/// - Underscore (_)
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::common::is_valid_start_char;
///
/// assert!(is_valid_start_char("user_id"));
/// assert!(is_valid_start_char("_private"));
/// assert!(!is_valid_start_char("123table"));
/// assert!(!is_valid_start_char(""));
/// ```
#[must_use]
pub fn is_valid_start_char(name: &str) -> bool {
    name.chars()
        .next()
        .map(|ch| ch.is_ascii_alphabetic() || ch == '_')
        .unwrap_or(false)
}

/// Check if string contains only valid identifier characters
///
/// Validates that all characters in the identifier are:
/// - ASCII alphanumeric (a-z, A-Z, 0-9)
/// - Underscore (_) - always allowed
/// - Additional special characters passed in `allowed_special`
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::common::is_identifier_chars;
///
/// // Database identifier (allows $)
/// assert!(is_identifier_chars("table_name", &['$']));
///
/// // Environment variable (only alphanumeric + underscore)
/// assert!(is_identifier_chars("USER_ID", &[]));
///
/// // Metric name (allows .)
/// assert!(is_identifier_chars("http.requests.total", &['.']));
/// ```
#[must_use]
pub fn is_identifier_chars(name: &str, allowed_special: &[char]) -> bool {
    name.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || allowed_special.contains(&ch))
}

/// Check if string has command injection patterns present
///
/// Detects common injection attack patterns including:
/// - **Command substitution**: `$(command)`, `` `command` ``
/// - **Variable expansion**: `${VAR}`, `$VAR` (dangerous in shell contexts)
/// - **Shell metacharacters**: `;`, `|`, `&` (command chaining)
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::common::is_injection_pattern_present;
///
/// // Injection patterns detected
/// assert!(is_injection_pattern_present("$(whoami)"));
/// assert!(is_injection_pattern_present("`ls -la`"));
/// assert!(is_injection_pattern_present("${HOME}"));
/// assert!(is_injection_pattern_present("$HOME"));      // Plain variable expansion
/// assert!(is_injection_pattern_present("file_$USER")); // Embedded variable
/// assert!(is_injection_pattern_present("cmd1; cmd2"));
///
/// // Safe strings
/// assert!(!is_injection_pattern_present("user_id"));
/// assert!(!is_injection_pattern_present("price$50"));  // $ followed by digit
/// assert!(!is_injection_pattern_present("end$"));      // $ at end of string
/// ```
///
/// # Security Considerations
///
/// - **OWASP Top 10**: Prevents OS Command Injection (A03:2021)
/// - **False Positives**: Prefers false positives over false negatives
/// - Plain `$VAR` patterns are detected because shells expand them
#[must_use]
pub fn is_injection_pattern_present(s: &str) -> bool {
    // Command substitution patterns
    if s.contains("$(") || s.contains('`') {
        return true;
    }

    // Variable expansion with braces (dangerous in shell contexts)
    if s.contains("${") {
        return true;
    }

    // Plain variable expansion: $VAR pattern
    // Shell will expand $HOME, $USER, $PATH, etc.
    // We check for $ followed by alphabetic char or underscore (valid var start)
    let chars: Vec<char> = s.chars().collect();
    for (i, &ch) in chars.iter().enumerate() {
        if ch == '$' {
            // Check next character exists and is valid variable start
            // Use saturating_add to avoid overflow on very long strings
            if let Some(&next) = chars.get(i.saturating_add(1))
                && (next.is_ascii_alphabetic() || next == '_')
            {
                return true;
            }
        }
    }

    // Shell metacharacters that enable command chaining
    if s.contains(';') || s.contains('|') || s.contains('&') {
        return true;
    }

    false
}

/// Check if severe injection patterns are present (more permissive check for values)
///
/// This is a more permissive check than `is_injection_pattern_present`, designed
/// for contexts where some special characters are acceptable (e.g., label values,
/// display text) but severe injection attacks must still be blocked.
///
/// Patterns detected:
/// - SQL injection: `';` pattern
/// - SQL destructive commands: `DROP`, `DELETE`
/// - XSS attacks: `<script`, `javascript:`
/// - Null byte injection: `\0`
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::common::is_severe_injection_pattern_present;
///
/// // Severe patterns detected
/// assert!(is_severe_injection_pattern_present("'; DROP TABLE"));
/// assert!(is_severe_injection_pattern_present("<script>alert(1)</script>"));
/// assert!(is_severe_injection_pattern_present("javascript:void(0)"));
/// assert!(is_severe_injection_pattern_present("value\0null"));
///
/// // Acceptable patterns (would fail strict check but pass here)
/// assert!(!is_severe_injection_pattern_present("value with spaces"));
/// assert!(!is_severe_injection_pattern_present("path/to/resource"));
/// assert!(!is_severe_injection_pattern_present("user@domain.com"));
/// ```
///
/// # Security Considerations
///
/// Use this for user-facing values where:
/// - Some special characters are needed (paths, URLs, etc.)
/// - The most dangerous attacks must still be blocked
/// - The value will be properly escaped before use
#[must_use]
pub fn is_severe_injection_pattern_present(s: &str) -> bool {
    s.contains("';")
        || s.contains("DROP")
        || s.contains("DELETE")
        || s.contains("<script")
        || s.contains("javascript:")
        || s.contains('\0')
}

/// Check if control characters are present in string
///
/// Detects ASCII control characters (0x00-0x1F, 0x7F) except tab,
/// which may be acceptable in some contexts.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::common::is_control_chars_present;
///
/// // Control characters detected
/// assert!(is_control_chars_present("value\0null"));   // Null byte
/// assert!(is_control_chars_present("value\nnewline")); // Newline
/// assert!(is_control_chars_present("value\rcarriage")); // Carriage return
///
/// // Acceptable
/// assert!(!is_control_chars_present("normal text"));
/// assert!(!is_control_chars_present("with\ttab")); // Tab is allowed
/// ```
///
/// # Security Considerations
///
/// Control characters can:
/// - Break log file parsing (newlines)
/// - Truncate strings in C APIs (null bytes)
/// - Cause display issues
#[must_use]
pub fn is_control_chars_present(s: &str) -> bool {
    s.chars().any(|ch| ch.is_control() && ch != '\t')
}

/// Check if SQL-specific injection patterns are present
///
/// Supplements `is_injection_pattern_present` with SQL-specific patterns
/// that may appear in contexts where hyphens are allowed.
///
/// Patterns detected:
/// - `--` (SQL line comment)
/// - `/*` (SQL multi-line comment start)
/// - `';` (SQL statement terminator with quote)
/// - `{{` (template injection)
/// - `../` or `..\\` (path traversal)
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::common::is_sql_injection_pattern_present;
///
/// // SQL injection patterns
/// assert!(is_sql_injection_pattern_present("id--comment"));
/// assert!(is_sql_injection_pattern_present("id/*comment*/"));
/// assert!(is_sql_injection_pattern_present("id';DROP TABLE"));
///
/// // Template and path traversal
/// assert!(is_sql_injection_pattern_present("{{template}}"));
/// assert!(is_sql_injection_pattern_present("../etc/passwd"));
///
/// // Safe strings
/// assert!(!is_sql_injection_pattern_present("normal-identifier"));
/// assert!(!is_sql_injection_pattern_present("api_key_123"));
/// ```
#[must_use]
pub fn is_sql_injection_pattern_present(s: &str) -> bool {
    s.contains("--")
        || s.contains("/*")
        || s.contains("';")
        || s.contains("{{")
        || s.contains("../")
        || s.contains("..\\")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_valid_start_char_alphabetic() {
        assert!(is_valid_start_char("user"));
        assert!(is_valid_start_char("User"));
        assert!(is_valid_start_char("TABLE"));
    }

    #[test]
    fn test_valid_start_char_underscore() {
        assert!(is_valid_start_char("_private"));
        assert!(is_valid_start_char("_id"));
    }

    #[test]
    fn test_invalid_start_char_number() {
        assert!(!is_valid_start_char("123table"));
        assert!(!is_valid_start_char("0user"));
    }

    #[test]
    fn test_invalid_start_char_special() {
        assert!(!is_valid_start_char("-option"));
        assert!(!is_valid_start_char("$var"));
        assert!(!is_valid_start_char(".hidden"));
    }

    #[test]
    fn test_invalid_start_char_empty() {
        assert!(!is_valid_start_char(""));
    }

    #[test]
    fn test_only_valid_chars_basic() {
        assert!(is_identifier_chars("user_id_123", &[]));
        assert!(is_identifier_chars("TABLE_NAME", &[]));
    }

    #[test]
    fn test_only_valid_chars_database() {
        assert!(is_identifier_chars("table$name", &['$']));
        assert!(!is_identifier_chars("table-name", &['$']));
    }

    #[test]
    fn test_only_valid_chars_metrics() {
        assert!(is_identifier_chars("http.requests.total", &['.']));
        assert!(!is_identifier_chars("cpu-usage", &['.']));
    }

    #[test]
    fn test_injection_command_substitution() {
        assert!(is_injection_pattern_present("$(whoami)"));
        assert!(is_injection_pattern_present("`ls -la`"));
    }

    #[test]
    fn test_injection_variable_expansion() {
        // Braced variable expansion
        assert!(is_injection_pattern_present("${HOME}"));
        assert!(is_injection_pattern_present("${USER}"));
        assert!(is_injection_pattern_present("path/${VAR}/file"));
    }

    #[test]
    fn test_injection_plain_variable() {
        // Plain variable expansion (CRITICAL - shells expand these!)
        assert!(is_injection_pattern_present("$HOME"));
        assert!(is_injection_pattern_present("$USER"));
        assert!(is_injection_pattern_present("$PATH"));
        assert!(is_injection_pattern_present("$_private"));

        // Embedded in strings
        assert!(is_injection_pattern_present("file_$USER"));
        assert!(is_injection_pattern_present("path/$HOME/file"));
        assert!(is_injection_pattern_present("prefix$VAR_suffix"));
    }

    #[test]
    fn test_injection_metacharacters() {
        assert!(is_injection_pattern_present("cmd1; cmd2"));
        assert!(is_injection_pattern_present("cat | grep"));
        assert!(is_injection_pattern_present("cmd1 && cmd2"));
        assert!(is_injection_pattern_present("cmd1 || cmd2"));
        assert!(is_injection_pattern_present("background &"));
    }

    #[test]
    fn test_no_injection_safe_strings() {
        // Normal identifiers
        assert!(!is_injection_pattern_present("user_id"));
        assert!(!is_injection_pattern_present("table_name"));
        assert!(!is_injection_pattern_present("MY_CONSTANT"));

        // $ followed by digit (not variable expansion)
        assert!(!is_injection_pattern_present("price$50"));
        assert!(!is_injection_pattern_present("item$1"));

        // $ at end of string
        assert!(!is_injection_pattern_present("end$"));
        assert!(!is_injection_pattern_present("dollar$"));

        // $ followed by special char (not variable)
        assert!(!is_injection_pattern_present("$@")); // $@ is special but not alphanumeric start
        assert!(!is_injection_pattern_present("$$")); // $$ is PID, but not $VAR pattern
    }

    #[test]
    fn test_injection_nested_patterns() {
        // Nested command substitution
        assert!(is_injection_pattern_present("$(echo $(whoami))"));
        assert!(is_injection_pattern_present("`echo `id``"));
    }

    #[test]
    fn test_injection_multiple_patterns() {
        // Multiple injection points
        assert!(is_injection_pattern_present("$(cmd1) | $(cmd2)"));
        assert!(is_injection_pattern_present("$VAR; $OTHER"));
    }

    #[test]
    fn test_injection_edge_cases() {
        // Empty string is safe
        assert!(!is_injection_pattern_present(""));

        // Just special chars without context
        assert!(!is_injection_pattern_present("$"));
        assert!(!is_injection_pattern_present("$1$2$3")); // Positional params, not vars

        // Unicode (should not trigger false positives)
        assert!(!is_injection_pattern_present("café"));
        assert!(!is_injection_pattern_present("日本語"));
    }

    // ------------------------------------------------------------------------
    // Severe Injection Pattern Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_severe_injection_sql() {
        assert!(is_severe_injection_pattern_present("'; DROP TABLE users"));
        assert!(is_severe_injection_pattern_present("value'; SELECT * FROM"));
    }

    #[test]
    fn test_severe_injection_destructive() {
        assert!(is_severe_injection_pattern_present("DROP TABLE users"));
        assert!(is_severe_injection_pattern_present("DELETE FROM users"));
    }

    #[test]
    fn test_severe_injection_xss() {
        assert!(is_severe_injection_pattern_present(
            "<script>alert(1)</script>"
        ));
        assert!(is_severe_injection_pattern_present("javascript:void(0)"));
    }

    #[test]
    fn test_severe_injection_null_byte() {
        assert!(is_severe_injection_pattern_present("value\0null"));
    }

    #[test]
    fn test_severe_injection_safe_values() {
        // These are safe for lenient contexts
        assert!(!is_severe_injection_pattern_present("value with spaces"));
        assert!(!is_severe_injection_pattern_present("/api/users/123"));
        assert!(!is_severe_injection_pattern_present("user@domain.com"));
        assert!(!is_severe_injection_pattern_present("GET"));
        assert!(!is_severe_injection_pattern_present("200"));
    }

    // ------------------------------------------------------------------------
    // Control Character Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_control_chars_detected() {
        assert!(is_control_chars_present("value\0null"));
        assert!(is_control_chars_present("value\nnewline"));
        assert!(is_control_chars_present("value\rcarriage"));
        assert!(is_control_chars_present("\x1b[escape"));
    }

    #[test]
    fn test_control_chars_tab_allowed() {
        // Tab is allowed as it's commonly used in text
        assert!(!is_control_chars_present("value\twith\ttabs"));
    }

    #[test]
    fn test_control_chars_normal_text() {
        assert!(!is_control_chars_present("normal text"));
        assert!(!is_control_chars_present("value with spaces"));
        assert!(!is_control_chars_present("123-456-7890"));
    }

    // ------------------------------------------------------------------------
    // SQL Injection Pattern Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sql_injection_comments() {
        assert!(is_sql_injection_pattern_present("id--comment"));
        assert!(is_sql_injection_pattern_present("id/*comment*/"));
    }

    #[test]
    fn test_sql_injection_statement_terminator() {
        assert!(is_sql_injection_pattern_present("id';DROP TABLE"));
    }

    #[test]
    fn test_sql_injection_template() {
        assert!(is_sql_injection_pattern_present("{{template}}"));
        assert!(is_sql_injection_pattern_present("value{{var}}"));
    }

    #[test]
    fn test_sql_injection_path_traversal() {
        assert!(is_sql_injection_pattern_present("../etc/passwd"));
        assert!(is_sql_injection_pattern_present("..\\windows\\system32"));
    }

    #[test]
    fn test_sql_injection_safe_strings() {
        assert!(!is_sql_injection_pattern_present("normal-identifier"));
        assert!(!is_sql_injection_pattern_present("api_key_123"));
        assert!(!is_sql_injection_pattern_present("my-config-value"));
    }
}
