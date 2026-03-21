//! Security threat detection for paths
//!
//! Pure detection functions for identifying security threats in paths.
//! All functions return `bool` or `Vec<SecurityThreat>` - no side effects.
//!
//! ## OWASP Coverage
//!
//! This module detects threats per OWASP and CWE guidelines:
//! - **CWE-22**: Path Traversal (`..`, encoded variants)
//! - **CWE-78**: OS Command Injection (`$()`, backticks, `${}`, `$VAR`)
//! - **CWE-158**: Null Byte Injection (`\0`)
//! - **CWE-175**: Double/Multiple Encoding (`%25xx`)
//! - **CWE-707**: Control Character Injection
//!
//! ## Design Philosophy
//!
//! Detection functions are **sensitive** (favor false positives over false negatives).
//! Use validation functions when you need precise enforcement.
//!
//! ## Examples
//!
//! ```ignore
//! use octarine::primitives::paths::security::detection;
//!
//! // Check for any security threats
//! assert!(detection::is_threat_present("../../../etc/passwd"));
//! assert!(detection::is_threat_present("file$(whoami).txt"));
//! assert!(!detection::is_threat_present("safe/path/file.txt"));
//!
//! // Get all detected threats
//! let threats = detection::detect_threats("..%2f..%2f$(cmd)");
//! assert!(!threats.is_empty());
//! ```

use crate::primitives::data::paths::types::SecurityThreat;
use std::path::{Component, Path};

// ============================================================================
// Comprehensive Detection
// ============================================================================

/// Detect all security threats in a path
///
/// Scans the path for all known threat patterns and returns a vector
/// of detected threats. Empty vector means no threats detected.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::detection::detect_threats;
/// use octarine::primitives::paths::types::SecurityThreat;
///
/// let threats = detect_threats("../$(whoami)");
/// assert!(threats.contains(&SecurityThreat::Traversal));
/// assert!(threats.contains(&SecurityThreat::CommandInjection));
/// ```
#[must_use]
pub fn detect_threats(path: &str) -> Vec<SecurityThreat> {
    let mut threats = Vec::new();

    // Check each threat type
    if is_traversal_present(path) {
        threats.push(SecurityThreat::Traversal);
    }

    if is_encoded_traversal_present(path) {
        threats.push(SecurityThreat::EncodedTraversal);
    }

    if is_command_injection_present(path) {
        threats.push(SecurityThreat::CommandInjection);
    }

    if is_variable_expansion_present(path) {
        threats.push(SecurityThreat::VariableExpansion);
    }

    if is_shell_metacharacters_present(path) {
        threats.push(SecurityThreat::ShellMetacharacters);
    }

    if is_null_bytes_present(path) {
        threats.push(SecurityThreat::NullByte);
    }

    if is_control_characters_present(path) {
        threats.push(SecurityThreat::ControlCharacters);
    }

    if is_double_encoding_present(path) {
        threats.push(SecurityThreat::DoubleEncoding);
    }

    if is_absolute_path_present(path) {
        threats.push(SecurityThreat::AbsolutePath);
    }

    threats
}

/// Check if path contains any security threat
///
/// Quick check that returns `true` if any threat is detected.
/// More efficient than `detect_threats()` when you only need a boolean result.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::detection::is_threat_present;
///
/// assert!(is_threat_present("../etc/passwd"));
/// assert!(is_threat_present("file;ls"));
/// assert!(!is_threat_present("safe/path.txt"));
/// ```
#[must_use]
pub fn is_threat_present(path: &str) -> bool {
    is_traversal_present(path)
        || is_encoded_traversal_present(path)
        || is_command_injection_present(path)
        || is_variable_expansion_present(path)
        || is_shell_metacharacters_present(path)
        || is_null_bytes_present(path)
        || is_control_characters_present(path)
        || is_double_encoding_present(path)
}

// ============================================================================
// Traversal Detection (CWE-22)
// ============================================================================

/// Check for directory traversal attempts (`..`)
///
/// Detects `..` path components that could traverse outside intended directories.
/// Uses Rust's `Path` parsing to correctly identify `..` as a component
/// vs `.` within filenames (e.g., `file..txt` is NOT traversal).
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::security::detection::is_traversal_present;
///
/// assert!(is_traversal_present("../../../etc"));
/// assert!(is_traversal_present("path/../sensitive"));
/// assert!(is_traversal_present(".."));
///
/// // NOT traversal - dots in filename
/// assert!(!is_traversal_present("file..txt"));
/// assert!(!is_traversal_present("path/to/file.txt"));
/// ```
#[must_use]
pub fn is_traversal_present(path: &str) -> bool {
    // Use std::path for platform-native path parsing
    let has_native_traversal = Path::new(path)
        .components()
        .any(|c| matches!(c, Component::ParentDir));

    if has_native_traversal {
        return true;
    }

    // Also check for Windows-style backslash traversals on Unix
    // This catches "..\\" patterns that Unix Path doesn't parse as traversal
    #[cfg(not(windows))]
    {
        if path.contains("..\\") {
            return true;
        }
    }

    // Detect traversal bypass techniques:
    // - "..../" or "....//" - repeated dots that could normalize to "../"
    // - Any pattern of 2+ dots followed by a path separator
    // These are common bypass techniques documented in OWASP
    let bytes = path.as_bytes();
    let mut dot_count = 0_u32;
    for &b in bytes {
        if b == b'.' {
            dot_count = dot_count.saturating_add(1);
        } else if b == b'/' || b == b'\\' {
            // If we have 2 or more dots before a separator, it's suspicious
            if dot_count >= 2 {
                return true;
            }
            dot_count = 0;
        } else {
            dot_count = 0;
        }
    }

    false
}

/// Check for URL-encoded traversal sequences
///
/// Detects percent-encoded characters that could bypass traversal checks:
/// - `%2e` or `%2E` = `.`
/// - `%2f` or `%2F` = `/`
/// - `%5c` or `%5C` = `\`
///
/// These encodings are often used to bypass naive string-based checks.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::security::detection::is_encoded_traversal_present;
///
/// assert!(is_encoded_traversal_present("..%2f..%2fetc"));
/// assert!(is_encoded_traversal_present("%2e%2e/secret"));
/// assert!(is_encoded_traversal_present("path%5c..%5cetc"));  // Windows backslash
///
/// assert!(!is_encoded_traversal_present("normal/path"));
/// assert!(!is_encoded_traversal_present("file%20name.txt")); // Space encoding is OK
/// ```
#[must_use]
pub fn is_encoded_traversal_present(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("%2e") // Encoded .
        || lower.contains("%2f") // Encoded /
        || lower.contains("%5c") // Encoded \
        // Unicode overlong encodings (CVE-2000-0884, etc.)
        || lower.contains("%c0%ae") // Overlong .
        || lower.contains("%c0%af") // Overlong /
        || lower.contains("%c1%9c") // Overlong \
        || lower.contains("%c1%1c") // Another overlong \
}

// ============================================================================
// Command Injection Detection (CWE-78)
// ============================================================================

/// Check for command injection patterns
///
/// Detects shell command substitution patterns that could execute arbitrary commands:
/// - `$()` - POSIX command substitution
/// - Backticks - Legacy command substitution
/// - `${}` - Variable expansion with potential command execution
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::security::detection::is_command_injection_present;
///
/// assert!(is_command_injection_present("file$(whoami).txt"));
/// assert!(is_command_injection_present("path`id`.txt"));
/// assert!(is_command_injection_present("${HOME}/file"));
///
/// assert!(!is_command_injection_present("safe/path.txt"));
/// ```
#[must_use]
pub fn is_command_injection_present(path: &str) -> bool {
    path.contains("$(") || path.contains('`') || path.contains("${")
}

/// Check for variable expansion patterns
///
/// Detects shell variable expansion that could leak environment information:
/// - `$VAR` - Simple variable expansion
/// - `${VAR}` - Braced variable expansion
///
/// Note: This is more sensitive than `is_command_injection_present` as it catches
/// any `$` character (except when followed by whitespace or end of string).
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::security::detection::is_variable_expansion_present;
///
/// assert!(is_variable_expansion_present("$HOME/file"));
/// assert!(is_variable_expansion_present("${USER}/path"));
/// assert!(is_variable_expansion_present("path/$VAR"));
///
/// assert!(!is_variable_expansion_present("safe/path.txt"));
/// assert!(!is_variable_expansion_present("price$5")); // $ at end
/// ```
#[must_use]
pub fn is_variable_expansion_present(path: &str) -> bool {
    // Look for $ followed by alphanumeric, underscore, or brace
    let bytes = path.as_bytes();
    for (i, &byte) in bytes.iter().enumerate() {
        if byte == b'$' {
            // Check what follows (saturating_add prevents overflow)
            if let Some(&next) = bytes.get(i.saturating_add(1))
                && (next == b'('
                    || next == b'{'
                    || next == b'_'
                    || next.is_ascii_alphabetic()
                    || next.is_ascii_digit())
            {
                return true;
            }
        }
    }
    false
}

/// Check for shell metacharacters
///
/// Detects characters that could allow command chaining or piping:
/// - `;` - Command separator
/// - `|` - Pipe
/// - `&` - Background/AND operator
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::security::detection::is_shell_metacharacters_present;
///
/// assert!(is_shell_metacharacters_present("file;ls"));
/// assert!(is_shell_metacharacters_present("path|cat /etc/passwd"));
/// assert!(is_shell_metacharacters_present("cmd && rm -rf"));
/// assert!(is_shell_metacharacters_present("file & whoami"));
///
/// assert!(!is_shell_metacharacters_present("safe/path.txt"));
/// ```
#[must_use]
pub fn is_shell_metacharacters_present(path: &str) -> bool {
    path.contains(';') || path.contains('|') || path.contains('&')
}

// ============================================================================
// Character-Based Threats (CWE-158, CWE-707)
// ============================================================================

/// Check for null byte injection
///
/// Null bytes (`\0`) can truncate strings in C APIs and bypass security checks.
/// This is a critical security check (CWE-158).
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::security::detection::is_null_bytes_present;
///
/// assert!(is_null_bytes_present("file.txt\0.jpg"));
/// assert!(is_null_bytes_present("path\0/sensitive"));
///
/// assert!(!is_null_bytes_present("safe/path.txt"));
/// ```
#[must_use]
pub fn is_null_bytes_present(path: &str) -> bool {
    path.contains('\0')
}

/// Check for control characters
///
/// Detects control characters that can break parsing, logging, or display:
/// - Newline (`\n`)
/// - Carriage return (`\r`)
/// - Tab (`\t`)
/// - Other ASCII control characters (0x00-0x1F, 0x7F)
///
/// Note: Null bytes are also control characters but checked separately
/// due to their higher severity.
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::security::detection::is_control_characters_present;
///
/// assert!(is_control_characters_present("file\n.txt"));
/// assert!(is_control_characters_present("path\r\ninjection"));
/// assert!(is_control_characters_present("file\t.txt"));
///
/// assert!(!is_control_characters_present("safe/path.txt"));
/// ```
#[must_use]
pub fn is_control_characters_present(path: &str) -> bool {
    path.chars().any(|c| c.is_control())
}

// ============================================================================
// Encoding-Based Threats (CWE-175)
// ============================================================================

/// Check for double/multiple encoding
///
/// Per OWASP ESAPI: "Data encoded more than once is not something that
/// a normal user would generate and should be regarded as an attack."
///
/// Detects `%25` (encoded `%`) followed by hex digits, indicating
/// that encoded data has been encoded again:
/// - `%252e` = `%2e` = `.`
/// - `%252f` = `%2f` = `/`
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::security::detection::is_double_encoding_present;
///
/// assert!(is_double_encoding_present("path%252e%252e"));  // Double-encoded ..
/// assert!(is_double_encoding_present("%252fetc%252fpasswd"));  // Double-encoded /etc/passwd
///
/// assert!(!is_double_encoding_present("path%2e%2e"));  // Single encoding (not this check)
/// assert!(!is_double_encoding_present("normal/path"));
/// ```
#[must_use]
pub fn is_double_encoding_present(path: &str) -> bool {
    let bytes = path.as_bytes();

    // Need at least 5 bytes for %25XX pattern
    if bytes.len() < 5 {
        return false;
    }

    // Use windows to safely check sequential bytes
    for window in bytes.windows(5) {
        // Look for %25 (encoded %) followed by two hex digits
        if let [b'%', b'2', b'5', c1, c2] = window
            && (*c1 as char).is_ascii_hexdigit()
            && (*c2 as char).is_ascii_hexdigit()
        {
            return true;
        }
    }

    false
}

// ============================================================================
// Path Type Detection
// ============================================================================

/// Check if path is absolute
///
/// Detects absolute paths that might escape intended boundaries:
/// - Unix absolute: `/path`
/// - Windows drive: `C:\path`
/// - Windows UNC: `\\server\share`
///
/// ## Examples
///
/// ```ignore
/// use octarine::primitives::paths::security::detection::is_absolute_path_present;
///
/// assert!(is_absolute_path_present("/etc/passwd"));
/// assert!(is_absolute_path_present("C:\\Windows\\System32"));
/// assert!(is_absolute_path_present("\\\\server\\share"));
///
/// assert!(!is_absolute_path_present("relative/path"));
/// assert!(!is_absolute_path_present("./current"));
/// ```
#[must_use]
pub fn is_absolute_path_present(path: &str) -> bool {
    // Unix absolute
    if path.starts_with('/') {
        return true;
    }

    // Windows UNC
    if path.starts_with("\\\\") {
        return true;
    }

    // Windows drive letter (e.g., C:\) - use safe indexing
    let bytes = path.as_bytes();
    if let Some(&[first, b':', sep]) = bytes.get(..3).and_then(|s| <&[u8; 3]>::try_from(s).ok())
        && (first as char).is_ascii_alphabetic()
        && (sep == b'\\' || sep == b'/')
    {
        return true;
    }

    // Also check with Rust's Path for edge cases
    Path::new(path).is_absolute()
}

// ============================================================================
// Combined Detection Helpers
// ============================================================================

/// Check for any injection-related threats
///
/// Combines command injection, variable expansion, and shell metacharacter checks.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::detection::is_injection_present;
///
/// assert!(is_injection_present("$(whoami)"));
/// assert!(is_injection_present("$HOME"));
/// assert!(is_injection_present("file;ls"));
/// assert!(!is_injection_present("safe.txt"));
/// ```
#[must_use]
pub fn is_injection_present(path: &str) -> bool {
    is_command_injection_present(path)
        || is_variable_expansion_present(path)
        || is_shell_metacharacters_present(path)
}

/// Check for any traversal-related threats
///
/// Combines basic traversal, encoded traversal, and absolute path checks.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::detection::is_any_traversal_present;
///
/// assert!(is_any_traversal_present("../secret"));
/// assert!(is_any_traversal_present("%2e%2e/secret"));
/// assert!(is_any_traversal_present("/etc/passwd"));
/// assert!(!is_any_traversal_present("safe/path.txt"));
/// ```
#[must_use]
pub fn is_any_traversal_present(path: &str) -> bool {
    is_traversal_present(path)
        || is_encoded_traversal_present(path)
        || is_absolute_path_present(path)
}

/// Check for any character-based threats
///
/// Combines null byte and control character checks.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::detection::is_dangerous_characters_present;
///
/// assert!(is_dangerous_characters_present("file\0.txt"));
/// assert!(is_dangerous_characters_present("path\n.txt"));
/// assert!(!is_dangerous_characters_present("safe.txt"));
/// ```
#[must_use]
pub fn is_dangerous_characters_present(path: &str) -> bool {
    is_null_bytes_present(path) || is_control_characters_present(path)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ------------------------------------------------------------------------
    // Traversal Detection Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_traversal_present_basic() {
        assert!(is_traversal_present(".."));
        assert!(is_traversal_present("../"));
        assert!(is_traversal_present("../etc"));
        assert!(is_traversal_present("path/../secret"));
        assert!(is_traversal_present("a/b/../../c"));
    }

    #[test]
    fn test_is_traversal_present_not_triggered() {
        assert!(!is_traversal_present("file.txt"));
        assert!(!is_traversal_present("file..txt")); // Dots in filename
        assert!(!is_traversal_present("path/to/file"));
        assert!(!is_traversal_present("./current")); // Current dir is OK
        assert!(!is_traversal_present("...")); // Three dots - not traversal
    }

    #[test]
    fn test_is_encoded_traversal_present() {
        assert!(is_encoded_traversal_present("%2e%2e"));
        assert!(is_encoded_traversal_present("%2E%2E")); // Uppercase
        assert!(is_encoded_traversal_present("..%2f..%2fetc"));
        assert!(is_encoded_traversal_present("%2e%2e%5c")); // Windows
        assert!(is_encoded_traversal_present("path%2Ffile")); // Encoded slash
    }

    #[test]
    fn test_is_encoded_traversal_present_not_triggered() {
        assert!(!is_encoded_traversal_present("normal/path"));
        assert!(!is_encoded_traversal_present("file%20name.txt")); // Space encoding OK
        assert!(!is_encoded_traversal_present("%2b")); // + encoding OK
    }

    // ------------------------------------------------------------------------
    // Command Injection Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_command_injection_present() {
        assert!(is_command_injection_present("$(whoami)"));
        assert!(is_command_injection_present("file$(cmd).txt"));
        assert!(is_command_injection_present("`ls`"));
        assert!(is_command_injection_present("path`id`.txt"));
        assert!(is_command_injection_present("${HOME}"));
        assert!(is_command_injection_present("${PATH}/bin"));
    }

    #[test]
    fn test_is_command_injection_present_not_triggered() {
        assert!(!is_command_injection_present("safe/path.txt"));
        assert!(!is_command_injection_present("file.txt"));
        assert!(!is_command_injection_present("$")); // Lone $ without pattern
    }

    #[test]
    fn test_is_variable_expansion_present() {
        assert!(is_variable_expansion_present("$HOME"));
        assert!(is_variable_expansion_present("$USER/file"));
        assert!(is_variable_expansion_present("${PATH}"));
        assert!(is_variable_expansion_present("$_var"));
        assert!(is_variable_expansion_present("$VAR123"));
        assert!(is_variable_expansion_present("$(cmd)")); // Also caught
    }

    #[test]
    fn test_is_variable_expansion_present_not_triggered() {
        assert!(!is_variable_expansion_present("safe/path"));
        assert!(!is_variable_expansion_present("$ alone")); // $ followed by space
        assert!(!is_variable_expansion_present("price$")); // $ at end
    }

    #[test]
    fn test_is_shell_metacharacters_present() {
        assert!(is_shell_metacharacters_present(";"));
        assert!(is_shell_metacharacters_present("file;ls"));
        assert!(is_shell_metacharacters_present("path|cat"));
        assert!(is_shell_metacharacters_present("file&whoami"));
        assert!(is_shell_metacharacters_present("cmd&&other"));
        assert!(is_shell_metacharacters_present("a||b"));
    }

    #[test]
    fn test_is_shell_metacharacters_present_not_triggered() {
        assert!(!is_shell_metacharacters_present("safe/path.txt"));
        assert!(!is_shell_metacharacters_present("file.txt"));
    }

    // ------------------------------------------------------------------------
    // Character-Based Threat Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_null_bytes_present() {
        assert!(is_null_bytes_present("file\0.txt"));
        assert!(is_null_bytes_present("\0"));
        assert!(is_null_bytes_present("path\0/secret"));
    }

    #[test]
    fn test_is_null_bytes_present_not_triggered() {
        assert!(!is_null_bytes_present("safe/path.txt"));
        assert!(!is_null_bytes_present(""));
    }

    #[test]
    fn test_is_control_characters_present() {
        assert!(is_control_characters_present("file\n.txt"));
        assert!(is_control_characters_present("path\r\n"));
        assert!(is_control_characters_present("file\t.txt"));
        assert!(is_control_characters_present("\x00")); // Null
        assert!(is_control_characters_present("\x1F")); // ASCII control
        assert!(is_control_characters_present("\x7F")); // DEL
    }

    #[test]
    fn test_is_control_characters_present_not_triggered() {
        assert!(!is_control_characters_present("safe/path.txt"));
        assert!(!is_control_characters_present("file with spaces.txt"));
    }

    // ------------------------------------------------------------------------
    // Encoding-Based Threat Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_double_encoding_present() {
        assert!(is_double_encoding_present("%252e%252e")); // %2e%2e (double-encoded ..)
        assert!(is_double_encoding_present("%252f")); // %2f (double-encoded /)
        assert!(is_double_encoding_present("path%2526")); // %26 (double-encoded &)
        assert!(is_double_encoding_present("%255c")); // %5c (double-encoded \)
    }

    #[test]
    fn test_is_double_encoding_present_not_triggered() {
        assert!(!is_double_encoding_present("%2e%2e")); // Single encoding
        assert!(!is_double_encoding_present("normal/path"));
        assert!(!is_double_encoding_present("%25")); // Just %25, no following hex
        assert!(!is_double_encoding_present("%25g")); // Not hex
    }

    // ------------------------------------------------------------------------
    // Absolute Path Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_absolute_path_present_unix() {
        assert!(is_absolute_path_present("/"));
        assert!(is_absolute_path_present("/etc"));
        assert!(is_absolute_path_present("/etc/passwd"));
    }

    #[test]
    fn test_is_absolute_path_present_windows() {
        assert!(is_absolute_path_present("C:\\"));
        assert!(is_absolute_path_present("C:\\Windows"));
        assert!(is_absolute_path_present("D:/path")); // Forward slash variant
        assert!(is_absolute_path_present("\\\\server\\share")); // UNC
    }

    #[test]
    fn test_is_absolute_path_present_not_triggered() {
        assert!(!is_absolute_path_present("relative/path"));
        assert!(!is_absolute_path_present("./current"));
        assert!(!is_absolute_path_present("path/to/file"));
        assert!(!is_absolute_path_present("")); // Empty
    }

    // ------------------------------------------------------------------------
    // Comprehensive Detection Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_detect_threats_multiple() {
        let threats = detect_threats("../$(whoami)\0");
        assert!(threats.contains(&SecurityThreat::Traversal));
        assert!(threats.contains(&SecurityThreat::CommandInjection));
        assert!(threats.contains(&SecurityThreat::VariableExpansion));
        assert!(threats.contains(&SecurityThreat::NullByte));
        assert!(threats.contains(&SecurityThreat::ControlCharacters));
    }

    #[test]
    fn test_detect_threats_empty_for_safe() {
        let threats = detect_threats("safe/path/file.txt");
        assert!(threats.is_empty());
    }

    #[test]
    fn test_is_threat_present_comprehensive() {
        // All threat types should trigger
        assert!(is_threat_present("../secret"));
        assert!(is_threat_present("%2e%2e/secret"));
        assert!(is_threat_present("$(cmd)"));
        assert!(is_threat_present("$HOME"));
        assert!(is_threat_present("file;ls"));
        assert!(is_threat_present("file\0.txt"));
        assert!(is_threat_present("file\n.txt"));
        assert!(is_threat_present("%252e"));

        // Safe paths
        assert!(!is_threat_present("safe/path.txt"));
        assert!(!is_threat_present("file.txt"));
        assert!(!is_threat_present("path/to/file.txt"));
    }

    // ------------------------------------------------------------------------
    // Combined Helper Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_injection_present() {
        assert!(is_injection_present("$(cmd)"));
        assert!(is_injection_present("$VAR"));
        assert!(is_injection_present("file;ls"));
        assert!(!is_injection_present("safe.txt"));
    }

    #[test]
    fn test_is_any_traversal_present() {
        assert!(is_any_traversal_present("../"));
        assert!(is_any_traversal_present("%2e%2e"));
        assert!(is_any_traversal_present("/absolute"));
        assert!(!is_any_traversal_present("relative"));
    }

    #[test]
    fn test_is_dangerous_characters_present() {
        assert!(is_dangerous_characters_present("\0"));
        assert!(is_dangerous_characters_present("\n"));
        assert!(!is_dangerous_characters_present("safe"));
    }
}
