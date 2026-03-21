//! Security sanitization for paths
//!
//! Sanitization functions that remove or reject security threats in paths.
//! Supports multiple strategies: clean (remove threats), strict (reject), escape (for display).
//!
//! ## Design Philosophy
//!
//! Sanitization is the **final security layer** - it either:
//! - **Strict mode**: Rejects paths with threats (returns `Err`)
//! - **Clean mode**: Removes threats and returns sanitized path
//! - **Escape mode**: Escapes threats for safe display (not filesystem use)
//!
//! ## Strategy Pattern
//!
//! ```ignore
//! use octarine::primitives::paths::types::PathSanitizationStrategy;
//! use octarine::primitives::paths::security::sanitization;
//!
//! let path = "../etc/passwd";
//!
//! // Strict: reject if threats found
//! assert!(sanitization::sanitize_with(path, PathSanitizationStrategy::Strict).is_err());
//!
//! // Clean: remove traversal, keep safe parts
//! let clean = sanitization::sanitize_with(path, PathSanitizationStrategy::Clean).expect("test");
//! assert!(!clean.contains(".."));
//!
//! // Escape: for logging/display only
//! let escaped = sanitization::sanitize_with(path, PathSanitizationStrategy::Escape).expect("test");
//! assert!(escaped.contains("[DOT_DOT]") || !escaped.contains(".."));
//! ```

use super::{detection, validation};
use crate::primitives::data::paths::types::PathSanitizationStrategy;
use crate::primitives::types::Problem;
use std::borrow::Cow;

/// Result type for sanitization functions
pub type SanitizationResult = Result<String, Problem>;

// ============================================================================
// Strategy-Based Sanitization
// ============================================================================

/// Sanitize path using specified strategy
///
/// ## Strategies
///
/// - `Clean`: Remove dangerous patterns, return sanitized path
/// - `Strict`: Return error if any threats detected
/// - `Escape`: Escape dangerous patterns for display (not filesystem safe)
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::types::PathSanitizationStrategy;
/// use octarine::primitives::paths::security::sanitization::sanitize_with;
///
/// // Clean mode removes traversal
/// let result = sanitize_with("../secret/file.txt", PathSanitizationStrategy::Clean);
/// assert!(result.is_ok());
/// assert!(!result.expect("test").contains(".."));
///
/// // Strict mode rejects
/// let result = sanitize_with("../secret", PathSanitizationStrategy::Strict);
/// assert!(result.is_err());
/// ```
pub fn sanitize_with(path: &str, strategy: PathSanitizationStrategy) -> SanitizationResult {
    match strategy {
        PathSanitizationStrategy::Clean => sanitize_clean(path),
        PathSanitizationStrategy::Strict => sanitize_strict(path),
        PathSanitizationStrategy::Escape => sanitize_escape(path),
    }
}

/// Sanitize path (default: Clean strategy)
///
/// Removes dangerous patterns and returns a safe path.
/// For strict rejection, use `sanitize_strict()`.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::sanitization::sanitize;
///
/// let safe = sanitize("../../../etc/passwd").expect("test");
/// assert!(!safe.contains(".."));
/// ```
pub fn sanitize(path: &str) -> SanitizationResult {
    sanitize_clean(path)
}

/// Sanitize path (strict mode)
///
/// Returns error if any security threats are detected.
/// Use when you cannot safely modify the path.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::sanitization::sanitize_strict;
///
/// assert!(sanitize_strict("safe/path.txt").is_ok());
/// assert!(sanitize_strict("../secret").is_err());
/// assert!(sanitize_strict("$(whoami)").is_err());
/// ```
pub fn sanitize_strict(path: &str) -> SanitizationResult {
    // Validate first - reject if any threats
    validation::validate_secure_strict(path)?;

    // Also check for empty/whitespace
    validation::validate_not_empty_strict(path)?;

    Ok(path.to_string())
}

/// Sanitize path (clean mode)
///
/// Removes dangerous patterns and returns a sanitized path.
/// May return error if path becomes empty after sanitization.
///
/// ## What Gets Removed/Fixed
///
/// - Traversal sequences (`..`) → removed
/// - Null bytes (`\0`) → removed
/// - Control characters → removed
/// - Redundant separators (`//`) → normalized to single
/// - Leading/trailing whitespace → trimmed
///
/// ## What Causes Rejection (even in clean mode)
///
/// - Command injection (`$()`, backticks) → rejected (cannot safely clean)
/// - Shell metacharacters (`;|&`) → rejected (cannot safely clean)
/// - Path becomes empty after sanitization
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::sanitization::sanitize_clean;
///
/// // Traversal removed
/// let safe = sanitize_clean("../../../etc/passwd").expect("test");
/// assert!(!safe.contains(".."));
///
/// // Command injection cannot be cleaned
/// assert!(sanitize_clean("$(whoami)").is_err());
/// ```
pub fn sanitize_clean(path: &str) -> SanitizationResult {
    // Some threats cannot be safely cleaned - reject them
    if detection::is_command_injection_present(path) {
        return Err(Problem::validation(
            "Path contains command injection - cannot safely sanitize",
        ));
    }

    if detection::is_shell_metacharacters_present(path) {
        return Err(Problem::validation(
            "Path contains shell metacharacters - cannot safely sanitize",
        ));
    }

    if detection::is_variable_expansion_present(path) {
        return Err(Problem::validation(
            "Path contains variable expansion - cannot safely sanitize",
        ));
    }

    if detection::is_double_encoding_present(path) {
        return Err(Problem::validation(
            "Path contains double encoding - cannot safely sanitize",
        ));
    }

    // Clean what we can
    let mut result = path.to_string();

    // Remove null bytes
    result = result.replace('\0', "");

    // Remove control characters (except keeping spaces)
    result = result.chars().filter(|c| !c.is_control()).collect();

    // Remove traversal sequences
    result = remove_traversal_sequences(&result);

    // Normalize separators
    result = normalize_separators(&result);

    // Trim whitespace
    result = result.trim().to_string();

    // Validate result is not empty
    if result.is_empty() {
        return Err(Problem::validation("Path became empty after sanitization"));
    }

    Ok(result)
}

/// Sanitize path for display (escape mode)
///
/// Escapes dangerous patterns for safe display in logs or UI.
/// The result is NOT safe for filesystem operations.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::sanitization::sanitize_escape;
///
/// let escaped = sanitize_escape("../$(whoami)").expect("test");
/// // Dangerous patterns are escaped for display
/// assert!(!escaped.contains("..") || escaped.contains("["));
/// ```
pub fn sanitize_escape(path: &str) -> SanitizationResult {
    let mut result = path.to_string();

    // Escape traversal
    result = result.replace("..", "[DOT_DOT]");

    // Escape command injection
    result = result.replace("$(", "[DOLLAR_PAREN]");
    result = result.replace('`', "[BACKTICK]");
    result = result.replace("${", "[DOLLAR_BRACE]");

    // Escape metacharacters
    result = result.replace(';', "[SEMICOLON]");
    result = result.replace('|', "[PIPE]");
    result = result.replace('&', "[AMP]");

    // Escape null bytes
    result = result.replace('\0', "[NULL]");

    // Escape control characters
    result = result
        .chars()
        .map(|c| {
            if c.is_control() && c != ' ' {
                format!("[CTRL_{:02X}]", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect();

    // Escape encoded sequences
    result = result.replace("%2e", "[PCT_2E]");
    result = result.replace("%2E", "[PCT_2E]");
    result = result.replace("%2f", "[PCT_2F]");
    result = result.replace("%2F", "[PCT_2F]");
    result = result.replace("%5c", "[PCT_5C]");
    result = result.replace("%5C", "[PCT_5C]");
    result = result.replace("%25", "[PCT_25]");

    Ok(result)
}

// ============================================================================
// Specific Sanitization Functions
// ============================================================================

/// Strip traversal sequences from path
///
/// Removes `..` components while preserving the rest of the path structure.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::sanitization::strip_traversal;
///
/// assert_eq!(strip_traversal("../etc/passwd"), "etc/passwd");
/// assert_eq!(strip_traversal("path/../secret"), "path/secret");
/// assert_eq!(strip_traversal("a/b/../../c"), "a/b/c");
/// ```
#[must_use]
pub fn strip_traversal(path: &str) -> String {
    remove_traversal_sequences(path)
}

/// Strip null bytes from path
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::sanitization::strip_null_bytes;
///
/// assert_eq!(strip_null_bytes("file\0.txt"), "file.txt");
/// ```
#[must_use]
pub fn strip_null_bytes(path: &str) -> String {
    path.replace('\0', "")
}

/// Strip control characters from path
///
/// Removes all control characters except space.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::sanitization::strip_control_characters;
///
/// assert_eq!(strip_control_characters("file\n.txt"), "file.txt");
/// assert_eq!(strip_control_characters("path\r\n"), "path");
/// ```
#[must_use]
pub fn strip_control_characters(path: &str) -> String {
    path.chars().filter(|c| !c.is_control()).collect()
}

/// Normalize path separators
///
/// Converts all separators to forward slash and removes redundant separators.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::sanitization::normalize_path_separators;
///
/// assert_eq!(normalize_path_separators("path\\to\\file"), "path/to/file");
/// assert_eq!(normalize_path_separators("path//to///file"), "path/to/file");
/// ```
#[must_use]
pub fn normalize_path_separators(path: &str) -> String {
    normalize_separators(path)
}

// ============================================================================
// Helper Functions (Internal)
// ============================================================================

/// Remove `..` path components
fn remove_traversal_sequences(path: &str) -> String {
    // Split by separators, filter out .., rejoin
    let parts: Vec<&str> = path
        .split(['/', '\\'])
        .filter(|part| *part != "..")
        .collect();

    // Preserve leading slash if present
    let prefix = if path.starts_with('/') { "/" } else { "" };

    // Join with forward slash
    let joined = parts.join("/");

    // Clean up any resulting empty segments
    let cleaned = joined
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/");

    format!("{}{}", prefix, cleaned)
}

/// Normalize separators to forward slash and remove redundant
fn normalize_separators(path: &str) -> String {
    // Convert backslashes to forward slashes
    let normalized = path.replace('\\', "/");

    // Remove redundant slashes (but preserve leading slash)
    let mut result = String::with_capacity(normalized.len());
    let mut prev_was_slash = false;
    let mut is_first = true;

    for c in normalized.chars() {
        if c == '/' {
            if !prev_was_slash || is_first {
                result.push(c);
            }
            prev_was_slash = true;
        } else {
            result.push(c);
            prev_was_slash = false;
        }
        is_first = false;
    }

    // Remove trailing slash (unless it's the root)
    if result.len() > 1 && result.ends_with('/') {
        result.pop();
    }

    result
}

// ============================================================================
// Cow-Returning Variants for Efficiency
// ============================================================================

/// Strip traversal sequences (zero-copy when unchanged)
///
/// Returns `Cow::Borrowed` if no changes needed, `Cow::Owned` otherwise.
#[must_use]
pub fn strip_traversal_cow(path: &str) -> Cow<'_, str> {
    if detection::is_traversal_present(path) {
        Cow::Owned(remove_traversal_sequences(path))
    } else {
        Cow::Borrowed(path)
    }
}

/// Strip null bytes (zero-copy when unchanged)
#[must_use]
pub fn strip_null_bytes_cow(path: &str) -> Cow<'_, str> {
    if detection::is_null_bytes_present(path) {
        Cow::Owned(path.replace('\0', ""))
    } else {
        Cow::Borrowed(path)
    }
}

/// Normalize separators (zero-copy when unchanged)
#[must_use]
pub fn normalize_separators_cow(path: &str) -> Cow<'_, str> {
    // Check if normalization needed
    let needs_normalization =
        path.contains('\\') || path.contains("//") || (path.len() > 1 && path.ends_with('/'));

    if needs_normalization {
        Cow::Owned(normalize_separators(path))
    } else {
        Cow::Borrowed(path)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ------------------------------------------------------------------------
    // Strategy-Based Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sanitize_with_clean() {
        let result = sanitize_with("../etc/passwd", PathSanitizationStrategy::Clean);
        assert!(result.is_ok());
        assert!(!result.expect("test").contains(".."));
    }

    #[test]
    fn test_sanitize_with_strict() {
        assert!(sanitize_with("safe/path", PathSanitizationStrategy::Strict).is_ok());
        assert!(sanitize_with("../etc", PathSanitizationStrategy::Strict).is_err());
        assert!(sanitize_with("$(cmd)", PathSanitizationStrategy::Strict).is_err());
    }

    #[test]
    fn test_sanitize_with_escape() {
        let result = sanitize_with("../$(whoami)", PathSanitizationStrategy::Escape).expect("test");
        assert!(result.contains("[DOT_DOT]"));
        assert!(result.contains("[DOLLAR_PAREN]"));
    }

    // ------------------------------------------------------------------------
    // Sanitize Strict Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sanitize_strict_safe() {
        assert_eq!(
            sanitize_strict("safe/path.txt").expect("test"),
            "safe/path.txt"
        );
        assert_eq!(sanitize_strict("./current").expect("test"), "./current");
    }

    #[test]
    fn test_sanitize_strict_rejects_threats() {
        assert!(sanitize_strict("../secret").is_err());
        assert!(sanitize_strict("$(whoami)").is_err());
        assert!(sanitize_strict("file\0.txt").is_err());
        assert!(sanitize_strict("file;ls").is_err());
        assert!(sanitize_strict("").is_err());
    }

    // ------------------------------------------------------------------------
    // Sanitize Clean Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sanitize_clean_removes_traversal() {
        assert_eq!(sanitize_clean("../etc/passwd").expect("test"), "etc/passwd");
        assert_eq!(
            sanitize_clean("path/../secret").expect("test"),
            "path/secret"
        );
        assert_eq!(sanitize_clean("../../file.txt").expect("test"), "file.txt");
    }

    #[test]
    fn test_sanitize_clean_removes_null_bytes() {
        assert_eq!(sanitize_clean("file\0.txt").expect("test"), "file.txt");
    }

    #[test]
    fn test_sanitize_clean_removes_control_chars() {
        assert_eq!(sanitize_clean("file\n.txt").expect("test"), "file.txt");
        assert_eq!(sanitize_clean("path\r\n").expect("test"), "path");
    }

    #[test]
    fn test_sanitize_clean_rejects_injection() {
        assert!(sanitize_clean("$(cmd)").is_err());
        assert!(sanitize_clean("`ls`").is_err());
        assert!(sanitize_clean("file;ls").is_err());
        assert!(sanitize_clean("$HOME").is_err());
    }

    #[test]
    fn test_sanitize_clean_rejects_empty_result() {
        assert!(sanitize_clean("..").is_err());
        assert!(sanitize_clean("../..").is_err());
        assert!(sanitize_clean("\0").is_err());
    }

    // ------------------------------------------------------------------------
    // Sanitize Escape Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sanitize_escape_traversal() {
        let result = sanitize_escape("../secret").expect("test");
        assert!(result.contains("[DOT_DOT]"));
        assert!(!result.contains("..") || result.contains("["));
    }

    #[test]
    fn test_sanitize_escape_injection() {
        let result = sanitize_escape("$(whoami)").expect("test");
        assert!(result.contains("[DOLLAR_PAREN]"));

        let result = sanitize_escape("`ls`").expect("test");
        assert!(result.contains("[BACKTICK]"));

        let result = sanitize_escape("${HOME}").expect("test");
        assert!(result.contains("[DOLLAR_BRACE]"));
    }

    #[test]
    fn test_sanitize_escape_metacharacters() {
        let result = sanitize_escape("file;ls|cat&rm").expect("test");
        assert!(result.contains("[SEMICOLON]"));
        assert!(result.contains("[PIPE]"));
        assert!(result.contains("[AMP]"));
    }

    #[test]
    fn test_sanitize_escape_null_and_control() {
        let result = sanitize_escape("file\0.txt").expect("test");
        assert!(result.contains("[NULL]"));

        let result = sanitize_escape("file\n.txt").expect("test");
        assert!(result.contains("[CTRL_"));
    }

    // ------------------------------------------------------------------------
    // Specific Function Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_strip_traversal() {
        assert_eq!(strip_traversal("../etc"), "etc");
        assert_eq!(strip_traversal("a/../b"), "a/b");
        assert_eq!(strip_traversal("a/b/../../c"), "a/b/c");
        assert_eq!(strip_traversal("safe/path"), "safe/path");
    }

    #[test]
    fn test_strip_null_bytes() {
        assert_eq!(strip_null_bytes("file\0.txt"), "file.txt");
        assert_eq!(strip_null_bytes("safe"), "safe");
        assert_eq!(strip_null_bytes("\0\0\0"), "");
    }

    #[test]
    fn test_strip_control_characters() {
        assert_eq!(strip_control_characters("file\n.txt"), "file.txt");
        assert_eq!(strip_control_characters("path\r\n"), "path");
        assert_eq!(strip_control_characters("file\t.txt"), "file.txt");
    }

    #[test]
    fn test_normalize_path_separators() {
        assert_eq!(normalize_path_separators("path\\to\\file"), "path/to/file");
        assert_eq!(normalize_path_separators("path//to///file"), "path/to/file");
        assert_eq!(normalize_path_separators("/root/path/"), "/root/path");
        assert_eq!(normalize_path_separators("/"), "/");
    }

    // ------------------------------------------------------------------------
    // Cow Variant Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_strip_traversal_cow_borrowed() {
        let result = strip_traversal_cow("safe/path");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn test_strip_traversal_cow_owned() {
        let result = strip_traversal_cow("../secret");
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn test_strip_null_bytes_cow_borrowed() {
        let result = strip_null_bytes_cow("safe");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn test_normalize_separators_cow() {
        // Borrowed when no changes needed
        let result = normalize_separators_cow("path/to/file");
        assert!(matches!(result, Cow::Borrowed(_)));

        // Owned when changes needed
        let result = normalize_separators_cow("path\\to\\file");
        assert!(matches!(result, Cow::Owned(_)));
    }
}
