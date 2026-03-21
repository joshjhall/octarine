//! Security validation for paths
//!
//! Validation functions that enforce security policies on paths.
//! All functions have dual API: lenient (returns `bool`) and strict (returns `Result`).
//!
//! ## Design Philosophy
//!
//! Validation is **strict** and **precise** - no false positives allowed.
//! If validation passes, the path is guaranteed safe for the checked threats.
//!
//! ## Dual API Pattern
//!
//! Each validation has two forms:
//! - `validate_xyz(path) -> bool` - Returns `true` if valid, `false` otherwise
//! - `validate_xyz_strict(path) -> Result<()>` - Returns `Ok(())` or detailed error
//!
//! ## Examples
//!
//! ```ignore
//! use octarine::primitives::paths::security::validation;
//!
//! // Lenient API - just true/false
//! assert!(validation::validate_secure("safe/path.txt"));
//! assert!(!validation::validate_secure("../../../etc/passwd"));
//!
//! // Strict API - with error details
//! assert!(validation::validate_secure_strict("safe/path.txt").is_ok());
//! let err = validation::validate_secure_strict("../etc").expect_err("test");
//! assert!(err.to_string().contains("traversal"));
//! ```

use super::detection;
use crate::primitives::data::paths::types::SecurityThreat;
use crate::primitives::types::Problem;

/// Result type for strict validation functions
pub type ValidationResult = Result<(), Problem>;

// ============================================================================
// Comprehensive Validation
// ============================================================================

/// Validate path is secure (lenient)
///
/// Checks for all security threats. Returns `true` if no threats detected.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::validation::validate_secure;
///
/// assert!(validate_secure("safe/path/file.txt"));
/// assert!(!validate_secure("../../../etc/passwd"));
/// assert!(!validate_secure("file$(whoami).txt"));
/// ```
#[must_use]
pub fn validate_secure(path: &str) -> bool {
    !detection::is_threat_present(path)
}

/// Validate path is secure (strict)
///
/// Checks for all security threats. Returns `Ok(())` if no threats detected,
/// or a detailed error listing all detected threats.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::validation::validate_secure_strict;
///
/// assert!(validate_secure_strict("safe/path.txt").is_ok());
///
/// let err = validate_secure_strict("../$(cmd)").expect_err("test");
/// let msg = err.to_string();
/// assert!(msg.contains("traversal") || msg.contains("injection"));
/// ```
pub fn validate_secure_strict(path: &str) -> ValidationResult {
    let threats = detection::detect_threats(path);

    if threats.is_empty() {
        return Ok(());
    }

    // Build detailed error message
    let threat_descriptions: Vec<&str> = threats.iter().map(SecurityThreat::description).collect();

    Err(Problem::validation(format!(
        "Path contains security threats: {}",
        threat_descriptions.join("; ")
    )))
}

// ============================================================================
// Traversal Validation (CWE-22)
// ============================================================================

/// Validate path has no traversal (lenient)
///
/// Checks for `..` path components. Returns `true` if no traversal found.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::validation::validate_no_traversal;
///
/// assert!(validate_no_traversal("safe/path.txt"));
/// assert!(!validate_no_traversal("../secret"));
/// assert!(!validate_no_traversal("path/../sensitive"));
/// ```
#[must_use]
pub fn validate_no_traversal(path: &str) -> bool {
    !detection::is_traversal_present(path)
}

/// Validate path has no traversal (strict)
///
/// Checks for `..` path components. Returns `Ok(())` if no traversal found.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::validation::validate_no_traversal_strict;
///
/// assert!(validate_no_traversal_strict("safe/path.txt").is_ok());
///
/// let err = validate_no_traversal_strict("../etc").expect_err("test");
/// assert!(err.to_string().contains("traversal"));
/// ```
pub fn validate_no_traversal_strict(path: &str) -> ValidationResult {
    if detection::is_traversal_present(path) {
        return Err(Problem::validation(
            "Path contains directory traversal sequences (..)",
        ));
    }
    Ok(())
}

/// Validate path has no encoded traversal (lenient)
///
/// Checks for URL-encoded traversal sequences (`%2e`, `%2f`, `%5c`).
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::validation::validate_no_encoded_traversal;
///
/// assert!(validate_no_encoded_traversal("safe/path.txt"));
/// assert!(!validate_no_encoded_traversal("%2e%2e/secret"));
/// ```
#[must_use]
pub fn validate_no_encoded_traversal(path: &str) -> bool {
    !detection::is_encoded_traversal_present(path)
}

/// Validate path has no encoded traversal (strict)
///
/// Checks for URL-encoded traversal sequences (`%2e`, `%2f`, `%5c`).
pub fn validate_no_encoded_traversal_strict(path: &str) -> ValidationResult {
    if detection::is_encoded_traversal_present(path) {
        return Err(Problem::validation(
            "Path contains encoded traversal sequences (%2e, %2f, or %5c)",
        ));
    }
    Ok(())
}

/// Validate path has no traversal of any kind (lenient)
///
/// Comprehensive check: basic traversal, encoded traversal, and absolute paths.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::validation::validate_no_any_traversal;
///
/// assert!(validate_no_any_traversal("safe/path.txt"));
/// assert!(!validate_no_any_traversal("../secret"));
/// assert!(!validate_no_any_traversal("%2e%2e/secret"));
/// assert!(!validate_no_any_traversal("/etc/passwd"));
/// ```
#[must_use]
pub fn validate_no_any_traversal(path: &str) -> bool {
    !detection::is_any_traversal_present(path)
}

/// Validate path has no traversal of any kind (strict)
///
/// Comprehensive check with detailed error messages.
pub fn validate_no_any_traversal_strict(path: &str) -> ValidationResult {
    if detection::is_traversal_present(path) {
        return Err(Problem::validation(
            "Path contains directory traversal sequences (..)",
        ));
    }

    if detection::is_encoded_traversal_present(path) {
        return Err(Problem::validation(
            "Path contains encoded traversal sequences",
        ));
    }

    if detection::is_absolute_path_present(path) {
        return Err(Problem::validation(
            "Absolute paths are not allowed in this context",
        ));
    }

    Ok(())
}

// ============================================================================
// Injection Validation (CWE-78)
// ============================================================================

/// Validate path has no command injection (lenient)
///
/// Checks for `$()`, backticks, and `${}` patterns.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::validation::validate_no_injection;
///
/// assert!(validate_no_injection("safe/path.txt"));
/// assert!(!validate_no_injection("$(whoami)"));
/// assert!(!validate_no_injection("`ls`"));
/// ```
#[must_use]
pub fn validate_no_injection(path: &str) -> bool {
    !detection::is_command_injection_present(path)
        && !detection::is_variable_expansion_present(path)
        && !detection::is_shell_metacharacters_present(path)
}

/// Validate path has no command injection (strict)
///
/// Checks for all injection patterns with detailed error messages.
pub fn validate_no_injection_strict(path: &str) -> ValidationResult {
    if detection::is_command_injection_present(path) {
        return Err(Problem::validation(
            "Path contains command injection patterns ($(), ``, or ${})",
        ));
    }

    if detection::is_variable_expansion_present(path) {
        return Err(Problem::validation(
            "Path contains shell variable expansion ($VAR or ${VAR})",
        ));
    }

    if detection::is_shell_metacharacters_present(path) {
        return Err(Problem::validation(
            "Path contains shell metacharacters (;, |, or &)",
        ));
    }

    Ok(())
}

/// Validate path has no command substitution (lenient)
///
/// Checks specifically for `$()` and backtick patterns.
#[must_use]
pub fn validate_no_command_substitution(path: &str) -> bool {
    !detection::is_command_injection_present(path)
}

/// Validate path has no command substitution (strict)
pub fn validate_no_command_substitution_strict(path: &str) -> ValidationResult {
    if detection::is_command_injection_present(path) {
        return Err(Problem::validation(
            "Path contains command substitution ($() or backticks)",
        ));
    }
    Ok(())
}

/// Validate path has no shell metacharacters (lenient)
#[must_use]
pub fn validate_no_shell_metacharacters(path: &str) -> bool {
    !detection::is_shell_metacharacters_present(path)
}

/// Validate path has no shell metacharacters (strict)
pub fn validate_no_shell_metacharacters_strict(path: &str) -> ValidationResult {
    if detection::is_shell_metacharacters_present(path) {
        return Err(Problem::validation(
            "Path contains shell metacharacters (;, |, or &)",
        ));
    }
    Ok(())
}

// ============================================================================
// Character Validation (CWE-158, CWE-707)
// ============================================================================

/// Validate path has no null bytes (lenient)
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::validation::validate_no_null_bytes;
///
/// assert!(validate_no_null_bytes("safe/path.txt"));
/// assert!(!validate_no_null_bytes("file\0.txt"));
/// ```
#[must_use]
pub fn validate_no_null_bytes(path: &str) -> bool {
    !detection::is_null_bytes_present(path)
}

/// Validate path has no null bytes (strict)
pub fn validate_no_null_bytes_strict(path: &str) -> ValidationResult {
    if detection::is_null_bytes_present(path) {
        return Err(Problem::validation(
            "Path contains null bytes - potential truncation attack (CWE-158)",
        ));
    }
    Ok(())
}

/// Validate path has no control characters (lenient)
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::validation::validate_no_control_characters;
///
/// assert!(validate_no_control_characters("safe/path.txt"));
/// assert!(!validate_no_control_characters("file\n.txt"));
/// ```
#[must_use]
pub fn validate_no_control_characters(path: &str) -> bool {
    !detection::is_control_characters_present(path)
}

/// Validate path has no control characters (strict)
pub fn validate_no_control_characters_strict(path: &str) -> ValidationResult {
    if detection::is_control_characters_present(path) {
        return Err(Problem::validation(
            "Path contains control characters (CWE-707)",
        ));
    }
    Ok(())
}

/// Validate path has no dangerous characters (lenient)
///
/// Combines null byte and control character checks.
#[must_use]
pub fn validate_no_dangerous_characters(path: &str) -> bool {
    !detection::is_dangerous_characters_present(path)
}

/// Validate path has no dangerous characters (strict)
pub fn validate_no_dangerous_characters_strict(path: &str) -> ValidationResult {
    validate_no_null_bytes_strict(path)?;
    validate_no_control_characters_strict(path)?;
    Ok(())
}

// ============================================================================
// Encoding Validation (CWE-175)
// ============================================================================

/// Validate path has no double encoding (lenient)
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::validation::validate_no_double_encoding;
///
/// assert!(validate_no_double_encoding("safe/path.txt"));
/// assert!(validate_no_double_encoding("%2e%2e")); // Single encoding OK
/// assert!(!validate_no_double_encoding("%252e%252e")); // Double encoding NOT OK
/// ```
#[must_use]
pub fn validate_no_double_encoding(path: &str) -> bool {
    !detection::is_double_encoding_present(path)
}

/// Validate path has no double encoding (strict)
pub fn validate_no_double_encoding_strict(path: &str) -> ValidationResult {
    if detection::is_double_encoding_present(path) {
        return Err(Problem::validation(
            "Path contains double/multiple encoding - potential bypass attack (CWE-175)",
        ));
    }
    Ok(())
}

// ============================================================================
// Path Type Validation
// ============================================================================

/// Validate path is relative (not absolute) (lenient)
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::validation::validate_relative;
///
/// assert!(validate_relative("safe/path.txt"));
/// assert!(validate_relative("./current"));
/// assert!(!validate_relative("/etc/passwd"));
/// assert!(!validate_relative("C:\\Windows"));
/// ```
#[must_use]
pub fn validate_relative(path: &str) -> bool {
    !detection::is_absolute_path_present(path)
}

/// Validate path is relative (strict)
pub fn validate_relative_strict(path: &str) -> ValidationResult {
    if detection::is_absolute_path_present(path) {
        return Err(Problem::validation("Path must be relative, not absolute"));
    }
    Ok(())
}

/// Validate path is not empty (lenient)
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::security::validation::validate_not_empty;
///
/// assert!(validate_not_empty("path"));
/// assert!(!validate_not_empty(""));
/// assert!(!validate_not_empty("   "));
/// ```
#[must_use]
pub fn validate_not_empty(path: &str) -> bool {
    !path.is_empty() && !path.trim().is_empty()
}

/// Validate path is not empty (strict)
pub fn validate_not_empty_strict(path: &str) -> ValidationResult {
    if path.is_empty() {
        return Err(Problem::validation("Path cannot be empty"));
    }

    if path.trim().is_empty() {
        return Err(Problem::validation("Path cannot be whitespace-only"));
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ------------------------------------------------------------------------
    // Comprehensive Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validate_secure_safe_paths() {
        assert!(validate_secure("safe/path.txt"));
        assert!(validate_secure("file.txt"));
        assert!(validate_secure("path/to/file.txt"));
        assert!(validate_secure("./current"));
    }

    #[test]
    fn test_validate_secure_unsafe_paths() {
        assert!(!validate_secure("../secret"));
        assert!(!validate_secure("$(whoami)"));
        assert!(!validate_secure("file\0.txt"));
        assert!(!validate_secure("file;ls"));
        assert!(!validate_secure("%252e%252e"));
    }

    #[test]
    fn test_validate_secure_strict_ok() {
        assert!(validate_secure_strict("safe/path.txt").is_ok());
        assert!(validate_secure_strict("file.txt").is_ok());
    }

    #[test]
    fn test_validate_secure_strict_errors() {
        let err = validate_secure_strict("../secret").expect_err("test");
        assert!(err.to_string().contains("security"));

        let err = validate_secure_strict("$(cmd)").expect_err("test");
        assert!(err.to_string().contains("security"));
    }

    // ------------------------------------------------------------------------
    // Traversal Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validate_no_traversal() {
        assert!(validate_no_traversal("safe/path"));
        assert!(!validate_no_traversal("../secret"));
        assert!(!validate_no_traversal("a/../b"));
    }

    #[test]
    fn test_validate_no_traversal_strict() {
        assert!(validate_no_traversal_strict("safe").is_ok());
        let err = validate_no_traversal_strict("..").expect_err("test");
        assert!(err.to_string().contains("traversal"));
    }

    #[test]
    fn test_validate_no_encoded_traversal() {
        assert!(validate_no_encoded_traversal("safe"));
        assert!(!validate_no_encoded_traversal("%2e%2e"));
        assert!(!validate_no_encoded_traversal("path%2fsecret"));
    }

    #[test]
    fn test_validate_no_any_traversal() {
        assert!(validate_no_any_traversal("safe/path"));
        assert!(!validate_no_any_traversal("../"));
        assert!(!validate_no_any_traversal("%2e%2e"));
        assert!(!validate_no_any_traversal("/absolute"));
    }

    // ------------------------------------------------------------------------
    // Injection Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validate_no_injection() {
        assert!(validate_no_injection("safe/path"));
        assert!(!validate_no_injection("$(cmd)"));
        assert!(!validate_no_injection("`ls`"));
        assert!(!validate_no_injection("$HOME"));
        assert!(!validate_no_injection("file;ls"));
    }

    #[test]
    fn test_validate_no_injection_strict() {
        assert!(validate_no_injection_strict("safe").is_ok());

        let err = validate_no_injection_strict("$(cmd)").expect_err("test");
        assert!(err.to_string().contains("injection"));

        let err = validate_no_injection_strict("$VAR").expect_err("test");
        assert!(err.to_string().contains("variable"));

        let err = validate_no_injection_strict(";ls").expect_err("test");
        assert!(err.to_string().contains("metacharacter"));
    }

    // ------------------------------------------------------------------------
    // Character Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validate_no_null_bytes() {
        assert!(validate_no_null_bytes("safe"));
        assert!(!validate_no_null_bytes("file\0.txt"));
    }

    #[test]
    fn test_validate_no_control_characters() {
        assert!(validate_no_control_characters("safe"));
        assert!(!validate_no_control_characters("file\n.txt"));
        assert!(!validate_no_control_characters("path\r\n"));
    }

    #[test]
    fn test_validate_no_dangerous_characters() {
        assert!(validate_no_dangerous_characters("safe"));
        assert!(!validate_no_dangerous_characters("\0"));
        assert!(!validate_no_dangerous_characters("\n"));
    }

    // ------------------------------------------------------------------------
    // Encoding Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validate_no_double_encoding() {
        assert!(validate_no_double_encoding("safe"));
        assert!(validate_no_double_encoding("%2e%2e")); // Single encoding OK
        assert!(!validate_no_double_encoding("%252e")); // Double encoding NOT OK
    }

    // ------------------------------------------------------------------------
    // Path Type Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validate_relative() {
        assert!(validate_relative("relative/path"));
        assert!(validate_relative("./current"));
        assert!(!validate_relative("/absolute"));
        assert!(!validate_relative("C:\\Windows"));
    }

    #[test]
    fn test_validate_not_empty() {
        assert!(validate_not_empty("path"));
        assert!(validate_not_empty("/"));
        assert!(!validate_not_empty(""));
        assert!(!validate_not_empty("   "));
        assert!(!validate_not_empty("\t\n"));
    }

    #[test]
    fn test_validate_not_empty_strict() {
        assert!(validate_not_empty_strict("path").is_ok());

        let err = validate_not_empty_strict("").expect_err("test");
        assert!(err.to_string().contains("empty"));

        let err = validate_not_empty_strict("  ").expect_err("test");
        assert!(err.to_string().contains("whitespace"));
    }
}
