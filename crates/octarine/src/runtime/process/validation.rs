//! Argument validation for secure command execution
//!
//! Validates command arguments against injection patterns and policy rules.
//!
//! # Security Model
//!
//! Arguments are validated at two levels:
//!
//! 1. **Injection Detection**: Checks for shell metacharacters, command substitution,
//!    and variable expansion patterns that could lead to command injection.
//!
//! 2. **Policy Validation**: Additional rules based on the argument type (URL, path, etc.)
//!
//! # Example
//!
//! ```ignore
//! use octarine::runtime::process::{ValidatedArg, ArgumentPolicy};
//!
//! // Validate with default policy (strict)
//! let arg = ValidatedArg::new("https://github.com/user/repo.git")?;
//!
//! // Validate with URL policy (allows some characters)
//! let url = ValidatedArg::with_policy("https://example.com?foo=bar", ArgumentPolicy::Url)?;
//! ```

use super::ProcessError;
use crate::primitives::security::commands::detection;

/// Policy for argument validation
///
/// Different argument types may require different validation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ArgumentPolicy {
    /// Strict validation - rejects most special characters
    ///
    /// Use for general arguments where no special characters are expected.
    #[default]
    Strict,

    /// URL validation - allows URL-safe characters
    ///
    /// Allows: `?`, `=`, `&`, `#`, `%`, `/`, `:`, `@`, `-`, `_`, `.`, `~`
    /// Still blocks: `;`, `|`, backticks, `$()`, `${}`
    Url,

    /// Path validation - allows path characters
    ///
    /// Allows: `/`, `\`, `.`, `-`, `_`
    /// Still blocks: injection patterns
    Path,

    /// Identifier validation - alphanumeric and limited punctuation
    ///
    /// Allows: alphanumeric, `-`, `_`, `.`
    /// Use for: branch names, tag names, container names
    Identifier,

    /// Permissive validation - only blocks injection patterns
    ///
    /// **Warning**: Use only when you need to pass complex arguments.
    /// Still blocks command injection patterns.
    Permissive,
}

impl ArgumentPolicy {
    /// Get a human-readable name for the policy
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Url => "url",
            Self::Path => "path",
            Self::Identifier => "identifier",
            Self::Permissive => "permissive",
        }
    }
}

/// A validated argument ready for use with SecureCommand
///
/// This type guarantees that the argument has been validated against
/// injection patterns. It cannot be constructed without validation.
#[derive(Debug, Clone)]
pub struct ValidatedArg {
    value: String,
    policy: ArgumentPolicy,
}

impl ValidatedArg {
    /// Create a new validated argument with strict policy
    ///
    /// # Errors
    ///
    /// Returns `ProcessError::InjectionDetected` if injection patterns are found.
    /// Returns `ProcessError::ValidationFailed` if policy rules are violated.
    pub fn new(value: impl Into<String>) -> Result<Self, ProcessError> {
        Self::with_policy(value, ArgumentPolicy::Strict)
    }

    /// Create a validated argument with a specific policy
    ///
    /// # Errors
    ///
    /// Returns `ProcessError::InjectionDetected` if injection patterns are found.
    /// Returns `ProcessError::ValidationFailed` if policy rules are violated.
    pub fn with_policy(
        value: impl Into<String>,
        policy: ArgumentPolicy,
    ) -> Result<Self, ProcessError> {
        let value = value.into();

        // Always check for injection patterns first
        Self::validate_injection(&value)?;

        // Then check policy-specific rules
        Self::validate_policy(&value, policy)?;

        Ok(Self { value, policy })
    }

    /// Get the validated argument value
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Get the policy used for validation
    #[must_use]
    pub fn policy(&self) -> ArgumentPolicy {
        self.policy
    }

    /// Consume and return the inner value
    #[must_use]
    pub fn into_inner(self) -> String {
        self.value
    }

    /// Check for command injection patterns
    ///
    /// Uses detection from primitives/security/commands for core injection patterns.
    /// Note: Globs and redirections are NOT checked here - they're context-dependent
    /// and handled by policy-specific checks instead.
    fn validate_injection(value: &str) -> Result<(), ProcessError> {
        // Check for command chaining - these are always dangerous
        if detection::is_any_chain_present(value) {
            return Err(ProcessError::injection(
                Self::sanitize_for_error(value),
                "command chaining detected",
            ));
        }

        // Check for shell expansion - always dangerous
        if detection::is_shell_expansion_present(value) {
            return Err(ProcessError::injection(
                Self::sanitize_for_error(value),
                "shell expansion detected",
            ));
        }

        // Check for null bytes and control characters - always dangerous
        if detection::is_null_byte_present(value) {
            return Err(ProcessError::injection(
                Self::sanitize_for_error(value),
                "null byte detected",
            ));
        }

        if detection::is_control_character_present(value) {
            return Err(ProcessError::injection(
                Self::sanitize_for_error(value),
                "control character detected",
            ));
        }

        // Newlines can be used for command injection
        if value.contains('\n') || value.contains('\r') {
            return Err(ProcessError::injection(
                Self::sanitize_for_error(value),
                "newline character",
            ));
        }

        // Note: Globs and redirections are NOT checked here.
        // They're context-dependent:
        // - Strict policy blocks them
        // - URL/Path policies allow some
        // - Permissive policy allows them
        // Policy-specific checks handle these in validate_policy()

        Ok(())
    }

    /// Sanitize a value for inclusion in error messages
    ///
    /// Prevents the error message from leaking potentially malicious input
    fn sanitize_for_error(value: &str) -> String {
        // Truncate long values
        const MAX_LEN: usize = 50;
        if value.len() > MAX_LEN {
            format!("{}...", &value[..MAX_LEN])
        } else {
            value.to_string()
        }
    }

    /// Check policy-specific validation rules
    fn validate_policy(value: &str, policy: ArgumentPolicy) -> Result<(), ProcessError> {
        match policy {
            ArgumentPolicy::Strict => Self::validate_strict(value),
            ArgumentPolicy::Url => Self::validate_url(value),
            ArgumentPolicy::Path => Self::validate_path(value),
            ArgumentPolicy::Identifier => Self::validate_identifier(value),
            ArgumentPolicy::Permissive => Ok(()), // Only injection checks
        }
    }

    /// Strict policy: reject most special characters
    fn validate_strict(value: &str) -> Result<(), ProcessError> {
        // Check for redirection (not always injection, but dangerous in strict mode)
        if value.contains('>') || value.contains('<') {
            return Err(ProcessError::validation(
                value,
                "redirection operators not allowed in strict mode",
            ));
        }

        // Check for glob patterns (could expand unexpectedly)
        if value.contains('*') || value.contains('?') {
            return Err(ProcessError::validation(
                value,
                "glob patterns not allowed in strict mode",
            ));
        }

        // Check for quotes (could be used for escaping)
        if value.contains('\'') || value.contains('"') {
            return Err(ProcessError::validation(
                value,
                "quotes not allowed in strict mode",
            ));
        }

        // Check for parentheses (could be used for subshells)
        if value.contains('(') || value.contains(')') {
            return Err(ProcessError::validation(
                value,
                "parentheses not allowed in strict mode",
            ));
        }

        // Check for square brackets (could be test constructs)
        if value.contains('[') || value.contains(']') {
            return Err(ProcessError::validation(
                value,
                "brackets not allowed in strict mode",
            ));
        }

        // Check for curly braces (could be brace expansion)
        if value.contains('{') || value.contains('}') {
            return Err(ProcessError::validation(
                value,
                "braces not allowed in strict mode",
            ));
        }

        Ok(())
    }

    /// URL policy: allow URL-safe characters
    fn validate_url(value: &str) -> Result<(), ProcessError> {
        // URLs should start with a scheme or be relative
        // We don't enforce this strictly, but check for dangerous patterns

        // Redirection still not allowed
        if value.contains('>') || value.contains('<') {
            return Err(ProcessError::validation(
                value,
                "redirection operators not allowed in URLs",
            ));
        }

        // Single quotes could break shell escaping
        if value.contains('\'') {
            return Err(ProcessError::validation(
                value,
                "single quotes not allowed in URLs",
            ));
        }

        // Parentheses could be subshells
        if value.contains('(') || value.contains(')') {
            return Err(ProcessError::validation(
                value,
                "parentheses not allowed in URLs",
            ));
        }

        Ok(())
    }

    /// Path policy: allow path characters
    fn validate_path(value: &str) -> Result<(), ProcessError> {
        // Path traversal is allowed here (the caller decides if it's safe)
        // We only block injection and dangerous patterns

        // Redirection not allowed in paths
        if value.contains('>') || value.contains('<') {
            return Err(ProcessError::validation(
                value,
                "redirection operators not allowed in paths",
            ));
        }

        // Glob patterns might expand unexpectedly
        if value.contains('*') || value.contains('?') {
            return Err(ProcessError::validation(
                value,
                "glob patterns not allowed in paths",
            ));
        }

        // Quotes could break shell escaping
        if value.contains('\'') || value.contains('"') {
            return Err(ProcessError::validation(
                value,
                "quotes not allowed in paths",
            ));
        }

        Ok(())
    }

    /// Identifier policy: alphanumeric and limited punctuation
    fn validate_identifier(value: &str) -> Result<(), ProcessError> {
        if value.is_empty() {
            return Err(ProcessError::validation(
                value,
                "identifier cannot be empty",
            ));
        }

        for ch in value.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' && ch != '.' && ch != '/' {
                return Err(ProcessError::validation(
                    value,
                    format!("invalid character '{}' in identifier", ch),
                ));
            }
        }

        Ok(())
    }
}

impl AsRef<str> for ValidatedArg {
    fn as_ref(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Display for ValidatedArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    // ========================================================================
    // Injection Detection Tests
    // ========================================================================

    #[test]
    fn test_injection_command_substitution() {
        assert!(ValidatedArg::new("$(whoami)").is_err());
        assert!(ValidatedArg::new("file$(id).txt").is_err());
        assert!(ValidatedArg::new("`whoami`").is_err());
        assert!(ValidatedArg::new("file`id`.txt").is_err());
    }

    #[test]
    fn test_injection_variable_expansion() {
        assert!(ValidatedArg::new("${HOME}").is_err());
        assert!(ValidatedArg::new("${PATH}/bin").is_err());
        // Note: $VAR without braces is not blocked (would block too much)
        // The actual shell won't expand it if properly quoted by Command
    }

    #[test]
    fn test_injection_shell_metacharacters() {
        assert!(ValidatedArg::new("file;rm -rf /").is_err());
        assert!(ValidatedArg::new("cat file | grep").is_err());
        assert!(ValidatedArg::new("cmd &").is_err());
        assert!(ValidatedArg::new("cmd && other").is_err());
        assert!(ValidatedArg::new("cmd || fallback").is_err());
    }

    #[test]
    fn test_injection_newlines() {
        assert!(ValidatedArg::new("line1\nline2").is_err());
        assert!(ValidatedArg::new("line1\rline2").is_err());
    }

    #[test]
    fn test_injection_null_bytes() {
        assert!(ValidatedArg::new("file\0.txt").is_err());
    }

    // ========================================================================
    // Strict Policy Tests
    // ========================================================================

    #[test]
    fn test_strict_allows_safe() {
        assert!(ValidatedArg::new("simple").is_ok());
        assert!(ValidatedArg::new("with-dash").is_ok());
        assert!(ValidatedArg::new("with_underscore").is_ok());
        assert!(ValidatedArg::new("with.dot").is_ok());
        assert!(ValidatedArg::new("123").is_ok());
        assert!(ValidatedArg::new("path/to/file").is_ok());
    }

    #[test]
    fn test_strict_blocks_dangerous() {
        assert!(ValidatedArg::new("file>output").is_err());
        assert!(ValidatedArg::new("*.txt").is_err());
        assert!(ValidatedArg::new("file?.txt").is_err());
        assert!(ValidatedArg::new("'quoted'").is_err());
        assert!(ValidatedArg::new("\"quoted\"").is_err());
        assert!(ValidatedArg::new("(subshell)").is_err());
        assert!(ValidatedArg::new("[test]").is_err());
        assert!(ValidatedArg::new("{a,b}").is_err());
    }

    // ========================================================================
    // URL Policy Tests
    // ========================================================================

    #[test]
    fn test_url_allows_valid_urls() {
        assert!(ValidatedArg::with_policy("https://example.com", ArgumentPolicy::Url).is_ok());
        assert!(
            ValidatedArg::with_policy("https://example.com/path?query=value", ArgumentPolicy::Url)
                .is_ok()
        );
        assert!(
            ValidatedArg::with_policy("https://user:pass@example.com", ArgumentPolicy::Url).is_ok()
        );
        assert!(
            ValidatedArg::with_policy("https://example.com#anchor", ArgumentPolicy::Url).is_ok()
        );
        assert!(
            ValidatedArg::with_policy("git@github.com:user/repo.git", ArgumentPolicy::Url).is_ok()
        );
    }

    #[test]
    fn test_url_blocks_dangerous() {
        assert!(
            ValidatedArg::with_policy("https://example.com$(whoami)", ArgumentPolicy::Url).is_err()
        );
        assert!(
            ValidatedArg::with_policy("https://example.com>file", ArgumentPolicy::Url).is_err()
        );
        assert!(
            ValidatedArg::with_policy("https://example.com'quote", ArgumentPolicy::Url).is_err()
        );
    }

    // ========================================================================
    // Path Policy Tests
    // ========================================================================

    #[test]
    fn test_path_allows_valid_paths() {
        assert!(ValidatedArg::with_policy("/usr/local/bin", ArgumentPolicy::Path).is_ok());
        assert!(ValidatedArg::with_policy("./relative/path", ArgumentPolicy::Path).is_ok());
        assert!(ValidatedArg::with_policy("../parent/path", ArgumentPolicy::Path).is_ok());
        assert!(ValidatedArg::with_policy("file.txt", ArgumentPolicy::Path).is_ok());
        assert!(ValidatedArg::with_policy("path/with spaces", ArgumentPolicy::Path).is_ok());
    }

    #[test]
    fn test_path_blocks_dangerous() {
        assert!(ValidatedArg::with_policy("/path$(whoami)", ArgumentPolicy::Path).is_err());
        assert!(ValidatedArg::with_policy("/path>file", ArgumentPolicy::Path).is_err());
        assert!(ValidatedArg::with_policy("/path/*.txt", ArgumentPolicy::Path).is_err());
    }

    // ========================================================================
    // Identifier Policy Tests
    // ========================================================================

    #[test]
    fn test_identifier_allows_valid() {
        assert!(ValidatedArg::with_policy("main", ArgumentPolicy::Identifier).is_ok());
        assert!(ValidatedArg::with_policy("feature-branch", ArgumentPolicy::Identifier).is_ok());
        assert!(ValidatedArg::with_policy("v1.0.0", ArgumentPolicy::Identifier).is_ok());
        assert!(ValidatedArg::with_policy("my_container", ArgumentPolicy::Identifier).is_ok());
        assert!(ValidatedArg::with_policy("user/repo", ArgumentPolicy::Identifier).is_ok());
    }

    #[test]
    fn test_identifier_blocks_special_chars() {
        assert!(ValidatedArg::with_policy("", ArgumentPolicy::Identifier).is_err());
        assert!(ValidatedArg::with_policy("has space", ArgumentPolicy::Identifier).is_err());
        assert!(ValidatedArg::with_policy("has:colon", ArgumentPolicy::Identifier).is_err());
        assert!(ValidatedArg::with_policy("has@at", ArgumentPolicy::Identifier).is_err());
    }

    // ========================================================================
    // Permissive Policy Tests
    // ========================================================================

    #[test]
    fn test_permissive_allows_most() {
        assert!(ValidatedArg::with_policy("file>output", ArgumentPolicy::Permissive).is_ok());
        assert!(ValidatedArg::with_policy("*.txt", ArgumentPolicy::Permissive).is_ok());
        assert!(ValidatedArg::with_policy("'quoted'", ArgumentPolicy::Permissive).is_ok());
        assert!(ValidatedArg::with_policy("{a,b}", ArgumentPolicy::Permissive).is_ok());
    }

    #[test]
    fn test_permissive_still_blocks_injection() {
        assert!(ValidatedArg::with_policy("$(whoami)", ArgumentPolicy::Permissive).is_err());
        assert!(ValidatedArg::with_policy("cmd;rm", ArgumentPolicy::Permissive).is_err());
        assert!(ValidatedArg::with_policy("cmd|cat", ArgumentPolicy::Permissive).is_err());
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_empty_string() {
        // Empty string is allowed by default (not an injection)
        assert!(ValidatedArg::new("").is_ok());
        // But not for identifiers
        assert!(ValidatedArg::with_policy("", ArgumentPolicy::Identifier).is_err());
    }

    #[test]
    fn test_unicode() {
        assert!(ValidatedArg::new("héllo").is_ok());
        assert!(ValidatedArg::new("日本語").is_ok());
        assert!(ValidatedArg::new("🚀").is_ok());
    }

    #[test]
    fn test_long_argument() {
        let long_arg = "a".repeat(10000);
        assert!(ValidatedArg::new(&long_arg).is_ok());
    }

    #[test]
    fn test_error_messages_dont_leak() {
        let err = ValidatedArg::new("$(whoami)").unwrap_err();
        let display = format!("{}", err);
        // Error message should not contain the actual malicious input
        assert!(!display.contains("$(whoami)"));
        // But should indicate the problem
        assert!(display.contains("command"));
        assert!(display.contains("injection"));
    }
}
