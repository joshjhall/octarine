//! Builder API for command security operations
//!
//! Provides a fluent builder interface for security detection, validation,
//! and sanitization operations on command arguments.
//!
//! ## Example
//!
//! ```ignore
//! use octarine::primitives::security::commands::CommandSecurityBuilder;
//!
//! let security = CommandSecurityBuilder::new();
//!
//! // Detection
//! assert!(security.is_dangerous("$(whoami)"));
//! let threats = security.detect_threats("; rm -rf /");
//! assert!(!threats.is_empty());
//!
//! // Validation
//! assert!(security.validate_safe("safe-arg").is_ok());
//! assert!(security.validate_safe("$(whoami)").is_err());
//!
//! // Sanitization (escaping)
//! let escaped = security.escape_shell_arg("user's input").expect("valid");
//! ```

use super::types::{AllowList, CommandThreat};
use super::{detection, sanitization, validation};
use crate::primitives::types::Problem;

/// Builder for command security operations
///
/// Provides a unified API for all security-related command operations:
/// detection, validation, and sanitization (escaping).
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::security::commands::CommandSecurityBuilder;
///
/// let security = CommandSecurityBuilder::new();
///
/// // Quick danger check
/// if security.is_dangerous(user_input) {
///     // Handle malicious input
/// }
///
/// // Or get detailed threats
/// let threats = security.detect_threats(user_input);
/// for threat in &threats {
///     println!("Detected: {}", threat);
/// }
/// # let user_input = "safe";
/// ```
#[derive(Debug, Clone, Default)]
pub struct CommandSecurityBuilder;

impl CommandSecurityBuilder {
    /// Create a new command security builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // ========================================================================
    // Detection Methods
    // ========================================================================

    /// Detect all security threats in an argument
    ///
    /// Returns a vector of all detected threats.
    #[must_use]
    pub fn detect_threats(&self, arg: &str) -> Vec<CommandThreat> {
        detection::detect_threats(arg)
    }

    /// Check if argument contains any dangerous pattern
    ///
    /// Quick boolean check for any threat.
    #[must_use]
    pub fn is_dangerous(&self, arg: &str) -> bool {
        detection::is_dangerous_arg(arg)
    }

    /// Check for command chaining patterns (`;`, `|`, `&`, `&&`, `||`)
    #[must_use]
    pub fn is_any_chain_present(&self, arg: &str) -> bool {
        detection::is_any_chain_present(arg)
    }

    /// Check for semicolon command chaining (`;`)
    #[must_use]
    pub fn is_command_chain_present(&self, arg: &str) -> bool {
        detection::is_command_chain_present(arg)
    }

    /// Check for pipe chaining (`|`)
    #[must_use]
    pub fn is_pipe_chain_present(&self, arg: &str) -> bool {
        detection::is_pipe_chain_present(arg)
    }

    /// Check for background execution (`&`)
    #[must_use]
    pub fn is_background_execution_present(&self, arg: &str) -> bool {
        detection::is_background_execution_present(arg)
    }

    /// Check for conditional chaining (`&&` or `||`)
    #[must_use]
    pub fn is_conditional_chain_present(&self, arg: &str) -> bool {
        detection::is_conditional_chain_present(arg)
    }

    /// Check for any shell expansion pattern
    #[must_use]
    pub fn is_shell_expansion_present(&self, arg: &str) -> bool {
        detection::is_shell_expansion_present(arg)
    }

    /// Check for command substitution (`$()` or backticks)
    #[must_use]
    pub fn is_command_substitution_present(&self, arg: &str) -> bool {
        detection::is_command_substitution_present(arg)
    }

    /// Check for variable expansion (`$VAR` or `${VAR}`)
    #[must_use]
    pub fn is_variable_expansion_present(&self, arg: &str) -> bool {
        detection::is_variable_expansion_present(arg)
    }

    /// Check for indirect variable expansion (`${!VAR}`)
    #[must_use]
    pub fn is_indirect_expansion_present(&self, arg: &str) -> bool {
        detection::is_indirect_expansion_present(arg)
    }

    /// Check for arithmetic expansion (`$((expr))`)
    #[must_use]
    pub fn is_arithmetic_expansion_present(&self, arg: &str) -> bool {
        detection::is_arithmetic_expansion_present(arg)
    }

    /// Check for any redirection pattern (`>`, `<`)
    #[must_use]
    pub fn is_redirection_present(&self, arg: &str) -> bool {
        detection::is_redirection_present(arg)
    }

    /// Check for output redirection (`>` or `>>`)
    #[must_use]
    pub fn is_output_redirect_present(&self, arg: &str) -> bool {
        detection::is_output_redirect_present(arg)
    }

    /// Check for input redirection (`<`)
    #[must_use]
    pub fn is_input_redirect_present(&self, arg: &str) -> bool {
        detection::is_input_redirect_present(arg)
    }

    /// Check for glob patterns (`*`, `?`, `[...]`)
    #[must_use]
    pub fn is_glob_present(&self, arg: &str) -> bool {
        detection::is_glob_present(arg)
    }

    /// Check for null byte injection
    #[must_use]
    pub fn is_null_byte_present(&self, arg: &str) -> bool {
        detection::is_null_byte_present(arg)
    }

    /// Check for control characters
    #[must_use]
    pub fn is_control_character_present(&self, arg: &str) -> bool {
        detection::is_control_character_present(arg)
    }

    /// Check for dangerous environment variable name
    #[must_use]
    pub fn is_dangerous_env_name(&self, name: &str) -> bool {
        detection::is_dangerous_env_name(name)
    }

    /// Check for dangerous environment variable value
    #[must_use]
    pub fn is_dangerous_env_value(&self, value: &str) -> bool {
        detection::is_dangerous_env_value(value)
    }

    // ========================================================================
    // Validation Methods
    // ========================================================================

    /// Validate that an argument is safe
    ///
    /// Returns `Ok(())` if safe, or an error with threat details.
    pub fn validate_safe(&self, arg: &str) -> Result<(), Problem> {
        validation::validate_safe_arg(arg)
    }

    /// Validate that a command is in the allow-list
    pub fn validate_command_allowed(
        &self,
        command: &str,
        allowlist: &AllowList,
    ) -> Result<(), Problem> {
        validation::validate_command_allowed(command, allowlist)
    }

    /// Validate a command name (no injection patterns, no path traversal)
    pub fn validate_command_name(&self, command: &str) -> Result<(), Problem> {
        validation::validate_command_name(command)
    }

    /// Validate multiple arguments
    pub fn validate_args<I, S>(&self, args: I) -> Result<(), Problem>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        validation::validate_args(args)
    }

    /// Validate environment variable name and value
    pub fn validate_env(&self, name: &str, value: &str) -> Result<(), Problem> {
        validation::validate_env(name, value)
    }

    // ========================================================================
    // Sanitization Methods (Shell Escaping)
    // ========================================================================

    /// Escape a shell argument for the current platform
    ///
    /// Returns a safely escaped argument that can be passed to a shell.
    pub fn escape_shell_arg(&self, arg: &str) -> Result<String, Problem> {
        sanitization::escape_shell_arg(arg)
    }

    /// Escape a shell argument using Unix conventions (single quotes)
    #[must_use]
    pub fn escape_shell_arg_unix(&self, arg: &str) -> String {
        sanitization::escape_shell_arg_unix(arg)
    }

    /// Escape a shell argument using Windows conventions (double quotes)
    #[must_use]
    pub fn escape_shell_arg_windows(&self, arg: &str) -> String {
        sanitization::escape_shell_arg_windows(arg)
    }

    /// Escape multiple shell arguments
    pub fn escape_shell_args<I, S>(&self, args: I) -> Result<Vec<String>, Problem>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        sanitization::escape_shell_args(args)
    }

    /// Join escaped arguments into a command string
    pub fn join_shell_args<I, S>(&self, args: I) -> Result<String, Problem>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        sanitization::join_shell_args(args)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    fn builder() -> CommandSecurityBuilder {
        CommandSecurityBuilder::new()
    }

    // ------------------------------------------------------------------------
    // Detection Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_detect_threats() {
        let threats = builder().detect_threats("$(whoami); ls | cat");
        assert!(threats.contains(&CommandThreat::CommandSubstitution));
        assert!(threats.contains(&CommandThreat::CommandChain));
        assert!(threats.contains(&CommandThreat::PipeChain));
    }

    #[test]
    fn test_is_dangerous() {
        assert!(builder().is_dangerous("$(whoami)"));
        assert!(builder().is_dangerous("; rm -rf /"));
        assert!(!builder().is_dangerous("safe-arg"));
    }

    #[test]
    fn test_chain_detection() {
        let b = builder();
        assert!(b.is_any_chain_present(";"));
        assert!(b.is_command_chain_present(";"));
        assert!(b.is_pipe_chain_present("|"));
        assert!(b.is_background_execution_present("cmd &"));
        assert!(b.is_conditional_chain_present("&&"));
    }

    #[test]
    fn test_expansion_detection() {
        let b = builder();
        assert!(b.is_shell_expansion_present("$(cmd)"));
        assert!(b.is_command_substitution_present("$(cmd)"));
        assert!(b.is_variable_expansion_present("$VAR"));
        assert!(b.is_indirect_expansion_present("${!VAR}"));
        assert!(b.is_arithmetic_expansion_present("$((1+1))"));
    }

    #[test]
    fn test_redirection_detection() {
        let b = builder();
        assert!(b.is_redirection_present("> file"));
        assert!(b.is_output_redirect_present("> file"));
        assert!(b.is_input_redirect_present("< file"));
    }

    #[test]
    fn test_special_chars() {
        let b = builder();
        assert!(b.is_glob_present("*.txt"));
        assert!(b.is_null_byte_present("file\0.txt"));
        assert!(b.is_control_character_present("\x01"));
    }

    // ------------------------------------------------------------------------
    // Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validate_safe() {
        assert!(builder().validate_safe("safe-arg").is_ok());
        assert!(builder().validate_safe("$(whoami)").is_err());
    }

    #[test]
    fn test_validate_command_allowed() {
        let allowlist = AllowList::git_operations();
        assert!(
            builder()
                .validate_command_allowed("git", &allowlist)
                .is_ok()
        );
        assert!(
            builder()
                .validate_command_allowed("rm", &allowlist)
                .is_err()
        );
    }

    // ------------------------------------------------------------------------
    // Sanitization Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_escape_shell_arg() {
        let escaped = builder().escape_shell_arg("user's input").expect("valid");
        assert!(!escaped.is_empty());
    }

    #[test]
    fn test_escape_shell_arg_unix() {
        assert_eq!(builder().escape_shell_arg_unix("simple"), "'simple'");
        assert_eq!(builder().escape_shell_arg_unix("user's"), "'user'\\''s'");
    }

    #[test]
    fn test_escape_shell_arg_windows() {
        assert_eq!(builder().escape_shell_arg_windows("simple"), "\"simple\"");
    }
}
