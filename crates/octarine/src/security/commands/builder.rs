//! Command security operations builder with observability
//!
//! Wraps `primitives::security::commands::CommandSecurityBuilder` with observe instrumentation.
//!
//! # Security Checks
//!
//! All security checks follow OWASP guidelines and address:
//! - **CWE-78**: OS Command Injection
//! - **CWE-158**: Null Byte Injection
//! - **CWE-707**: Improper Neutralization
//!
//! # Examples
//!
//! ```ignore
//! use octarine::security::commands::CommandSecurityBuilder;
//!
//! let security = CommandSecurityBuilder::new();
//!
//! // Detection
//! if security.is_dangerous("$(whoami)") {
//!     // Handle threat
//! }
//!
//! // Validation
//! security.validate_safe("safe-arg").unwrap();
//!
//! // Sanitization
//! let escaped = security.escape_shell_arg("user's input").unwrap();
//! ```

use std::time::Instant;

use crate::observe;
use crate::observe::Problem;
use crate::observe::metrics::{MetricName, increment_by, record};
use crate::primitives::security::commands::CommandSecurityBuilder as PrimitiveCommandSecurityBuilder;

use super::types::{AllowList, CommandThreat};

// Pre-validated metric names
#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn threats_detected() -> MetricName {
        MetricName::new("security.commands.threats_detected").expect("valid metric name")
    }

    pub fn validate_ms() -> MetricName {
        MetricName::new("security.commands.validate_ms").expect("valid metric name")
    }

    pub fn escape_ms() -> MetricName {
        MetricName::new("security.commands.escape_ms").expect("valid metric name")
    }
}

/// Command security operations builder with observability
///
/// Provides comprehensive security detection, validation, and sanitization
/// for command arguments with full audit trail via observe.
///
/// This builder always emits observe events. For operations without
/// observability overhead, use the shortcut functions or primitives directly.
#[derive(Debug, Clone, Copy, Default)]
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

    /// Check if argument contains any dangerous pattern
    #[must_use]
    pub fn is_dangerous(&self, arg: &str) -> bool {
        let result = PrimitiveCommandSecurityBuilder::new().is_dangerous(arg);
        if result {
            observe::event::critical("Command injection detected in argument");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Detect all security threats in an argument
    #[must_use]
    pub fn detect_threats(&self, arg: &str) -> Vec<CommandThreat> {
        let threats = PrimitiveCommandSecurityBuilder::new().detect_threats(arg);

        if !threats.is_empty() {
            let threat_names: Vec<_> = threats.iter().map(|t| t.description()).collect();
            observe::event::critical(format!(
                "Command threats detected: {}",
                threat_names.join(", ")
            ));
            increment_by(metric_names::threats_detected(), threats.len() as u64);
        }

        threats.into_iter().map(CommandThreat::from).collect()
    }

    /// Check for command chaining patterns
    #[must_use]
    pub fn is_any_chain_present(&self, arg: &str) -> bool {
        let result = PrimitiveCommandSecurityBuilder::new().is_any_chain_present(arg);
        if result {
            observe::warn(
                "command_chain_detected",
                "Command chaining pattern detected",
            );
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check for shell expansion patterns
    #[must_use]
    pub fn is_shell_expansion_present(&self, arg: &str) -> bool {
        let result = PrimitiveCommandSecurityBuilder::new().is_shell_expansion_present(arg);
        if result {
            observe::error(
                "shell_expansion_detected",
                "Shell expansion pattern detected",
            );
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check for command substitution (`$()` or backticks)
    #[must_use]
    pub fn is_command_substitution_present(&self, arg: &str) -> bool {
        let result = PrimitiveCommandSecurityBuilder::new().is_command_substitution_present(arg);
        if result {
            observe::error(
                "command_substitution_detected",
                "Command substitution pattern detected",
            );
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check for variable expansion
    #[must_use]
    pub fn is_variable_expansion_present(&self, arg: &str) -> bool {
        let result = PrimitiveCommandSecurityBuilder::new().is_variable_expansion_present(arg);
        if result {
            observe::warn(
                "variable_expansion_detected",
                "Variable expansion in argument",
            );
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check for indirect variable expansion (`${!VAR}`)
    #[must_use]
    pub fn is_indirect_expansion_present(&self, arg: &str) -> bool {
        let result = PrimitiveCommandSecurityBuilder::new().is_indirect_expansion_present(arg);
        if result {
            observe::warn(
                "indirect_expansion_detected",
                "Indirect variable expansion in argument",
            );
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check for arithmetic expansion (`$((expr))`)
    #[must_use]
    pub fn is_arithmetic_expansion_present(&self, arg: &str) -> bool {
        let result = PrimitiveCommandSecurityBuilder::new().is_arithmetic_expansion_present(arg);
        if result {
            observe::warn(
                "arithmetic_expansion_detected",
                "Arithmetic expansion in argument",
            );
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check for redirection patterns
    #[must_use]
    pub fn is_redirection_present(&self, arg: &str) -> bool {
        let result = PrimitiveCommandSecurityBuilder::new().is_redirection_present(arg);
        if result {
            observe::warn("redirection_detected", "Redirection pattern in argument");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check for glob patterns
    #[must_use]
    pub fn is_glob_present(&self, arg: &str) -> bool {
        let result = PrimitiveCommandSecurityBuilder::new().is_glob_present(arg);
        if result {
            observe::warn("glob_detected", "Glob pattern in argument");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check for null bytes
    #[must_use]
    pub fn is_null_byte_present(&self, arg: &str) -> bool {
        let result = PrimitiveCommandSecurityBuilder::new().is_null_byte_present(arg);
        if result {
            observe::error("null_byte_detected", "Null byte detected in argument");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check for control characters
    #[must_use]
    pub fn is_control_character_present(&self, arg: &str) -> bool {
        let result = PrimitiveCommandSecurityBuilder::new().is_control_character_present(arg);
        if result {
            observe::warn("control_char_detected", "Control character in argument");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    // ========================================================================
    // Validation Methods
    // ========================================================================

    /// Validate that an argument is safe
    ///
    /// Returns `Ok(())` if the argument is safe, `Err` if it contains threats.
    pub fn validate_safe(&self, arg: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = PrimitiveCommandSecurityBuilder::new().validate_safe(arg);

        record(
            metric_names::validate_ms(),
            start.elapsed().as_micros() as f64 / 1000.0,
        );

        if let Err(ref e) = result {
            observe::event::critical(format!("Command argument validation failed: {}", e));
        }

        result
    }

    /// Validate that a command is in the allow-list
    pub fn validate_command_allowed(
        &self,
        command: &str,
        allowlist: &AllowList,
    ) -> Result<(), Problem> {
        let prim_allowlist = allowlist.as_primitive();
        let result = PrimitiveCommandSecurityBuilder::new()
            .validate_command_allowed(command, prim_allowlist);

        if result.is_err() {
            observe::event::critical(format!("Command '{}' not in allow-list", command));
        }

        result
    }

    /// Validate a command name
    pub fn validate_command_name(&self, command: &str) -> Result<(), Problem> {
        let result = PrimitiveCommandSecurityBuilder::new().validate_command_name(command);
        if let Err(ref e) = result {
            observe::warn(
                "command_name_invalid",
                format!("Invalid command name: {}", e),
            );
        }
        result
    }

    /// Validate multiple arguments
    pub fn validate_args<I, S>(&self, args: I) -> Result<(), Problem>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        PrimitiveCommandSecurityBuilder::new().validate_args(args)
    }

    /// Validate environment variable name and value
    pub fn validate_env(&self, name: &str, value: &str) -> Result<(), Problem> {
        let result = PrimitiveCommandSecurityBuilder::new().validate_env(name, value);

        if result.is_err() {
            observe::event::critical(format!("Command env validation failed: {}", name));
        }

        result
    }

    // ========================================================================
    // Sanitization Methods (Shell Escaping)
    // ========================================================================

    /// Escape a shell argument for the current platform
    pub fn escape_shell_arg(&self, arg: &str) -> Result<String, Problem> {
        let start = Instant::now();
        let result = PrimitiveCommandSecurityBuilder::new().escape_shell_arg(arg);

        record(
            metric_names::escape_ms(),
            start.elapsed().as_micros() as f64 / 1000.0,
        );

        result
    }

    /// Escape a shell argument using Unix conventions
    #[must_use]
    pub fn escape_shell_arg_unix(&self, arg: &str) -> String {
        PrimitiveCommandSecurityBuilder::new().escape_shell_arg_unix(arg)
    }

    /// Escape a shell argument using Windows conventions
    #[must_use]
    pub fn escape_shell_arg_windows(&self, arg: &str) -> String {
        PrimitiveCommandSecurityBuilder::new().escape_shell_arg_windows(arg)
    }

    /// Escape multiple shell arguments
    pub fn escape_shell_args<I, S>(&self, args: I) -> Result<Vec<String>, Problem>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        PrimitiveCommandSecurityBuilder::new().escape_shell_args(args)
    }

    /// Join escaped arguments into a command string
    pub fn join_shell_args<I, S>(&self, args: I) -> Result<String, Problem>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        PrimitiveCommandSecurityBuilder::new().join_shell_args(args)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let _builder = CommandSecurityBuilder::new();
        // Builder is a unit struct, nothing to assert
    }

    #[test]
    fn test_security_detection() {
        let security = CommandSecurityBuilder::new();

        assert!(security.is_dangerous("$(whoami)"));
        assert!(security.is_dangerous("; rm -rf /"));
        assert!(!security.is_dangerous("safe-arg"));

        assert!(security.is_command_substitution_present("$(cmd)"));
        assert!(security.is_variable_expansion_present("$VAR"));
        assert!(security.is_null_byte_present("file\0.txt"));
    }

    #[test]
    fn test_security_validation() {
        let security = CommandSecurityBuilder::new();

        assert!(security.validate_safe("safe-arg").is_ok());
        assert!(security.validate_safe("$(whoami)").is_err());
    }

    #[test]
    fn test_shell_escaping() {
        let security = CommandSecurityBuilder::new();

        let escaped = security
            .escape_shell_arg("user's input")
            .expect("should escape");
        assert!(!escaped.is_empty());
    }

    #[test]
    fn test_validate_args_multi_arg_error() {
        // The error path of validate_args (issue #274 / umbrella #181):
        // a list with one bad item should propagate the failure.
        let security = CommandSecurityBuilder::new();

        let bad = ["safe-arg", "$(rm -rf /)", "also-safe"];
        let err = security
            .validate_args(bad)
            .expect_err("middle arg has command substitution; expected Err");
        // Error message should reference the offending argument index ("Argument 1").
        let msg = format!("{}", err);
        assert!(
            msg.contains("Argument 1"),
            "expected indexed error, got: {}",
            msg
        );

        // All-safe inputs pass.
        assert!(security.validate_args(["a", "b", "c"]).is_ok());
        // Empty iterator is vacuously ok.
        let empty: [&str; 0] = [];
        assert!(security.validate_args(empty).is_ok());
    }

    #[test]
    fn test_validate_env_dangerous_name() {
        let security = CommandSecurityBuilder::new();

        // Shell metacharacter in name is dangerous (per is_dangerous_env_name).
        assert!(security.validate_env("BAD$NAME", "ok").is_err());
        // `=` in the name is dangerous.
        assert!(security.validate_env("KEY=other", "ok").is_err());
        // Empty name is dangerous.
        assert!(security.validate_env("", "value").is_err());
    }

    #[test]
    fn test_validate_env_dangerous_value() {
        let security = CommandSecurityBuilder::new();

        // Shell expansion in value is dangerous.
        assert!(security.validate_env("PATH", "$(whoami)").is_err());
        // Null byte in value is dangerous.
        assert!(security.validate_env("PATH", "ok\0bad").is_err());

        // Positive case: plain value passes.
        assert!(security.validate_env("PATH", "/usr/bin").is_ok());
    }
}
