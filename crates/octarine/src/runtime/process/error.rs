//! Process execution errors
//!
//! Error types for secure command execution.

use std::io;

use thiserror::Error;

use crate::observe::Problem;

/// Errors that can occur during secure command execution
///
/// # Security Note
///
/// Display formatting intentionally redacts potentially malicious arguments
/// to prevent log injection attacks. Argument lengths are shown instead of
/// actual values for security-related errors.
#[derive(Debug, Error)]
pub enum ProcessError {
    /// Command injection detected in argument
    #[error("command injection detected: {pattern} pattern in argument (length: {})", argument.len())]
    InjectionDetected {
        /// The argument that failed validation
        argument: String,
        /// Description of the injection pattern found
        pattern: String,
    },

    /// Command not found or not executable
    #[error("command not found: {command}")]
    CommandNotFound {
        /// The command that was not found
        command: String,
    },

    /// Command execution timed out
    #[error("command '{command}' timed out after {timeout_secs} seconds")]
    Timeout {
        /// The command that timed out
        command: String,
        /// The timeout duration in seconds
        timeout_secs: u64,
    },

    /// Command exited with non-zero status
    #[error("{}", format_non_zero_exit(.command, *.code, .stderr))]
    NonZeroExit {
        /// The command that failed
        command: String,
        /// The exit code
        code: i32,
        /// Stderr output (truncated if too long)
        stderr: String,
    },

    /// I/O error during command execution
    #[error("{context}: {source}")]
    Io {
        /// The I/O error
        #[source]
        source: io::Error,
        /// Context about the operation
        context: String,
    },

    /// Environment variable error
    #[error("environment error: {message}")]
    Environment {
        /// Description of the environment error
        message: String,
    },

    /// Argument validation failed (not injection, but policy violation)
    #[error("argument validation failed: {rule} (length: {})", argument.len())]
    ValidationFailed {
        /// The argument that failed validation
        argument: String,
        /// The validation rule that was violated
        rule: String,
    },

    /// Command not in allow-list
    #[error("command not allowed: '{command}' is not in the allow-list")]
    CommandNotAllowed {
        /// The command that was not allowed
        command: String,
    },
}

/// Format non-zero exit error message
fn format_non_zero_exit(command: &str, code: i32, stderr: &str) -> String {
    if stderr.is_empty() {
        format!("command '{}' exited with code {}", command, code)
    } else {
        format!(
            "command '{}' exited with code {}: {}",
            command, code, stderr
        )
    }
}

impl ProcessError {
    /// Create an injection detected error
    pub fn injection(argument: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self::InjectionDetected {
            argument: argument.into(),
            pattern: pattern.into(),
        }
    }

    /// Create a command not found error
    pub fn not_found(command: impl Into<String>) -> Self {
        Self::CommandNotFound {
            command: command.into(),
        }
    }

    /// Create a timeout error
    pub fn timeout(command: impl Into<String>, timeout_secs: u64) -> Self {
        Self::Timeout {
            command: command.into(),
            timeout_secs,
        }
    }

    /// Create a non-zero exit error
    pub fn non_zero_exit(command: impl Into<String>, code: i32, stderr: impl Into<String>) -> Self {
        let stderr = stderr.into();
        // Truncate stderr to avoid huge error messages
        let stderr = if stderr.len() > 1000 {
            format!("{}... (truncated)", &stderr[..1000])
        } else {
            stderr
        };
        Self::NonZeroExit {
            command: command.into(),
            code,
            stderr,
        }
    }

    /// Create an I/O error with context
    pub fn io(source: io::Error, context: impl Into<String>) -> Self {
        Self::Io {
            source,
            context: context.into(),
        }
    }

    /// Create an environment error
    pub fn environment(message: impl Into<String>) -> Self {
        Self::Environment {
            message: message.into(),
        }
    }

    /// Create a validation failed error
    pub fn validation(argument: impl Into<String>, rule: impl Into<String>) -> Self {
        Self::ValidationFailed {
            argument: argument.into(),
            rule: rule.into(),
        }
    }

    /// Create a command not allowed error
    pub fn command_not_allowed(command: impl Into<String>) -> Self {
        Self::CommandNotAllowed {
            command: command.into(),
        }
    }

    /// Check if this is a security-related error (injection, validation, not allowed)
    #[must_use]
    pub fn is_security_error(&self) -> bool {
        matches!(
            self,
            Self::InjectionDetected { .. }
                | Self::ValidationFailed { .. }
                | Self::CommandNotAllowed { .. }
        )
    }
}

impl From<ProcessError> for Problem {
    fn from(err: ProcessError) -> Self {
        match &err {
            ProcessError::InjectionDetected { .. }
            | ProcessError::ValidationFailed { .. }
            | ProcessError::CommandNotAllowed { .. } => Problem::security(err.to_string()),
            ProcessError::CommandNotFound { .. } => Problem::not_found(err.to_string()),
            ProcessError::Timeout { .. } => Problem::timeout(err.to_string()),
            ProcessError::NonZeroExit { .. }
            | ProcessError::Io { .. }
            | ProcessError::Environment { .. } => Problem::operation_failed(err.to_string()),
        }
    }
}

impl From<io::Error> for ProcessError {
    fn from(err: io::Error) -> Self {
        Self::io(err, "I/O error")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_injection_error() {
        let err = ProcessError::injection("$(whoami)", "command substitution");
        assert!(err.is_security_error());
        let display = format!("{}", err);
        assert!(display.contains("command injection detected"));
        assert!(display.contains("command substitution"));
        // Should NOT contain the actual malicious argument
        assert!(!display.contains("$(whoami)"));
    }

    #[test]
    fn test_timeout_error() {
        let err = ProcessError::timeout("git clone", 60);
        assert!(!err.is_security_error());
        let display = format!("{}", err);
        assert!(display.contains("timed out"));
        assert!(display.contains("60 seconds"));
    }

    #[test]
    fn test_non_zero_exit() {
        let err = ProcessError::non_zero_exit("ls", 1, "No such file");
        let display = format!("{}", err);
        assert!(display.contains("exited with code 1"));
        assert!(display.contains("No such file"));
    }

    #[test]
    fn test_stderr_truncation() {
        let long_stderr = "x".repeat(2000);
        let err = ProcessError::non_zero_exit("cmd", 1, long_stderr);
        if let ProcessError::NonZeroExit { stderr, .. } = err {
            assert!(stderr.len() < 1100);
            assert!(stderr.contains("truncated"));
        }
    }

    #[test]
    fn test_into_problem() {
        let err = ProcessError::injection("arg", "pattern");
        let problem: Problem = err.into();
        // Problem should be created successfully
        assert!(!problem.to_string().is_empty());
    }
}
