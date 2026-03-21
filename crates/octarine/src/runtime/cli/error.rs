//! CLI error types and result aliases

use std::fmt;

use crate::observe::Problem;

use super::ExitCode;

/// Result type for CLI operations
pub type CliResult<T = ()> = Result<T, CliError>;

/// CLI-specific error with exit code
///
/// Wraps errors with appropriate exit codes and user-friendly messages.
///
/// # Example
///
/// ```
/// use octarine::runtime::cli::{CliError, ExitCode};
///
/// let err = CliError::new("Failed to connect to server")
///     .with_exit_code(ExitCode::UNAVAILABLE)
///     .with_hint("Check your network connection");
/// ```
#[derive(Debug)]
pub struct CliError {
    /// User-facing error message
    message: String,
    /// Exit code to use when terminating
    exit_code: ExitCode,
    /// Optional hint for the user
    hint: Option<String>,
    /// Optional underlying cause
    cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl CliError {
    /// Create a new CLI error with a message
    ///
    /// Default exit code is `GENERAL_ERROR` (1).
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: ExitCode::GENERAL_ERROR,
            hint: None,
            cause: None,
        }
    }

    /// Create a usage error (exit code 2)
    #[must_use]
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(message).with_exit_code(ExitCode::USAGE_ERROR)
    }

    /// Create a configuration error (exit code 78)
    #[must_use]
    pub fn config(message: impl Into<String>) -> Self {
        Self::new(message).with_exit_code(ExitCode::CONFIG_ERROR)
    }

    /// Create an I/O error (exit code 74)
    #[must_use]
    pub fn io(message: impl Into<String>) -> Self {
        Self::new(message).with_exit_code(ExitCode::IO_ERROR)
    }

    /// Create a permission error (exit code 77)
    #[must_use]
    pub fn permission(message: impl Into<String>) -> Self {
        Self::new(message).with_exit_code(ExitCode::NO_PERMISSION)
    }

    /// Create a service unavailable error (exit code 69)
    #[must_use]
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(message).with_exit_code(ExitCode::UNAVAILABLE)
    }

    /// Create an interrupted error (exit code 130)
    #[must_use]
    pub fn interrupted() -> Self {
        Self::new("Operation interrupted").with_exit_code(ExitCode::INTERRUPTED)
    }

    /// Set the exit code
    #[must_use]
    pub fn with_exit_code(mut self, code: ExitCode) -> Self {
        self.exit_code = code;
        self
    }

    /// Add a hint for the user
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Add an underlying cause
    #[must_use]
    pub fn with_cause<E: std::error::Error + Send + Sync + 'static>(mut self, cause: E) -> Self {
        self.cause = Some(Box::new(cause));
        self
    }

    /// Get the error message
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the exit code
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        self.exit_code
    }

    /// Get the hint, if any
    #[must_use]
    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }

    /// Format the error for display to the user
    #[must_use]
    pub fn format_user(&self) -> String {
        let mut output = format!("error: {}", self.message);

        if let Some(hint) = &self.hint {
            output.push_str(&format!("\n  hint: {}", hint));
        }

        output
    }

    /// Format the error with full details (for debugging)
    #[must_use]
    pub fn format_debug(&self) -> String {
        let mut output = format!("error: {} (exit code: {})", self.message, self.exit_code);

        if let Some(hint) = &self.hint {
            output.push_str(&format!("\n  hint: {}", hint));
        }

        if let Some(cause) = &self.cause {
            output.push_str(&format!("\n  caused by: {}", cause));
        }

        output
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, " (hint: {})", hint)?;
        }
        Ok(())
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().map(|e| e.as_ref() as _)
    }
}

impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self {
        let exit_code = match err.kind() {
            std::io::ErrorKind::NotFound => ExitCode::NO_INPUT,
            std::io::ErrorKind::PermissionDenied => ExitCode::NO_PERMISSION,
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted => ExitCode::UNAVAILABLE,
            std::io::ErrorKind::Interrupted => ExitCode::INTERRUPTED,
            _ => ExitCode::IO_ERROR,
        };

        Self::new(err.to_string())
            .with_exit_code(exit_code)
            .with_cause(err)
    }
}

impl From<Problem> for CliError {
    fn from(problem: Problem) -> Self {
        // Map Problem variants to appropriate exit codes
        let exit_code = match &problem {
            Problem::Validation(_) | Problem::Sanitization(_) | Problem::Parse(_) => {
                ExitCode::USAGE_ERROR
            }
            Problem::Config(_) => ExitCode::CONFIG_ERROR,
            Problem::Io(_) => ExitCode::IO_ERROR,
            Problem::NotFound(_) => ExitCode::NO_INPUT,
            Problem::Timeout(_) | Problem::Network(_) => ExitCode::UNAVAILABLE,
            Problem::Auth(_) | Problem::PermissionDenied(_) => ExitCode::NO_PERMISSION,
            Problem::RateLimited(_) => ExitCode::TEMP_FAILURE,
            _ => ExitCode::GENERAL_ERROR,
        };

        Self::new(problem.to_string()).with_exit_code(exit_code)
    }
}

impl From<String> for CliError {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

impl From<&str> for CliError {
    fn from(message: &str) -> Self {
        Self::new(message)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_new_error() {
        let err = CliError::new("Something went wrong");
        assert_eq!(err.message(), "Something went wrong");
        assert_eq!(err.exit_code(), ExitCode::GENERAL_ERROR);
        assert!(err.hint().is_none());
    }

    #[test]
    fn test_usage_error() {
        let err = CliError::usage("Invalid argument");
        assert_eq!(err.exit_code(), ExitCode::USAGE_ERROR);
    }

    #[test]
    fn test_config_error() {
        let err = CliError::config("Missing config file");
        assert_eq!(err.exit_code(), ExitCode::CONFIG_ERROR);
    }

    #[test]
    fn test_with_hint() {
        let err = CliError::new("Connection failed").with_hint("Check your internet connection");
        assert_eq!(err.hint(), Some("Check your internet connection"));
    }

    #[test]
    fn test_format_user() {
        let err = CliError::new("File not found").with_hint("Check the path and try again");
        let formatted = err.format_user();
        assert!(formatted.contains("error: File not found"));
        assert!(formatted.contains("hint: Check the path"));
    }

    #[test]
    fn test_format_debug() {
        let err = CliError::new("Operation failed")
            .with_exit_code(ExitCode::SOFTWARE_ERROR)
            .with_hint("Report this bug");
        let formatted = err.format_debug();
        assert!(formatted.contains("exit code: 70"));
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let cli_err: CliError = io_err.into();
        assert_eq!(cli_err.exit_code(), ExitCode::NO_INPUT);
    }

    #[test]
    fn test_from_io_error_permission() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let cli_err: CliError = io_err.into();
        assert_eq!(cli_err.exit_code(), ExitCode::NO_PERMISSION);
    }

    #[test]
    fn test_display() {
        let err = CliError::new("Error message").with_hint("A hint");
        let display = format!("{}", err);
        assert!(display.contains("Error message"));
        assert!(display.contains("hint: A hint"));
    }

    #[test]
    fn test_from_string() {
        let err: CliError = "An error".into();
        assert_eq!(err.message(), "An error");
    }
}
