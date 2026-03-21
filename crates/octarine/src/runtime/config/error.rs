//! Configuration errors

use std::path::Path;

use thiserror::Error;

use crate::observe::Problem;

/// Errors that can occur during configuration loading
#[derive(Debug, Clone, Error)]
pub enum ConfigError {
    /// Required environment variable is missing
    #[error("required configuration '{name}' is not set")]
    Missing {
        /// The variable name (with prefix)
        name: String,
    },

    /// Value failed to parse to expected type
    #[error("failed to parse '{name}' as {expected_type}: {details} (value: {value})")]
    ParseError {
        /// The variable name
        name: String,
        /// The raw value (may be masked if secret)
        value: String,
        /// The expected type
        expected_type: String,
        /// Details about the parse failure
        details: String,
    },

    /// Value failed validation
    #[error("validation failed for '{name}': {rule} ({details})")]
    ValidationFailed {
        /// The variable name
        name: String,
        /// The validation rule that failed
        rule: String,
        /// Details about the failure
        details: String,
    },

    /// Environment variable name is invalid
    #[error("invalid config name '{name}': {reason}")]
    InvalidName {
        /// The invalid name
        name: String,
        /// Why it's invalid
        reason: String,
    },

    /// Configuration file could not be read
    #[error("failed to load config file '{path}': {reason}")]
    FileError {
        /// The path to the file
        path: String,
        /// Why the file could not be loaded
        reason: String,
    },

    /// File permissions are insecure
    #[error("insecure permissions on '{path}': expected {expected}, got {actual}")]
    InsecurePermissions {
        /// The path to the file
        path: String,
        /// Expected permissions
        expected: String,
        /// Actual permissions found
        actual: String,
    },

    /// Figment extraction failed
    #[error("failed to extract configuration: {0}")]
    ExtractionError(String),
}

impl ConfigError {
    /// Create a missing variable error
    pub fn missing(name: impl Into<String>) -> Self {
        Self::Missing { name: name.into() }
    }

    /// Create a parse error
    pub fn parse(
        name: impl Into<String>,
        value: impl Into<String>,
        expected_type: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self::ParseError {
            name: name.into(),
            value: value.into(),
            expected_type: expected_type.into(),
            details: details.into(),
        }
    }

    /// Create a parse error with masked value (for secrets)
    pub fn parse_secret(
        name: impl Into<String>,
        expected_type: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self::ParseError {
            name: name.into(),
            value: "[REDACTED]".to_string(),
            expected_type: expected_type.into(),
            details: details.into(),
        }
    }

    /// Create a validation error
    pub fn validation(
        name: impl Into<String>,
        rule: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self::ValidationFailed {
            name: name.into(),
            rule: rule.into(),
            details: details.into(),
        }
    }

    /// Create an invalid name error
    pub fn invalid_name(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidName {
            name: name.into(),
            reason: reason.into(),
        }
    }

    /// Create a file error
    pub fn file_error(path: impl AsRef<Path>, reason: impl Into<String>) -> Self {
        Self::FileError {
            path: path.as_ref().display().to_string(),
            reason: reason.into(),
        }
    }

    /// Create an insecure permissions error
    pub fn insecure_permissions(
        path: impl AsRef<Path>,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self::InsecurePermissions {
            path: path.as_ref().display().to_string(),
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Create an extraction error
    pub fn extraction_error(details: impl Into<String>) -> Self {
        Self::ExtractionError(details.into())
    }

    /// Get the variable name associated with this error (if applicable)
    pub fn name(&self) -> &str {
        match self {
            Self::Missing { name } => name,
            Self::ParseError { name, .. } => name,
            Self::ValidationFailed { name, .. } => name,
            Self::InvalidName { name, .. } => name,
            Self::FileError { path, .. } => path,
            Self::InsecurePermissions { path, .. } => path,
            Self::ExtractionError(details) => details,
        }
    }
}

impl From<figment::Error> for ConfigError {
    fn from(err: figment::Error) -> Self {
        Self::extraction_error(err.to_string())
    }
}

impl From<ConfigError> for Problem {
    fn from(err: ConfigError) -> Self {
        Problem::config(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_missing_error() {
        let err = ConfigError::missing("APP_DATABASE_URL");
        assert_eq!(err.name(), "APP_DATABASE_URL");
        let display = format!("{}", err);
        assert!(display.contains("APP_DATABASE_URL"));
        assert!(display.contains("not set"));
    }

    #[test]
    fn test_parse_error() {
        let err = ConfigError::parse("APP_PORT", "not-a-number", "u16", "invalid digit");
        let display = format!("{}", err);
        assert!(display.contains("APP_PORT"));
        assert!(display.contains("u16"));
        assert!(display.contains("not-a-number"));
    }

    #[test]
    fn test_parse_secret_masks_value() {
        let err = ConfigError::parse_secret("APP_API_KEY", "string", "too short");
        let display = format!("{}", err);
        assert!(display.contains("[REDACTED]"));
        assert!(!display.contains("actual-secret"));
    }

    #[test]
    fn test_validation_error() {
        let err = ConfigError::validation("APP_PORT", "range", "must be 1-65535");
        let display = format!("{}", err);
        assert!(display.contains("validation failed"));
        assert!(display.contains("range"));
    }

    #[test]
    fn test_into_problem() {
        let err = ConfigError::missing("APP_KEY");
        let problem: Problem = err.into();
        assert!(!problem.to_string().is_empty());
    }

    #[test]
    fn test_file_error() {
        let err = ConfigError::file_error("/etc/app.toml", "file not found");
        let display = format!("{err}");
        assert!(display.contains("/etc/app.toml"));
        assert!(display.contains("file not found"));
    }

    #[test]
    fn test_insecure_permissions() {
        let err = ConfigError::insecure_permissions("/etc/secrets.toml", "0600", "0644");
        let display = format!("{err}");
        assert!(display.contains("/etc/secrets.toml"));
        assert!(display.contains("insecure permissions"));
        assert!(display.contains("0600"));
        assert!(display.contains("0644"));
    }

    #[test]
    fn test_extraction_error() {
        let err = ConfigError::extraction_error("missing field 'port'");
        let display = format!("{err}");
        assert!(display.contains("failed to extract"));
        assert!(display.contains("missing field 'port'"));
    }

    #[test]
    fn test_from_figment_error() {
        // Create a simple figment error by extracting wrong type
        let figment = figment::Figment::new();
        let result: Result<String, figment::Error> = figment.extract();
        let figment_err = result.unwrap_err();
        let config_err: ConfigError = figment_err.into();
        assert!(matches!(config_err, ConfigError::ExtractionError(_)));
    }
}
