//! Hostname validation primitives
//!
//! Pure validation functions for hostname security.

// Allow dead_code: These are Layer 1 primitives that will be used by observe module
#![allow(dead_code)]

use crate::primitives::types::Problem;

// ============================================================================
// Options
// ============================================================================

/// Configuration for hostname validation
#[derive(Debug, Clone)]
pub struct NetworkSecurityHostnameConfig {
    /// Maximum hostname length (RFC 1035: 253)
    pub max_length: usize,
    /// Maximum label length (RFC 1035: 63)
    pub max_label_length: usize,
    /// Allow underscores (non-standard but common)
    pub allow_underscores: bool,
    /// Allow numeric-only labels
    pub allow_numeric_labels: bool,
}

impl Default for NetworkSecurityHostnameConfig {
    fn default() -> Self {
        Self {
            max_length: 253,
            max_label_length: 63,
            allow_underscores: false,
            allow_numeric_labels: true,
        }
    }
}

impl NetworkSecurityHostnameConfig {
    /// Create strict RFC-compliant options
    #[must_use]
    pub fn strict() -> Self {
        Self::default()
    }

    /// Create lenient options (allows underscores)
    #[must_use]
    pub fn lenient() -> Self {
        Self {
            allow_underscores: true,
            ..Default::default()
        }
    }
}

// ============================================================================
// Validation Functions
// ============================================================================

/// Validate hostname format
///
/// # Errors
///
/// Returns `Problem::validation` if hostname is invalid.
pub fn validate_hostname(hostname: &str) -> Result<(), Problem> {
    validate_hostname_with_options(hostname, &NetworkSecurityHostnameConfig::default())
}

/// Validate hostname with custom options
///
/// # Errors
///
/// Returns `Problem::validation` if hostname is invalid.
pub fn validate_hostname_with_options(
    hostname: &str,
    config: &NetworkSecurityHostnameConfig,
) -> Result<(), Problem> {
    let trimmed = hostname.trim();

    if trimmed.is_empty() {
        return Err(Problem::validation("Hostname cannot be empty"));
    }

    // Check total length
    if trimmed.len() > config.max_length {
        return Err(Problem::validation(format!(
            "Hostname exceeds maximum length of {} characters",
            config.max_length
        )));
    }

    // Cannot start or end with hyphen or dot
    if trimmed.starts_with('-') || trimmed.starts_with('.') {
        return Err(Problem::validation(
            "Hostname cannot start with hyphen or dot",
        ));
    }
    if trimmed.ends_with('-') || trimmed.ends_with('.') {
        return Err(Problem::validation(
            "Hostname cannot end with hyphen or dot",
        ));
    }

    // Validate each label
    for label in trimmed.split('.') {
        validate_label(label, config)?;
    }

    Ok(())
}

/// Validate hostname length only
///
/// # Errors
///
/// Returns `Problem::validation` if hostname exceeds max length.
pub fn validate_hostname_length(hostname: &str, max_length: usize) -> Result<(), Problem> {
    let trimmed = hostname.trim();

    if trimmed.len() > max_length {
        return Err(Problem::validation(format!(
            "Hostname exceeds maximum length of {max_length} characters"
        )));
    }

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

fn validate_label(label: &str, config: &NetworkSecurityHostnameConfig) -> Result<(), Problem> {
    if label.is_empty() {
        return Err(Problem::validation("Hostname label cannot be empty"));
    }

    if label.len() > config.max_label_length {
        return Err(Problem::validation(format!(
            "Hostname label exceeds maximum length of {} characters",
            config.max_label_length
        )));
    }

    // Cannot start or end with hyphen
    if label.starts_with('-') || label.ends_with('-') {
        return Err(Problem::validation(
            "Hostname label cannot start or end with hyphen",
        ));
    }

    // Check allowed characters
    for c in label.chars() {
        if !is_valid_hostname_char(c, config) {
            return Err(Problem::validation(format!(
                "Invalid character in hostname: '{c}'"
            )));
        }
    }

    Ok(())
}

fn is_valid_hostname_char(c: char, config: &NetworkSecurityHostnameConfig) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || (config.allow_underscores && c == '_')
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_hostname_valid() {
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("sub.example.com").is_ok());
        assert!(validate_hostname("localhost").is_ok());
        assert!(validate_hostname("my-server").is_ok());
        assert!(validate_hostname("server1").is_ok());
        assert!(validate_hostname("123.456").is_ok()); // Numeric labels allowed by default
    }

    #[test]
    fn test_validate_hostname_invalid() {
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("-invalid.com").is_err());
        assert!(validate_hostname("invalid-.com").is_err());
        assert!(validate_hostname(".invalid.com").is_err());
        assert!(validate_hostname("invalid.com.").is_err());
        assert!(validate_hostname("invalid..com").is_err());
    }

    #[test]
    fn test_validate_hostname_underscores() {
        let strict = NetworkSecurityHostnameConfig::strict();
        let lenient = NetworkSecurityHostnameConfig::lenient();

        assert!(validate_hostname_with_options("my_server.com", &strict).is_err());
        assert!(validate_hostname_with_options("my_server.com", &lenient).is_ok());
    }

    #[test]
    fn test_validate_hostname_length() {
        let long_hostname = "a".repeat(254);
        assert!(validate_hostname(&long_hostname).is_err());

        let long_label = format!("{}.com", "a".repeat(64));
        assert!(validate_hostname(&long_label).is_err());
    }
}
