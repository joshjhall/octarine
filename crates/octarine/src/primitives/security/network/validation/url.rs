//! URL validation primitives
//!
//! Pure validation functions for URL security.

// Allow dead_code: These are Layer 1 primitives that will be used by observe module
#![allow(dead_code)]

use crate::primitives::security::network::detection::ssrf::{is_dangerous_scheme, is_safe_scheme};
use crate::primitives::security::network::detection::url::extract_scheme;
use crate::primitives::types::Problem;

// ============================================================================
// Options
// ============================================================================

/// Configuration for URL validation
#[derive(Debug, Clone)]
pub struct NetworkSecurityUrlConfig {
    /// Require HTTPS only (block HTTP)
    pub require_https: bool,
    /// Maximum URL length
    pub max_length: usize,
    /// Allowed schemes (if empty, defaults to http/https)
    pub allowed_schemes: Vec<String>,
}

impl Default for NetworkSecurityUrlConfig {
    fn default() -> Self {
        Self {
            require_https: false,
            max_length: 2048,
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
        }
    }
}

impl NetworkSecurityUrlConfig {
    /// Create options that require HTTPS
    #[must_use]
    pub fn https_only() -> Self {
        Self {
            require_https: true,
            allowed_schemes: vec!["https".to_string()],
            ..Default::default()
        }
    }

    /// Create strict options
    #[must_use]
    pub fn strict() -> Self {
        Self {
            require_https: true,
            max_length: 1024,
            allowed_schemes: vec!["https".to_string()],
        }
    }
}

// ============================================================================
// Validation Functions
// ============================================================================

/// Validate URL format and basic security
///
/// # Errors
///
/// Returns `Problem::validation` if URL is invalid.
pub fn validate_url_format(url: &str) -> Result<(), Problem> {
    let trimmed = url.trim();

    if trimmed.is_empty() {
        return Err(Problem::validation("URL cannot be empty"));
    }

    if trimmed.len() > 2048 {
        return Err(Problem::validation("URL exceeds maximum length"));
    }

    // Must have a scheme
    if extract_scheme(trimmed).is_none() {
        return Err(Problem::validation(
            "URL must have a scheme (e.g., https://)",
        ));
    }

    // Check for dangerous schemes
    if is_dangerous_scheme(trimmed) {
        return Err(Problem::validation(format!(
            "URL uses dangerous scheme: {trimmed}"
        )));
    }

    Ok(())
}

/// Validate URL scheme is allowed
///
/// # Errors
///
/// Returns `Problem::validation` if scheme is not in allowed list.
pub fn validate_url_scheme(url: &str, config: &NetworkSecurityUrlConfig) -> Result<(), Problem> {
    let trimmed = url.trim();

    let scheme =
        extract_scheme(trimmed).ok_or_else(|| Problem::validation("URL must have a scheme"))?;

    // Check dangerous schemes first
    if is_dangerous_scheme(trimmed) {
        return Err(Problem::validation(format!(
            "URL uses dangerous scheme: {scheme}"
        )));
    }

    // Check if scheme is in allowed list
    let scheme_lower = scheme.to_lowercase();
    if !config
        .allowed_schemes
        .iter()
        .any(|s| s.to_lowercase() == scheme_lower)
    {
        return Err(Problem::validation(format!(
            "URL scheme '{scheme}' not in allowed list: {:?}",
            config.allowed_schemes
        )));
    }

    // Check HTTPS requirement
    if config.require_https && scheme_lower != "https" {
        return Err(Problem::validation("HTTPS is required"));
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_url_format_valid() {
        assert!(validate_url_format("https://example.com").is_ok());
        assert!(validate_url_format("http://example.com/path").is_ok());
        assert!(validate_url_format("https://example.com:8080").is_ok());
    }

    #[test]
    fn test_validate_url_format_invalid() {
        assert!(validate_url_format("").is_err());
        assert!(validate_url_format("example.com").is_err()); // No scheme
        assert!(validate_url_format("file:///etc/passwd").is_err()); // Dangerous
        assert!(validate_url_format("javascript:alert(1)").is_err()); // Dangerous
    }

    #[test]
    fn test_validate_url_scheme() {
        let default_config = NetworkSecurityUrlConfig::default();
        let https_config = NetworkSecurityUrlConfig::https_only();

        assert!(validate_url_scheme("https://example.com", &default_config).is_ok());
        assert!(validate_url_scheme("http://example.com", &default_config).is_ok());
        assert!(validate_url_scheme("ftp://example.com", &default_config).is_err());

        assert!(validate_url_scheme("https://example.com", &https_config).is_ok());
        assert!(validate_url_scheme("http://example.com", &https_config).is_err());
    }
}
