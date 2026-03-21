//! Shortcut functions for common network security operations
//!
//! These functions provide a simplified API for the most common network
//! security operations. For more control, use [`NetworkSecurityBuilder`].
//!
//! All shortcuts include observe instrumentation for compliance-grade audit trails.

// Allow dead_code: These are public API shortcuts that will be used by consumers
#![allow(dead_code)]

use crate::observe::Problem;

use super::NetworkSecurityBuilder;

// ============================================================================
// SSRF Detection Shortcuts
// ============================================================================

/// Check if a URL/host potentially targets internal resources (SSRF risk)
///
/// This is a quick check for common SSRF patterns. For comprehensive
/// validation, use [`validate_ssrf_safe`].
///
/// # Example
///
/// ```ignore
/// use octarine::security::network::is_potential_ssrf;
///
/// if is_potential_ssrf("http://localhost/admin") {
///     // Block the request
/// }
/// ```
pub fn is_potential_ssrf(url_or_host: &str) -> bool {
    NetworkSecurityBuilder::new().is_potential_ssrf(url_or_host)
}

/// Check if a URL uses a dangerous scheme (file://, gopher://, etc.)
pub fn is_dangerous_scheme(url: &str) -> bool {
    NetworkSecurityBuilder::new().is_dangerous_scheme(url)
}

/// Check if a URL points to cloud metadata endpoints
pub fn is_cloud_metadata_endpoint(url: &str) -> bool {
    NetworkSecurityBuilder::new().is_cloud_metadata_endpoint(url)
}

/// Check if a host is internal (localhost, private IP ranges, etc.)
pub fn is_internal_host(host: &str) -> bool {
    NetworkSecurityBuilder::new().is_internal_host(host)
}

/// Check if a URL is a known URL shortener
pub fn is_url_shortener(url: &str) -> bool {
    NetworkSecurityBuilder::new().is_url_shortener(url)
}

// ============================================================================
// SSRF Validation Shortcuts
// ============================================================================

/// Validate that a URL is safe from SSRF attacks
///
/// This is the recommended function for validating user-provided URLs before
/// making HTTP requests. It checks for dangerous schemes, internal hosts,
/// cloud metadata endpoints, and URL shorteners.
///
/// # Example
///
/// ```ignore
/// use octarine::security::network::validate_ssrf_safe;
///
/// fn fetch_url(url: &str) -> Result<String, Error> {
///     validate_ssrf_safe(url)?;
///     // Safe to proceed with the request
///     http_client.get(url).send()
/// }
/// ```
///
/// # Errors
///
/// Returns `Problem::validation` if any SSRF risk is detected.
pub fn validate_ssrf_safe(url: &str) -> Result<(), Problem> {
    NetworkSecurityBuilder::new().validate_ssrf_safe(url)
}

/// Validate that a URL doesn't target internal resources
///
/// # Errors
///
/// Returns `Problem::validation` if the URL targets internal resources.
pub fn validate_not_internal(url: &str) -> Result<(), Problem> {
    NetworkSecurityBuilder::new().validate_not_internal(url)
}

/// Validate that a URL uses a safe scheme
///
/// # Errors
///
/// Returns `Problem::validation` if the scheme is dangerous.
pub fn validate_safe_scheme(url: &str) -> Result<(), Problem> {
    NetworkSecurityBuilder::new().validate_safe_scheme(url)
}

/// Validate that a URL doesn't target cloud metadata endpoints
///
/// # Errors
///
/// Returns `Problem::validation` if the URL targets cloud metadata.
pub fn validate_not_cloud_metadata(url: &str) -> Result<(), Problem> {
    NetworkSecurityBuilder::new().validate_not_cloud_metadata(url)
}

/// Validate that a URL is not a URL shortener
///
/// # Errors
///
/// Returns `Problem::validation` if the URL is a shortener.
pub fn validate_not_url_shortener(url: &str) -> Result<(), Problem> {
    NetworkSecurityBuilder::new().validate_not_url_shortener(url)
}

// ============================================================================
// URL Validation Shortcuts
// ============================================================================

/// Validate URL format and basic security
///
/// # Errors
///
/// Returns `Problem::validation` if the URL is malformed or uses dangerous schemes.
pub fn validate_url_format(url: &str) -> Result<(), Problem> {
    NetworkSecurityBuilder::new().validate_url_format(url)
}

/// Validate URL scheme against default allowed list (http, https)
///
/// # Errors
///
/// Returns `Problem::validation` if the scheme is not allowed.
pub fn validate_url_scheme(url: &str) -> Result<(), Problem> {
    NetworkSecurityBuilder::new().validate_url_scheme(url)
}

/// Validate URL requires HTTPS
///
/// # Errors
///
/// Returns `Problem::validation` if the URL is not HTTPS.
pub fn validate_https_required(url: &str) -> Result<(), Problem> {
    NetworkSecurityBuilder::new().validate_https_required(url)
}

// ============================================================================
// Hostname Validation Shortcuts
// ============================================================================

/// Validate hostname format (RFC-compliant)
///
/// # Errors
///
/// Returns `Problem::validation` if the hostname is invalid.
pub fn validate_hostname(hostname: &str) -> Result<(), Problem> {
    NetworkSecurityBuilder::new().validate_hostname(hostname)
}

/// Validate hostname with lenient options (allows underscores)
///
/// # Errors
///
/// Returns `Problem::validation` if the hostname is invalid.
pub fn validate_hostname_lenient(hostname: &str) -> Result<(), Problem> {
    NetworkSecurityBuilder::new().validate_hostname_lenient(hostname)
}

// ============================================================================
// Port Validation Shortcuts
// ============================================================================

/// Validate port number (1-65535)
///
/// # Errors
///
/// Returns `Problem::validation` if the port is invalid (0).
pub fn validate_port(port: u16) -> Result<(), Problem> {
    NetworkSecurityBuilder::new().validate_port(port)
}

/// Parse and validate port from string
///
/// # Errors
///
/// Returns `Problem::validation` if the string is not a valid port.
pub fn parse_port(s: &str) -> Result<u16, Problem> {
    NetworkSecurityBuilder::new().parse_port(s)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssrf_shortcuts() {
        assert!(is_potential_ssrf("http://localhost/admin"));
        assert!(is_potential_ssrf("http://169.254.169.254/metadata"));
        assert!(!is_potential_ssrf("https://api.example.com/data"));
    }

    #[test]
    fn test_validation_shortcuts() {
        assert!(validate_ssrf_safe("https://api.example.com/data").is_ok());
        assert!(validate_ssrf_safe("http://localhost/admin").is_err());

        assert!(validate_url_format("https://example.com").is_ok());
        assert!(validate_url_format("not-a-url").is_err());

        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("-invalid").is_err());

        assert!(validate_port(80).is_ok());
        assert!(validate_port(0).is_err());
    }
}
