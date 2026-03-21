//! SSRF Validation Primitives
//!
//! Pure validation functions for Server-Side Request Forgery prevention.
//! No observe dependencies - returns Result types for error handling.
//!
//! ## Usage
//!
//! ```ignore
//! use octarine::primitives::data::network::validation::ssrf::*;
//!
//! // Validate URL is SSRF-safe
//! validate_ssrf_safe("https://api.example.com")?;
//!
//! // Validate specific aspects
//! validate_safe_scheme("https://api.example.com")?;
//! validate_not_cloud_metadata("api.example.com")?;
//! validate_not_internal("api.example.com")?;
//! ```

// Allow dead_code: These are Layer 1 primitives that will be used by observe module
#![allow(dead_code)]

use crate::primitives::security::network::detection::ssrf::{
    extract_host_for_ssrf_check, is_cloud_metadata_endpoint, is_dangerous_scheme, is_internal_host,
    is_safe_scheme, is_url_shortener,
};
use crate::primitives::types::Problem;

// ============================================================================
// Combined SSRF Validation
// ============================================================================

/// Validate URL is safe from SSRF attacks
///
/// Checks:
/// 1. Scheme is HTTP or HTTPS
/// 2. Host is not internal/private
/// 3. Host is not a cloud metadata endpoint
/// 4. Host is not a URL shortener (warning in error message)
///
/// # Errors
///
/// Returns `Problem::validation` if URL fails any check.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::validation::ssrf::validate_ssrf_safe;
///
/// // Valid external URLs
/// assert!(validate_ssrf_safe("https://api.github.com/users").is_ok());
///
/// // Invalid - internal host
/// assert!(validate_ssrf_safe("http://localhost/admin").is_err());
///
/// // Invalid - cloud metadata
/// assert!(validate_ssrf_safe("http://169.254.169.254/").is_err());
///
/// // Invalid - dangerous scheme
/// assert!(validate_ssrf_safe("file:///etc/passwd").is_err());
/// ```
pub fn validate_ssrf_safe(url: &str) -> Result<(), Problem> {
    let trimmed = url.trim();

    // Check for empty URL
    if trimmed.is_empty() {
        return Err(Problem::validation("URL cannot be empty"));
    }

    // Check for dangerous schemes first (most critical)
    if is_dangerous_scheme(trimmed) {
        return Err(Problem::validation(format!(
            "URL uses dangerous scheme that could enable SSRF: {trimmed}"
        )));
    }

    // Verify safe scheme
    if !is_safe_scheme(trimmed) {
        return Err(Problem::validation(format!(
            "URL must use HTTP or HTTPS scheme: {trimmed}"
        )));
    }

    // Extract host for further checks
    let host = match extract_host_for_ssrf_check(trimmed) {
        Some(h) => h,
        None => {
            return Err(Problem::validation(format!(
                "Could not extract host from URL: {trimmed}"
            )));
        }
    };

    // Check cloud metadata endpoints
    validate_not_cloud_metadata(&host)?;

    // Check internal hosts
    validate_not_internal(&host)?;

    // Check URL shorteners (warning but still fails validation)
    if is_url_shortener(&host) {
        return Err(Problem::validation(format!(
            "URL uses a URL shortener which could redirect to malicious destinations: {host}"
        )));
    }

    Ok(())
}

// ============================================================================
// Individual Validation Functions
// ============================================================================

/// Validate host is not a cloud metadata endpoint
///
/// Cloud metadata endpoints provide access to:
/// - IAM credentials and access tokens
/// - SSH keys
/// - Instance configuration
/// - Sensitive application secrets
///
/// # Errors
///
/// Returns `Problem::validation` if host is a metadata endpoint.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::validation::ssrf::validate_not_cloud_metadata;
///
/// assert!(validate_not_cloud_metadata("api.github.com").is_ok());
/// assert!(validate_not_cloud_metadata("169.254.169.254").is_err());
/// assert!(validate_not_cloud_metadata("metadata.google.internal").is_err());
/// ```
pub fn validate_not_cloud_metadata(host: &str) -> Result<(), Problem> {
    if is_cloud_metadata_endpoint(host) {
        return Err(Problem::validation(format!(
            "Host is a cloud metadata endpoint - access denied for security: {host}"
        )));
    }
    Ok(())
}

/// Validate host is not internal/private
///
/// Internal hosts include:
/// - Localhost (127.0.0.1, ::1, localhost)
/// - Private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
/// - Link-local addresses (169.254.x.x, fe80::/10)
/// - Internal domain patterns (.local, .internal, .corp, etc.)
/// - Container service names (kubernetes, docker, consul, etc.)
///
/// # Errors
///
/// Returns `Problem::validation` if host is internal.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::validation::ssrf::validate_not_internal;
///
/// assert!(validate_not_internal("api.github.com").is_ok());
/// assert!(validate_not_internal("localhost").is_err());
/// assert!(validate_not_internal("192.168.1.1").is_err());
/// assert!(validate_not_internal("db.internal").is_err());
/// ```
pub fn validate_not_internal(host: &str) -> Result<(), Problem> {
    if is_internal_host(host) {
        return Err(Problem::validation(format!(
            "Host is internal/private - external access required: {host}"
        )));
    }
    Ok(())
}

/// Validate URL scheme is safe (HTTP/HTTPS only)
///
/// Dangerous schemes like file://, gopher://, ldap:// can be used to:
/// - Read local files
/// - Access internal services
/// - Bypass firewalls
/// - Execute protocol-specific attacks
///
/// # Errors
///
/// Returns `Problem::validation` if scheme is not HTTP or HTTPS.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::validation::ssrf::validate_safe_scheme;
///
/// assert!(validate_safe_scheme("https://api.example.com").is_ok());
/// assert!(validate_safe_scheme("http://webhook.site").is_ok());
/// assert!(validate_safe_scheme("file:///etc/passwd").is_err());
/// assert!(validate_safe_scheme("gopher://internal").is_err());
/// ```
pub fn validate_safe_scheme(url: &str) -> Result<(), Problem> {
    let trimmed = url.trim();

    if is_dangerous_scheme(trimmed) {
        return Err(Problem::validation(format!(
            "URL uses dangerous scheme: {trimmed}"
        )));
    }

    if !is_safe_scheme(trimmed) {
        return Err(Problem::validation(format!(
            "URL must use HTTP or HTTPS scheme: {trimmed}"
        )));
    }

    Ok(())
}

/// Validate host is not a URL shortener
///
/// URL shorteners can be used to:
/// - Bypass domain allowlists
/// - Hide malicious redirect destinations
/// - Perform redirect-based SSRF attacks
///
/// # Errors
///
/// Returns `Problem::validation` if host is a known URL shortener.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::validation::ssrf::validate_not_url_shortener;
///
/// assert!(validate_not_url_shortener("api.example.com").is_ok());
/// assert!(validate_not_url_shortener("bit.ly").is_err());
/// assert!(validate_not_url_shortener("tinyurl.com").is_err());
/// ```
pub fn validate_not_url_shortener(host: &str) -> Result<(), Problem> {
    if is_url_shortener(host) {
        return Err(Problem::validation(format!(
            "Host is a URL shortener - direct URLs required: {host}"
        )));
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // --- Combined SSRF Validation Tests ---

    #[test]
    fn test_validate_ssrf_safe_valid() {
        assert!(validate_ssrf_safe("https://api.github.com/users").is_ok());
        assert!(validate_ssrf_safe("https://webhook.site/callback").is_ok());
        assert!(validate_ssrf_safe("http://example.com/api").is_ok());
    }

    #[test]
    fn test_validate_ssrf_safe_empty() {
        assert!(validate_ssrf_safe("").is_err());
        assert!(validate_ssrf_safe("   ").is_err());
    }

    #[test]
    fn test_validate_ssrf_safe_dangerous_scheme() {
        assert!(validate_ssrf_safe("file:///etc/passwd").is_err());
        assert!(validate_ssrf_safe("gopher://internal:80").is_err());
        assert!(validate_ssrf_safe("ldap://dc.internal").is_err());
    }

    #[test]
    fn test_validate_ssrf_safe_no_scheme() {
        assert!(validate_ssrf_safe("example.com").is_err());
        assert!(validate_ssrf_safe("//example.com").is_err());
    }

    #[test]
    fn test_validate_ssrf_safe_cloud_metadata() {
        assert!(validate_ssrf_safe("http://169.254.169.254/").is_err());
        assert!(validate_ssrf_safe("http://metadata.google.internal/").is_err());
    }

    #[test]
    fn test_validate_ssrf_safe_internal() {
        assert!(validate_ssrf_safe("http://localhost/admin").is_err());
        assert!(validate_ssrf_safe("http://127.0.0.1:8080/").is_err());
        assert!(validate_ssrf_safe("http://192.168.1.1/api").is_err());
        assert!(validate_ssrf_safe("http://db.internal:5432/").is_err());
    }

    #[test]
    fn test_validate_ssrf_safe_url_shortener() {
        assert!(validate_ssrf_safe("https://bit.ly/abc123").is_err());
        assert!(validate_ssrf_safe("https://tinyurl.com/xyz").is_err());
    }

    // --- Cloud Metadata Validation Tests ---

    #[test]
    fn test_validate_not_cloud_metadata_valid() {
        assert!(validate_not_cloud_metadata("api.github.com").is_ok());
        assert!(validate_not_cloud_metadata("8.8.8.8").is_ok());
    }

    #[test]
    fn test_validate_not_cloud_metadata_invalid() {
        assert!(validate_not_cloud_metadata("169.254.169.254").is_err());
        assert!(validate_not_cloud_metadata("metadata.google.internal").is_err());
        assert!(validate_not_cloud_metadata("169.254.170.2").is_err());
    }

    // --- Internal Host Validation Tests ---

    #[test]
    fn test_validate_not_internal_valid() {
        assert!(validate_not_internal("api.github.com").is_ok());
        assert!(validate_not_internal("8.8.8.8").is_ok());
    }

    #[test]
    fn test_validate_not_internal_invalid() {
        assert!(validate_not_internal("localhost").is_err());
        assert!(validate_not_internal("127.0.0.1").is_err());
        assert!(validate_not_internal("192.168.1.1").is_err());
        assert!(validate_not_internal("10.0.0.1").is_err());
        assert!(validate_not_internal("db.internal").is_err());
    }

    // --- Scheme Validation Tests ---

    #[test]
    fn test_validate_safe_scheme_valid() {
        assert!(validate_safe_scheme("https://api.example.com").is_ok());
        assert!(validate_safe_scheme("http://webhook.site").is_ok());
    }

    #[test]
    fn test_validate_safe_scheme_invalid() {
        assert!(validate_safe_scheme("file:///etc/passwd").is_err());
        assert!(validate_safe_scheme("ftp://server/file").is_err());
        assert!(validate_safe_scheme("gopher://internal").is_err());
        assert!(validate_safe_scheme("example.com").is_err()); // No scheme
    }

    // --- URL Shortener Validation Tests ---

    #[test]
    fn test_validate_not_url_shortener_valid() {
        assert!(validate_not_url_shortener("api.example.com").is_ok());
        assert!(validate_not_url_shortener("github.com").is_ok());
    }

    #[test]
    fn test_validate_not_url_shortener_invalid() {
        assert!(validate_not_url_shortener("bit.ly").is_err());
        assert!(validate_not_url_shortener("tinyurl.com").is_err());
        assert!(validate_not_url_shortener("t.co").is_err());
    }
}
