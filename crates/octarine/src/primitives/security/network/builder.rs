//! Primitive network security builder
//!
//! Provides a builder pattern for all network security operations.
//! This is the Layer 1 (primitives) API - no observe dependencies.
//!
//! The public API (`data/network`) wraps this with observe instrumentation.

use crate::primitives::types::Problem;

use super::detection::host;
use super::detection::ssrf;
use super::detection::url;
use super::validation::hostname;
use super::validation::port;
use super::validation::ssrf as ssrf_validation;
use super::validation::url as url_validation;

// Re-export types needed by builder users
pub use super::detection::host::HostType;
pub use super::validation::hostname::NetworkSecurityHostnameConfig;
pub use super::validation::url::NetworkSecurityUrlConfig;
pub use crate::primitives::types::PortRange;

/// Builder for network security operations
///
/// Provides all network security detection and validation functions
/// through a unified builder interface. No observe instrumentation.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::data::network::NetworkSecurityBuilder;
///
/// let builder = NetworkSecurityBuilder::new();
///
/// // SSRF detection
/// if builder.is_potential_ssrf("http://localhost/admin") {
///     // Handle SSRF risk
/// }
///
/// // Validation
/// builder.validate_ssrf_safe("https://api.example.com")?;
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkSecurityBuilder;

impl NetworkSecurityBuilder {
    /// Create a new primitive network security builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // ========================================================================
    // Host Classification
    // ========================================================================

    /// Classify a host string as IPv4, IPv6, Domain, or Unknown
    #[must_use]
    pub fn classify_host(&self, host: &str) -> HostType {
        host::classify_host(host)
    }

    /// Check if a host is an IP address (v4 or v6)
    #[must_use]
    pub fn is_ip_address_host(&self, host: &str) -> bool {
        host::is_ip_address_host(host)
    }

    /// Check if a host is a domain name
    #[must_use]
    pub fn is_domain_host(&self, host: &str) -> bool {
        host::is_domain_host(host)
    }

    // ========================================================================
    // URL Detection
    // ========================================================================

    /// Extract the scheme from a URL (e.g., "https" from "https://example.com")
    #[must_use]
    pub fn extract_scheme<'a>(&self, url_str: &'a str) -> Option<&'a str> {
        url::extract_scheme(url_str)
    }

    /// Extract the host from a URL
    #[must_use]
    pub fn extract_host<'a>(&self, url_str: &'a str) -> Option<&'a str> {
        url::extract_host(url_str)
    }

    /// Check if a URL is absolute (has scheme)
    #[must_use]
    pub fn is_absolute_url(&self, url_str: &str) -> bool {
        url::is_absolute_url(url_str)
    }

    /// Check if a URL is relative (no scheme)
    #[must_use]
    pub fn is_relative_url(&self, url_str: &str) -> bool {
        url::is_relative_url(url_str)
    }

    // ========================================================================
    // SSRF Detection - Schemes
    // ========================================================================

    /// Check if a URL uses a dangerous scheme (file://, gopher://, etc.)
    #[must_use]
    pub fn is_dangerous_scheme(&self, url_str: &str) -> bool {
        ssrf::is_dangerous_scheme(url_str)
    }

    /// Check if a URL uses a safe scheme (http, https)
    #[must_use]
    pub fn is_safe_scheme(&self, url_str: &str) -> bool {
        ssrf::is_safe_scheme(url_str)
    }

    // ========================================================================
    // SSRF Detection - Internal Hosts
    // ========================================================================

    /// Check if a host is localhost (127.0.0.1, ::1, localhost, etc.)
    #[must_use]
    pub fn is_localhost(&self, host: &str) -> bool {
        ssrf::is_localhost(host)
    }

    /// Check if a host matches internal domain patterns (.local, .internal, etc.)
    #[must_use]
    pub fn is_internal_domain_pattern(&self, host: &str) -> bool {
        ssrf::is_internal_domain_pattern(host)
    }

    /// Check if an IP is in private IPv4 ranges (10.x, 172.16-31.x, 192.168.x)
    #[must_use]
    pub fn is_private_ipv4_range(&self, ip: &str) -> bool {
        ssrf::is_private_ipv4_range(ip)
    }

    /// Check if an IP is in loopback IPv4 range (127.x.x.x)
    #[must_use]
    pub fn is_loopback_ipv4_range(&self, ip: &str) -> bool {
        ssrf::is_loopback_ipv4_range(ip)
    }

    /// Check if an IP is in link-local IPv4 range (169.254.x.x)
    #[must_use]
    pub fn is_link_local_ipv4_range(&self, ip: &str) -> bool {
        ssrf::is_link_local_ipv4_range(ip)
    }

    /// Check if an IP is a private IPv6 address
    #[must_use]
    pub fn is_private_ipv6(&self, ip: &str) -> bool {
        ssrf::is_private_ipv6(ip)
    }

    /// Check if a host is internal (localhost, private IPs, internal domains)
    #[must_use]
    pub fn is_internal_host(&self, host: &str) -> bool {
        ssrf::is_internal_host(host)
    }

    // ========================================================================
    // SSRF Detection - Cloud Metadata
    // ========================================================================

    /// Check if a host/URL targets cloud metadata endpoints (AWS, GCP, Azure)
    #[must_use]
    pub fn is_cloud_metadata_endpoint(&self, host: &str) -> bool {
        ssrf::is_cloud_metadata_endpoint(host)
    }

    /// Check if a host contains metadata-related patterns
    #[must_use]
    pub fn is_metadata_pattern_present(&self, host: &str) -> bool {
        ssrf::is_metadata_pattern_present(host)
    }

    // ========================================================================
    // SSRF Detection - URL Shorteners
    // ========================================================================

    /// Check if a host is a known URL shortener
    #[must_use]
    pub fn is_url_shortener(&self, host: &str) -> bool {
        ssrf::is_url_shortener(host)
    }

    // ========================================================================
    // SSRF Detection - Combined
    // ========================================================================

    /// Extract host from URL for SSRF checking (handles various formats)
    #[must_use]
    pub fn extract_host_for_ssrf_check(&self, url_str: &str) -> Option<String> {
        ssrf::extract_host_for_ssrf_check(url_str)
    }

    /// Check if a URL/host potentially targets internal resources (SSRF risk)
    #[must_use]
    pub fn is_potential_ssrf(&self, url_or_host: &str) -> bool {
        ssrf::is_potential_ssrf(url_or_host)
    }

    // ========================================================================
    // SSRF Validation
    // ========================================================================

    /// Validate that a URL is safe from SSRF attacks
    ///
    /// Checks for dangerous schemes, internal hosts, cloud metadata, and URL shorteners.
    pub fn validate_ssrf_safe(&self, url: &str) -> Result<(), Problem> {
        ssrf_validation::validate_ssrf_safe(url)
    }

    /// Validate that a URL doesn't target internal resources
    pub fn validate_not_internal(&self, url: &str) -> Result<(), Problem> {
        ssrf_validation::validate_not_internal(url)
    }

    /// Validate that a URL uses a safe scheme
    pub fn validate_safe_scheme(&self, url: &str) -> Result<(), Problem> {
        ssrf_validation::validate_safe_scheme(url)
    }

    /// Validate that a URL doesn't target cloud metadata endpoints
    pub fn validate_not_cloud_metadata(&self, url: &str) -> Result<(), Problem> {
        ssrf_validation::validate_not_cloud_metadata(url)
    }

    /// Validate that a URL is not a URL shortener
    pub fn validate_not_url_shortener(&self, url: &str) -> Result<(), Problem> {
        ssrf_validation::validate_not_url_shortener(url)
    }

    // ========================================================================
    // URL Validation
    // ========================================================================

    /// Validate URL format and basic security
    pub fn validate_url_format(&self, url: &str) -> Result<(), Problem> {
        url_validation::validate_url_format(url)
    }

    /// Validate URL scheme against allowed list
    pub fn validate_url_scheme(
        &self,
        url: &str,
        config: &NetworkSecurityUrlConfig,
    ) -> Result<(), Problem> {
        url_validation::validate_url_scheme(url, config)
    }

    // ========================================================================
    // Hostname Validation
    // ========================================================================

    /// Validate hostname format (RFC-compliant)
    pub fn validate_hostname(&self, hostname: &str) -> Result<(), Problem> {
        hostname::validate_hostname(hostname)
    }

    /// Validate hostname with custom config
    pub fn validate_hostname_with_config(
        &self,
        hostname_str: &str,
        config: &NetworkSecurityHostnameConfig,
    ) -> Result<(), Problem> {
        hostname::validate_hostname_with_options(hostname_str, config)
    }

    /// Validate hostname length only
    pub fn validate_hostname_length(
        &self,
        hostname: &str,
        max_length: usize,
    ) -> Result<(), Problem> {
        hostname::validate_hostname_length(hostname, max_length)
    }

    // ========================================================================
    // Port Validation
    // ========================================================================

    /// Validate a port number (1-65535)
    pub fn validate_port(&self, port_num: u16) -> Result<(), Problem> {
        port::validate_port(port_num)
    }

    /// Validate a port is within a specific range
    pub fn validate_port_range(&self, port_num: u16, range: PortRange) -> Result<(), Problem> {
        port::validate_port_range(port_num, range)
    }

    /// Parse and validate a port from a string
    pub fn parse_port(&self, s: &str) -> Result<u16, Problem> {
        port::parse_port(s)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = NetworkSecurityBuilder::new();
        // Builder should be usable
        assert!(!builder.is_potential_ssrf("https://example.com"));
    }

    #[test]
    fn test_host_classification() {
        let builder = NetworkSecurityBuilder::new();

        assert_eq!(builder.classify_host("192.168.1.1"), HostType::Ipv4);
        assert_eq!(builder.classify_host("::1"), HostType::Ipv6);
        assert_eq!(builder.classify_host("example.com"), HostType::Domain);

        assert!(builder.is_ip_address_host("192.168.1.1"));
        assert!(builder.is_domain_host("example.com"));
    }

    #[test]
    fn test_url_detection() {
        let builder = NetworkSecurityBuilder::new();

        assert_eq!(builder.extract_scheme("https://example.com"), Some("https"));
        assert!(builder.is_absolute_url("https://example.com"));
        assert!(builder.is_relative_url("/path/to/resource"));
    }

    #[test]
    fn test_ssrf_detection() {
        let builder = NetworkSecurityBuilder::new();

        assert!(builder.is_dangerous_scheme("file:///etc/passwd"));
        assert!(builder.is_safe_scheme("https://example.com"));
        assert!(builder.is_localhost("127.0.0.1"));
        assert!(builder.is_internal_host("192.168.1.1"));
        assert!(builder.is_cloud_metadata_endpoint("169.254.169.254"));
        assert!(builder.is_potential_ssrf("http://localhost/admin"));
    }

    #[test]
    fn test_ssrf_validation() {
        let builder = NetworkSecurityBuilder::new();

        assert!(
            builder
                .validate_ssrf_safe("https://api.example.com")
                .is_ok()
        );
        assert!(builder.validate_ssrf_safe("http://localhost").is_err());
        assert!(builder.validate_ssrf_safe("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_hostname_validation() {
        let builder = NetworkSecurityBuilder::new();

        assert!(builder.validate_hostname("example.com").is_ok());
        assert!(builder.validate_hostname("-invalid").is_err());
    }

    #[test]
    fn test_port_validation() {
        let builder = NetworkSecurityBuilder::new();

        assert!(builder.validate_port(80).is_ok());
        assert!(builder.validate_port(0).is_err());
        assert!(
            builder
                .validate_port_range(80, PortRange::WellKnown)
                .is_ok()
        );
        assert!(builder.parse_port("8080").is_ok());
    }
}
