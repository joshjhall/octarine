//! Network security builder with observe instrumentation
//!
//! Provides a builder pattern for network security operations with
//! built-in logging and metrics via the observe module.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.

// Allow dead_code: This is a new module that will be used by consumers
#![allow(dead_code)]

use std::time::Instant;

use crate::observe::metrics::{increment_by, record};
use crate::observe::{Problem, event};
use crate::primitives::security::network::NetworkSecurityBuilder as PrimitiveNetworkSecurityBuilder;

use super::types::{HostType, NetworkSecurityHostnameConfig, NetworkSecurityUrlConfig, PortRange};

crate::define_metrics! {
    validate_ms => "security.network.validate_ms",
    threats_detected => "security.network.threats_detected",
}

// ============================================================================
// NetworkSecurityBuilder
// ============================================================================

/// Builder for network security operations with observe instrumentation
///
/// This builder wraps `PrimitiveNetworkSecurityBuilder` and adds observe
/// instrumentation for compliance-grade audit trails.
///
/// # Example
///
/// ```ignore
/// use octarine::security::network::NetworkSecurityBuilder;
///
/// let builder = NetworkSecurityBuilder::new();
///
/// // SSRF validation
/// builder.validate_ssrf_safe("https://api.example.com/data")?;
///
/// // URL validation
/// builder.validate_url_format("https://example.com")?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct NetworkSecurityBuilder {
    /// The underlying primitive builder
    inner: PrimitiveNetworkSecurityBuilder,
    /// Whether to emit observe events
    emit_events: bool,
}

impl NetworkSecurityBuilder {
    /// Create a new builder with default settings
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PrimitiveNetworkSecurityBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: PrimitiveNetworkSecurityBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // Host Classification
    // ========================================================================

    /// Classify a host string as IPv4, IPv6, Domain, or Unknown
    #[must_use]
    pub fn classify_host(&self, host: &str) -> super::types::HostType {
        self.inner.classify_host(host).into()
    }

    /// Check if a host is an IP address (v4 or v6)
    #[must_use]
    pub fn is_ip_address_host(&self, host: &str) -> bool {
        self.inner.is_ip_address_host(host)
    }

    /// Check if a host is a domain name
    #[must_use]
    pub fn is_domain_host(&self, host: &str) -> bool {
        self.inner.is_domain_host(host)
    }

    // ========================================================================
    // URL Detection
    // ========================================================================

    /// Extract the scheme from a URL (e.g., "https" from `https://example.com`)
    #[must_use]
    pub fn extract_scheme<'a>(&self, url_str: &'a str) -> Option<&'a str> {
        self.inner.extract_scheme(url_str)
    }

    /// Extract the host from a URL
    #[must_use]
    pub fn extract_host<'a>(&self, url_str: &'a str) -> Option<&'a str> {
        self.inner.extract_host(url_str)
    }

    /// Check if a URL is absolute (has scheme)
    #[must_use]
    pub fn is_absolute_url(&self, url_str: &str) -> bool {
        self.inner.is_absolute_url(url_str)
    }

    /// Check if a URL is relative (no scheme)
    #[must_use]
    pub fn is_relative_url(&self, url_str: &str) -> bool {
        self.inner.is_relative_url(url_str)
    }

    // ========================================================================
    // SSRF Detection - Schemes
    // ========================================================================

    /// Check if a URL uses a dangerous scheme (file://, gopher://, etc.)
    pub fn is_dangerous_scheme(&self, url: &str) -> bool {
        let result = self.inner.is_dangerous_scheme(url);

        if self.emit_events && result {
            event::warn(format!("Dangerous scheme detected: {}", url));
            increment_by(metric_names::threats_detected(), 1);
        }

        result
    }

    /// Check if a URL uses a safe scheme (http, https)
    #[must_use]
    pub fn is_safe_scheme(&self, url_str: &str) -> bool {
        self.inner.is_safe_scheme(url_str)
    }

    // ========================================================================
    // SSRF Detection - Internal Hosts
    // ========================================================================

    /// Check if a host is localhost (127.0.0.1, ::1, localhost, etc.)
    pub fn is_localhost(&self, host: &str) -> bool {
        let result = self.inner.is_localhost(host);

        if self.emit_events && result {
            event::debug(format!("Localhost detected: {}", host));
        }

        result
    }

    /// Check if a host matches internal domain patterns (.local, .internal, etc.)
    pub fn is_internal_domain_pattern(&self, host: &str) -> bool {
        let result = self.inner.is_internal_domain_pattern(host);

        if self.emit_events && result {
            event::debug(format!("Internal domain pattern detected: {}", host));
        }

        result
    }

    /// Check if an IP is in private IPv4 ranges (10.x, 172.16-31.x, 192.168.x)
    pub fn is_private_ipv4_range(&self, ip: &str) -> bool {
        let result = self.inner.is_private_ipv4_range(ip);

        if self.emit_events && result {
            event::debug(format!("Private IPv4 range detected: {}", ip));
        }

        result
    }

    /// Check if an IP is in loopback IPv4 range (127.x.x.x)
    pub fn is_loopback_ipv4_range(&self, ip: &str) -> bool {
        let result = self.inner.is_loopback_ipv4_range(ip);

        if self.emit_events && result {
            event::debug(format!("Loopback IPv4 range detected: {}", ip));
        }

        result
    }

    /// Check if an IP is in link-local IPv4 range (169.254.x.x)
    pub fn is_link_local_ipv4_range(&self, ip: &str) -> bool {
        let result = self.inner.is_link_local_ipv4_range(ip);

        if self.emit_events && result {
            event::debug(format!("Link-local IPv4 range detected: {}", ip));
        }

        result
    }

    /// Check if an IP is a private IPv6 address
    pub fn is_private_ipv6(&self, ip: &str) -> bool {
        let result = self.inner.is_private_ipv6(ip);

        if self.emit_events && result {
            event::debug(format!("Private IPv6 detected: {}", ip));
        }

        result
    }

    /// Check if a host is internal (localhost, private IPs, internal domains)
    pub fn is_internal_host(&self, host: &str) -> bool {
        let result = self.inner.is_internal_host(host);

        if self.emit_events && result {
            event::debug(format!("Internal host detected: {}", host));
        }

        result
    }

    // ========================================================================
    // SSRF Detection - Cloud Metadata
    // ========================================================================

    /// Check if a host/URL targets cloud metadata endpoints (AWS, GCP, Azure)
    pub fn is_cloud_metadata_endpoint(&self, url: &str) -> bool {
        let result = self.inner.is_cloud_metadata_endpoint(url);

        if self.emit_events && result {
            event::critical(format!("Cloud metadata access detected: {}", url));
            increment_by(metric_names::threats_detected(), 1);
        }

        result
    }

    /// Check if a host contains metadata-related patterns
    pub fn is_metadata_pattern_present(&self, host: &str) -> bool {
        let result = self.inner.is_metadata_pattern_present(host);

        if self.emit_events && result {
            event::debug(format!("Metadata pattern present: {}", host));
        }

        result
    }

    // ========================================================================
    // SSRF Detection - URL Shorteners
    // ========================================================================

    /// Check if a host is a known URL shortener
    pub fn is_url_shortener(&self, url: &str) -> bool {
        let result = self.inner.is_url_shortener(url);

        if self.emit_events && result {
            event::debug(format!("URL shortener detected: {}", url));
        }

        result
    }

    // ========================================================================
    // SSRF Detection - Combined
    // ========================================================================

    /// Extract host from URL for SSRF checking (handles various formats)
    #[must_use]
    pub fn extract_host_for_ssrf_check(&self, url_str: &str) -> Option<String> {
        self.inner.extract_host_for_ssrf_check(url_str)
    }

    /// Check if a URL/host potentially targets internal resources (SSRF risk)
    pub fn is_potential_ssrf(&self, url_or_host: &str) -> bool {
        let result = self.inner.is_potential_ssrf(url_or_host);

        if self.emit_events && result {
            event::critical(format!("SSRF detected: {}", url_or_host));
            increment_by(metric_names::threats_detected(), 1);
        }

        result
    }

    // ========================================================================
    // SSRF Validation
    // ========================================================================

    /// Validate that a URL is safe from SSRF attacks
    ///
    /// Checks for:
    /// - Dangerous schemes (file://, gopher://, etc.)
    /// - Internal hosts (localhost, private IPs)
    /// - Cloud metadata endpoints
    /// - URL shorteners
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if any SSRF risk is detected.
    pub fn validate_ssrf_safe(&self, url: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_ssrf_safe(url);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::critical(format!("SSRF validation failed: {}", url));
            } else {
                event::debug(format!("SSRF validation passed: {}", url));
            }
        }

        result
    }

    /// Validate that a URL doesn't target internal resources
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if the URL targets internal resources.
    pub fn validate_not_internal(&self, url: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_not_internal(url);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::critical(format!("Internal URL blocked: {}", url));
            }
        }

        result
    }

    /// Validate that a URL uses a safe scheme
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if the scheme is dangerous.
    pub fn validate_safe_scheme(&self, url: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_safe_scheme(url);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::critical(format!("Dangerous scheme blocked: {}", url));
            }
        }

        result
    }

    /// Validate that a URL doesn't target cloud metadata endpoints
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if the URL targets cloud metadata.
    pub fn validate_not_cloud_metadata(&self, url: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_not_cloud_metadata(url);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::critical(format!("Cloud metadata blocked: {}", url));
            }
        }

        result
    }

    /// Validate that a URL is not a URL shortener
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if the URL is a shortener.
    pub fn validate_not_url_shortener(&self, url: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_not_url_shortener(url);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::warn(format!("URL shortener blocked: {}", url));
            }
        }

        result
    }

    // ========================================================================
    // URL Validation
    // ========================================================================

    /// Validate URL format and basic security
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if the URL is malformed or uses dangerous schemes.
    pub fn validate_url_format(&self, url: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_url_format(url);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::warn(format!("Invalid URL format: {}", url));
            }
        }

        result
    }

    /// Validate URL scheme against allowed list
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if the scheme is not in the allowed list.
    pub fn validate_url_scheme(&self, url: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let config = NetworkSecurityUrlConfig::default();
        let result = self.inner.validate_url_scheme(url, &(&config).into());

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::warn(format!("URL scheme not allowed: {}", url));
            }
        }

        result
    }

    /// Validate URL requires HTTPS
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if the URL is not HTTPS.
    pub fn validate_https_required(&self, url: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let config = NetworkSecurityUrlConfig::https_only();
        let result = self.inner.validate_url_scheme(url, &(&config).into());

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::warn(format!("HTTPS required: {}", url));
            }
        }

        result
    }

    // ========================================================================
    // Hostname Validation
    // ========================================================================

    /// Validate hostname format (RFC-compliant)
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if the hostname is invalid.
    pub fn validate_hostname(&self, hostname: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_hostname(hostname);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::warn(format!("Invalid hostname: {}", hostname));
            }
        }

        result
    }

    /// Validate hostname with lenient config (allows underscores)
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if the hostname is invalid.
    pub fn validate_hostname_lenient(&self, hostname: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let config = NetworkSecurityHostnameConfig::lenient();
        let result = self
            .inner
            .validate_hostname_with_config(hostname, &(&config).into());

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::warn(format!("Invalid hostname: {}", hostname));
            }
        }

        result
    }

    /// Validate hostname length only
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if the hostname exceeds the max length.
    pub fn validate_hostname_length(
        &self,
        hostname: &str,
        max_length: usize,
    ) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_hostname_length(hostname, max_length);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::warn(format!(
                    "Hostname too long: {} (max {})",
                    hostname.len(),
                    max_length
                ));
            }
        }

        result
    }

    // ========================================================================
    // Port Validation
    // ========================================================================

    /// Validate port number (1-65535)
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if the port is invalid.
    pub fn validate_port(&self, port: u16) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_port(port);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::warn(format!("Invalid port: {}", port));
            }
        }

        result
    }

    /// Validate port is in a specific range
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if the port is outside the range.
    pub fn validate_port_range(&self, port: u16, range: PortRange) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_port_range(port, range.into());

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::warn(format!("Port {} out of range", port));
            }
        }

        result
    }

    /// Parse and validate port from string
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if the string is not a valid port.
    pub fn parse_port(&self, s: &str) -> Result<u16, Problem> {
        let start = Instant::now();
        let result = self.inner.parse_port(s);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::warn(format!("Invalid port string: {}", s));
            }
        }

        result
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::observe::metrics::{flush_for_testing, snapshot};
    use std::sync::Mutex;

    static METRICS_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_builder_creation() {
        let builder = NetworkSecurityBuilder::new();
        assert!(builder.emit_events);

        let silent = NetworkSecurityBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_ssrf_detection() {
        let builder = NetworkSecurityBuilder::silent();

        assert!(builder.is_potential_ssrf("http://localhost/admin"));
        assert!(builder.is_potential_ssrf("http://169.254.169.254/metadata"));
        assert!(!builder.is_potential_ssrf("https://api.example.com/data"));
    }

    #[test]
    fn test_ssrf_validation() {
        let builder = NetworkSecurityBuilder::silent();

        assert!(
            builder
                .validate_ssrf_safe("https://api.example.com/data")
                .is_ok()
        );
        assert!(
            builder
                .validate_ssrf_safe("http://localhost/admin")
                .is_err()
        );
        assert!(
            builder
                .validate_ssrf_safe("http://169.254.169.254/metadata")
                .is_err()
        );
    }

    #[test]
    fn test_url_validation() {
        let builder = NetworkSecurityBuilder::silent();

        assert!(builder.validate_url_format("https://example.com").is_ok());
        assert!(builder.validate_url_format("not-a-url").is_err());
        assert!(builder.validate_url_format("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_hostname_validation() {
        let builder = NetworkSecurityBuilder::silent();

        assert!(builder.validate_hostname("example.com").is_ok());
        assert!(builder.validate_hostname("my-server").is_ok());
        assert!(builder.validate_hostname("-invalid").is_err());
    }

    #[test]
    fn test_port_validation() {
        let builder = NetworkSecurityBuilder::silent();

        assert!(builder.validate_port(80).is_ok());
        assert!(builder.validate_port(443).is_ok());
        assert!(builder.validate_port(0).is_err());
    }

    #[test]
    fn test_with_events_toggle() {
        let builder = NetworkSecurityBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_metrics_validate_ms_recorded() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let builder = NetworkSecurityBuilder::new();
        flush_for_testing();
        let before = snapshot()
            .histograms
            .get("security.network.validate_ms")
            .map_or(0, |h| h.count);

        let _ = builder.validate_url_format("https://example.com");
        flush_for_testing();

        let after = snapshot()
            .histograms
            .get("security.network.validate_ms")
            .map_or(0, |h| h.count);
        assert!(after > before, "validate_ms should record");
    }

    #[test]
    fn test_metrics_threats_detected_counter() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let builder = NetworkSecurityBuilder::new();
        flush_for_testing();
        let before = snapshot()
            .counters
            .get("security.network.threats_detected")
            .map_or(0, |c| c.value);

        assert!(builder.is_potential_ssrf("http://localhost/admin"));
        flush_for_testing();

        let after = snapshot()
            .counters
            .get("security.network.threats_detected")
            .map_or(0, |c| c.value);
        assert!(after > before, "threats_detected should increment");
    }

    #[test]
    fn test_silent_mode_emits_no_metrics() {
        // Structural test: `silent()` returns a builder with emit_events=false,
        // and every metric call site in this module is gated by `if self.emit_events`.
        // A behavioral delta-assertion would race with concurrent tests across the
        // workspace that hit these same global metric names via shortcuts/facade.
        let builder = NetworkSecurityBuilder::silent();
        assert!(!builder.emit_events);

        // Sanity: invoking through the silent builder still works functionally.
        assert!(builder.is_potential_ssrf("http://localhost/admin"));
        assert!(builder.validate_url_format("https://example.com").is_ok());
    }

    #[test]
    fn test_validate_hostname_length_error_path() {
        let builder = NetworkSecurityBuilder::silent();

        // Success: within RFC 1035 max (253).
        assert!(
            builder
                .validate_hostname_length("ok.example.com", 253)
                .is_ok()
        );

        // Error: 300 chars exceeds 253.
        let too_long = "a".repeat(300);
        assert!(builder.validate_hostname_length(&too_long, 253).is_err());

        // Error: even smaller maxes are enforced (length-only check is policy-driven).
        assert!(
            builder
                .validate_hostname_length("abcdef.example.com", 5)
                .is_err()
        );
    }

    #[test]
    fn test_classify_host_variants() {
        use super::super::types::HostType;
        let builder = NetworkSecurityBuilder::silent();

        assert_eq!(builder.classify_host("192.168.1.1"), HostType::Ipv4);
        assert_eq!(builder.classify_host("::1"), HostType::Ipv6);
        assert_eq!(builder.classify_host("[::1]"), HostType::Ipv6);
        assert_eq!(builder.classify_host("example.com"), HostType::Domain);
        assert_eq!(builder.classify_host(""), HostType::Unknown);
    }

    #[test]
    fn test_ssrf_ipv4_range_boundaries() {
        // RFC 1918 boundary coverage (issue #274 / umbrella #181).
        let builder = NetworkSecurityBuilder::silent();

        // 10.0.0.0/8 — full /8 is private.
        assert!(builder.is_potential_ssrf("http://10.0.0.0/"));
        assert!(builder.is_potential_ssrf("http://10.255.255.255/"));

        // 172.16.0.0/12 — 172.16.x.x through 172.31.x.x.
        assert!(builder.is_potential_ssrf("http://172.16.0.0/"));
        assert!(builder.is_potential_ssrf("http://172.31.255.255/"));

        // Just outside 172.16-31 should NOT trigger SSRF.
        assert!(!builder.is_potential_ssrf("http://172.15.0.0/"));
        assert!(!builder.is_potential_ssrf("http://172.32.0.0/"));

        // 192.168.0.0/16 — full /16 is private.
        assert!(builder.is_potential_ssrf("http://192.168.0.0/"));
        assert!(builder.is_potential_ssrf("http://192.168.255.255/"));
    }

    #[test]
    fn test_ssrf_ipv6_private_addresses() {
        // IPv6 private-range coverage (issue #274 / umbrella #181).
        let builder = NetworkSecurityBuilder::silent();

        // Direct IPv6 classification — non-bracketed form parses cleanly.
        // Unique-local (fc00::/7).
        assert!(builder.is_private_ipv6("fd00::1"));
        assert!(builder.is_private_ipv6("fc00::1"));
        // Link-local (fe80::/10).
        assert!(builder.is_private_ipv6("fe80::1"));
        // Loopback.
        assert!(builder.is_private_ipv6("::1"));
        // Unspecified.
        assert!(builder.is_private_ipv6("::"));
        // Public IPv6 (documentation prefix) should not match.
        assert!(!builder.is_private_ipv6("2001:db8::1"));

        // SSRF via URL form: bracketed `[::1]` works because it's in the
        // localhost lookup table. Other private IPv6 ranges are not yet
        // detected in `is_potential_ssrf` (the URL-host extractor returns
        // `[fd00::1]` with brackets, which `is_private_ipv6` cannot parse).
        // The direct `is_private_ipv6` checks above are the canonical
        // coverage; URL-form SSRF for arbitrary private IPv6 is tracked
        // as a separate primitive-level gap.
        assert!(builder.is_potential_ssrf("http://[::1]/"));
    }
}
