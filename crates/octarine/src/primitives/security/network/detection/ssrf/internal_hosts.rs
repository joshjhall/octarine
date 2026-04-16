//! Internal Host Detection
//!
//! Detection functions for localhost, private IPs, and internal domains.

// Allow dead_code: These are Layer 1 primitives that will be used by observe module
#![allow(dead_code)]

use std::net::IpAddr;
use std::str::FromStr;

/// Check if value looks like an IPv4 address (simple format check)
fn is_ipv4_format(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

/// Check if value looks like an IPv6 address (simple format check)
fn is_ipv6_format(value: &str) -> bool {
    // Simple check: contains colons and parses as IPv6
    if !value.contains(':') {
        return false;
    }
    IpAddr::from_str(value)
        .map(|ip| ip.is_ipv6())
        .unwrap_or(false)
}

// ============================================================================
// Constants
// ============================================================================

/// Known localhost/loopback hostnames
const LOCALHOST_HOSTNAMES: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "[::]",
    "[::1]",
    "[0:0:0:0:0:0:0:1]",
    "0177.0.0.1", // Octal encoding
    "0x7f.0.0.1", // Hex encoding
    "2130706433", // Decimal encoding of 127.0.0.1
    "0x7f000001", // Full hex encoding
    "127.1",      // Shortened localhost
    "127.0.1",    // Shortened localhost variant
];

/// Internal/private domain TLDs and patterns
const INTERNAL_DOMAIN_PATTERNS: &[&str] = &[
    // Common internal TLDs
    ".local",
    ".internal",
    ".corp",
    ".lan",
    ".home",
    ".private",
    ".localdomain",
    ".intranet",
    // Container orchestration
    ".svc.cluster.local", // Kubernetes
    ".consul",
    ".docker",
    ".container",
];

/// Internal service hostnames
const INTERNAL_SERVICE_PATTERNS: &[&str] = &[
    "kubernetes",
    "k8s",
    "docker",
    "consul",
    "etcd",
    "vault",
    "redis",
    "mysql",
    "postgres",
    "mongodb",
    "elasticsearch",
    "rabbitmq",
    "kafka",
    "zookeeper",
    "grafana",
    "prometheus",
    "jenkins",
    "gitlab",
    "admin",
    "management",
    "internal-api",
];

// ============================================================================
// Localhost Detection
// ============================================================================

/// Check if host is localhost or loopback
///
/// Detects various forms of localhost including:
/// - Standard hostnames (localhost, 127.0.0.1, ::1)
/// - Bracketed IPv6 ([::]  [::1])
/// - Alternative encodings (octal, hex, decimal)
/// - Shortened forms (127.1)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::detection::ssrf::is_localhost;
///
/// assert!(is_localhost("localhost"));
/// assert!(is_localhost("127.0.0.1"));
/// assert!(is_localhost("::1"));
/// assert!(is_localhost("0x7f.0.0.1"));
/// assert!(!is_localhost("example.com"));
/// ```
#[must_use]
pub fn is_localhost(host: &str) -> bool {
    let lower = host.to_lowercase();
    let trimmed = lower.trim();

    // Check exact matches
    for &localhost in LOCALHOST_HOSTNAMES {
        if trimmed == localhost {
            return true;
        }
    }

    // Check for localhost with port
    if let Some(hostname) = trimmed.split(':').next() {
        for &localhost in LOCALHOST_HOSTNAMES {
            if hostname == localhost {
                return true;
            }
        }
    }

    false
}

// ============================================================================
// Internal Domain Detection
// ============================================================================

/// Check if host matches internal/private domain patterns
///
/// Detects:
/// - .local, .internal, .corp, .lan, .home, .private TLDs
/// - Container orchestration: kubernetes, k8s, docker, consul, etcd
/// - Cloud internal endpoints
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::detection::ssrf::is_internal_domain_pattern;
///
/// assert!(is_internal_domain_pattern("app.local"));
/// assert!(is_internal_domain_pattern("db.internal"));
/// assert!(is_internal_domain_pattern("kubernetes.default.svc.cluster.local"));
/// assert!(!is_internal_domain_pattern("example.com"));
/// ```
#[must_use]
pub fn is_internal_domain_pattern(host: &str) -> bool {
    let lower = host.to_lowercase();
    let trimmed = lower.trim();

    // Check internal domain TLDs
    for &pattern in INTERNAL_DOMAIN_PATTERNS {
        if trimmed.ends_with(pattern) {
            return true;
        }
    }

    // Check for internal service names at the start
    for &service in INTERNAL_SERVICE_PATTERNS {
        if trimmed.starts_with(service)
            && (trimmed.len() == service.len()
                || trimmed.as_bytes().get(service.len()) == Some(&b'.'))
        {
            return true;
        }
    }

    false
}

// ============================================================================
// Private IP Detection
// ============================================================================

/// Check if IPv4 address is in private range (RFC 1918)
///
/// Private ranges:
/// - 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
/// - 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
/// - 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
#[must_use]
pub fn is_private_ipv4_range(ip: &str) -> bool {
    if !is_ipv4_format(ip) {
        return false;
    }

    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    let octets: Vec<u8> = parts.iter().filter_map(|p| p.parse::<u8>().ok()).collect();
    if octets.len() != 4 {
        return false;
    }

    // Destructure safely
    let (o0, o1) = match octets.as_slice() {
        [a, b, _, _] => (*a, *b),
        _ => return false,
    };

    // 10.0.0.0/8
    if o0 == 10 {
        return true;
    }
    // 172.16.0.0/12
    if o0 == 172 && (16..=31).contains(&o1) {
        return true;
    }
    // 192.168.0.0/16
    if o0 == 192 && o1 == 168 {
        return true;
    }

    false
}

/// Check if IPv4 address is loopback (127.0.0.0/8)
#[must_use]
pub fn is_loopback_ipv4_range(ip: &str) -> bool {
    if !is_ipv4_format(ip) {
        return false;
    }
    ip.starts_with("127.")
}

/// Check if IPv4 address is link-local (169.254.0.0/16)
///
/// Link-local includes cloud metadata range.
#[must_use]
pub fn is_link_local_ipv4_range(ip: &str) -> bool {
    if !is_ipv4_format(ip) {
        return false;
    }
    ip.starts_with("169.254.")
}

/// Check if IPv6 address is a private/internal address
#[must_use]
pub fn is_private_ipv6(ip: &str) -> bool {
    if !is_ipv6_format(ip) {
        return false;
    }

    let lower = ip.to_lowercase();

    // Loopback
    if lower == "::1" || lower == "0:0:0:0:0:0:0:1" {
        return true;
    }

    // Link-local (fe80::/10)
    if lower.starts_with("fe80:") {
        return true;
    }

    // Unique local addresses (fc00::/7)
    if lower.starts_with("fc") || lower.starts_with("fd") {
        return true;
    }

    // Unspecified
    if lower == "::" {
        return true;
    }

    false
}

// ============================================================================
// Combined Internal Host Detection
// ============================================================================

/// Check if host is internal (localhost, private IP, or internal domain)
///
/// Combines:
/// - Localhost detection
/// - Private IP detection
/// - Internal domain pattern detection
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::detection::ssrf::is_internal_host;
///
/// assert!(is_internal_host("localhost"));
/// assert!(is_internal_host("127.0.0.1"));
/// assert!(is_internal_host("192.168.1.1"));
/// assert!(is_internal_host("db.internal"));
/// assert!(!is_internal_host("api.github.com"));
/// ```
#[must_use]
pub fn is_internal_host(host: &str) -> bool {
    let trimmed = host.trim();

    // Check localhost
    if is_localhost(trimmed) {
        return true;
    }

    // Check private IPv4
    if is_private_ipv4_range(trimmed) {
        return true;
    }

    // Check loopback IPv4
    if is_loopback_ipv4_range(trimmed) {
        return true;
    }

    // Check link-local IPv4 (includes metadata range)
    if is_link_local_ipv4_range(trimmed) {
        return true;
    }

    // Check private IPv6
    if is_private_ipv6(trimmed) {
        return true;
    }

    // Check internal domain patterns
    if is_internal_domain_pattern(trimmed) {
        return true;
    }

    // Check DNS rebinding services
    if is_dns_rebinding_service(trimmed) {
        return true;
    }

    false
}

/// Known DNS rebinding services that allow embedding IP addresses in subdomains
///
/// These services (like xip.io, nip.io, sslip.io) resolve hostnames containing
/// IP addresses to those addresses, enabling DNS rebinding attacks to bypass
/// hostname-based SSRF filters.
const DNS_REBINDING_SERVICES: &[&str] = &[
    "xip.io",
    "nip.io",
    "sslip.io",
    "localtest.me",
    "lvh.me",
    "vcap.me",
    "127-0-0-1.org",
];

/// Check if hostname uses a DNS rebinding service
///
/// DNS rebinding services allow embedding IP addresses in subdomains,
/// which then resolve to those IP addresses. For example:
/// - `127.0.0.1.xip.io` resolves to `127.0.0.1`
/// - `192-168-1-1.nip.io` resolves to `192.168.1.1`
///
/// # Example
///
/// ```ignore
/// use octarine::primitives::security::network::detection::ssrf::is_dns_rebinding_service;
///
/// assert!(is_dns_rebinding_service("127.0.0.1.xip.io"));
/// assert!(is_dns_rebinding_service("192-168-1-1.nip.io"));
/// assert!(!is_dns_rebinding_service("api.example.com"));
/// ```
#[must_use]
pub fn is_dns_rebinding_service(host: &str) -> bool {
    let lower = host.to_lowercase();
    DNS_REBINDING_SERVICES.iter().any(|&service| {
        lower.ends_with(service) || lower == service[1..] // Handle bare domain
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // --- Localhost Tests ---

    #[test]
    fn test_localhost_standard() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("127.0.0.1"));
        assert!(is_localhost("::1"));
        assert!(is_localhost("[::1]"));
    }

    #[test]
    fn test_localhost_alternative_encodings() {
        assert!(is_localhost("0x7f.0.0.1"));
        assert!(is_localhost("2130706433"));
        assert!(is_localhost("127.1"));
    }

    #[test]
    fn test_localhost_with_port() {
        assert!(is_localhost("localhost:8080"));
        assert!(is_localhost("127.0.0.1:3000"));
    }

    // --- Internal Domain Tests ---

    #[test]
    fn test_internal_domain_patterns() {
        assert!(is_internal_domain_pattern("app.local"));
        assert!(is_internal_domain_pattern("db.internal"));
        assert!(is_internal_domain_pattern("service.corp"));
        assert!(is_internal_domain_pattern("device.lan"));
        assert!(!is_internal_domain_pattern("example.com"));
    }

    #[test]
    fn test_kubernetes_domains() {
        assert!(is_internal_domain_pattern(
            "myservice.default.svc.cluster.local"
        ));
        assert!(is_internal_domain_pattern("kubernetes.docker"));
    }

    #[test]
    fn test_internal_service_names() {
        assert!(is_internal_domain_pattern("kubernetes"));
        assert!(is_internal_domain_pattern("redis.cache"));
        assert!(is_internal_domain_pattern("consul"));
        assert!(is_internal_domain_pattern("vault.secrets"));
    }

    // --- Private IP Tests ---

    #[test]
    fn test_private_ipv4() {
        assert!(is_private_ipv4_range("10.0.0.1"));
        assert!(is_private_ipv4_range("10.255.255.255"));
        assert!(is_private_ipv4_range("172.16.0.1"));
        assert!(is_private_ipv4_range("172.31.255.255"));
        assert!(is_private_ipv4_range("192.168.0.1"));
        assert!(is_private_ipv4_range("192.168.255.255"));
        assert!(!is_private_ipv4_range("8.8.8.8"));
        assert!(!is_private_ipv4_range("172.15.0.1")); // Just outside range
        assert!(!is_private_ipv4_range("172.32.0.1")); // Just outside range
    }

    #[test]
    fn test_loopback_ipv4() {
        assert!(is_loopback_ipv4_range("127.0.0.1"));
        assert!(is_loopback_ipv4_range("127.255.255.255"));
        assert!(!is_loopback_ipv4_range("128.0.0.1"));
    }

    #[test]
    fn test_link_local_ipv4() {
        assert!(is_link_local_ipv4_range("169.254.0.1"));
        assert!(is_link_local_ipv4_range("169.254.169.254")); // Metadata IP
        assert!(!is_link_local_ipv4_range("169.255.0.1"));
    }

    #[test]
    fn test_private_ipv6() {
        assert!(is_private_ipv6("::1"));
        assert!(is_private_ipv6("fe80::1"));
        assert!(is_private_ipv6("fd00::1"));
        assert!(!is_private_ipv6("2001:db8::1"));
    }

    // --- Internal Host Combined Tests ---

    #[test]
    fn test_internal_host() {
        // Localhost
        assert!(is_internal_host("localhost"));
        assert!(is_internal_host("127.0.0.1"));

        // Private IPs
        assert!(is_internal_host("192.168.1.1"));
        assert!(is_internal_host("10.0.0.1"));

        // Internal domains
        assert!(is_internal_host("db.internal"));

        // Not internal
        assert!(!is_internal_host("api.github.com"));
        assert!(!is_internal_host("8.8.8.8"));
    }
}
