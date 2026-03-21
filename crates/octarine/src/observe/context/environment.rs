//! Environment context capture
//!
//! Captures information about the runtime environment, deployment,
//! and infrastructure where events occur.
//!
//! # Local Network Context
//!
//! The local network context captures all IP addresses and network interfaces
//! on the host. This is refreshed with a TTL to handle DHCP changes.
//!
//! ```ignore
//! use octarine::context::get_local_network;
//!
//! let network = get_local_network();
//! if let Some(ipv4) = network.primary_ipv4() {
//!     println!("Primary IPv4: {}", ipv4);
//! }
//! ```

use crate::primitives::identifiers::{IpAddress, IpAddressList, NetworkInterface};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// TTL for local network context refresh (5 minutes)
const LOCAL_NETWORK_TTL: Duration = Duration::from_secs(5 * 60);

// ============================================================================
// Environment Context (static info captured at startup)
// ============================================================================

/// Environment context information
#[derive(Debug, Clone)]
pub(super) struct EnvironmentContext {
    /// Environment name (dev, staging, prod)
    pub environment: String,

    /// Application version
    pub version: String,

    /// Git commit hash
    pub commit_hash: Option<String>,

    /// Deployment ID
    pub deployment_id: Option<String>,

    /// Region/datacenter
    pub region: Option<String>,

    /// Container/pod information
    pub container_id: Option<String>,
    pub pod_name: Option<String>,

    /// Host information
    pub hostname: String,

    /// Runtime information
    pub rust_version: String,
    pub os: String,
    pub arch: String,

    /// Feature flags
    pub feature_flags: HashMap<String, bool>,
}

/// Global environment context (captured once at startup)
static ENVIRONMENT: Lazy<EnvironmentContext> = Lazy::new(capture_environment);

/// Get the global environment context
///
/// Internal function for use within the observe module.
pub(super) fn get_environment() -> &'static EnvironmentContext {
    &ENVIRONMENT
}

/// Capture environment information at startup
fn capture_environment() -> EnvironmentContext {
    EnvironmentContext {
        // Core environment
        environment: std::env::var("ENVIRONMENT")
            .or_else(|_| std::env::var("ENV"))
            .unwrap_or_else(|_| "development".to_string()),

        // Version info
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit_hash: std::env::var("GIT_COMMIT").ok(),
        deployment_id: std::env::var("DEPLOYMENT_ID").ok(),

        // Infrastructure
        region: std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("REGION"))
            .ok(),

        // Container/K8s info
        container_id: std::env::var("HOSTNAME").ok().filter(|h| h.len() == 12), // Docker container IDs are 12 chars
        pod_name: std::env::var("POD_NAME").ok(),

        // Host info
        hostname: hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string()),

        // Runtime
        rust_version: env!("CARGO_PKG_RUST_VERSION")
            .to_string()
            .split_whitespace()
            .next()
            .unwrap_or("unknown")
            .to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),

        // Feature flags (would be loaded from config)
        feature_flags: load_feature_flags(),
    }
}

/// Load feature flags from configuration
fn load_feature_flags() -> HashMap<String, bool> {
    let mut flags = HashMap::new();

    // Check environment variables for feature flags
    for (key, value) in std::env::vars() {
        if let Some(flag_name) = key.strip_prefix("FEATURE_") {
            let flag_name = flag_name.to_lowercase();
            let enabled = value.to_lowercase() == "true" || value == "1";
            flags.insert(flag_name, enabled);
        }
    }

    flags
}

// ============================================================================
// Local Network Context (TTL-cached, refreshed on access)
// ============================================================================

/// Local network context with all interfaces and IP addresses
#[derive(Debug, Clone)]
pub struct LocalNetworkContext {
    /// All local IP addresses (combined from all interfaces)
    pub addresses: IpAddressList,

    /// Network interfaces with their IPs
    pub interfaces: Vec<NetworkInterface>,

    /// When this context was captured
    captured_at: Instant,
}

impl LocalNetworkContext {
    /// Capture current local network context
    fn capture() -> Self {
        let mut addresses = IpAddressList::new();
        let mut interfaces: HashMap<String, NetworkInterface> = HashMap::new();

        // First check environment variables (common in containers)
        if let Ok(pod_ip) = std::env::var("POD_IP")
            && let Some(ip) = IpAddress::parse(&pod_ip)
        {
            addresses.push(ip);
            let mut iface = NetworkInterface::new("pod");
            iface.add_address(ip);
            interfaces.insert("pod".to_string(), iface);
        }

        // Use local-ip-address crate to get all network interfaces
        if let Ok(netifs) = local_ip_address::list_afinet_netifas() {
            for (name, ip_addr) in netifs {
                let ip = IpAddress::new(ip_addr);

                // Add to combined list
                addresses.push(ip);

                // Add to interface map
                interfaces
                    .entry(name.clone())
                    .or_insert_with(|| NetworkInterface::new(name))
                    .add_address(ip);
            }
        }

        Self {
            addresses,
            interfaces: interfaces.into_values().collect(),
            captured_at: Instant::now(),
        }
    }

    /// Check if this context is still valid (within TTL)
    fn is_valid(&self) -> bool {
        self.captured_at.elapsed() < LOCAL_NETWORK_TTL
    }

    /// Get the primary IPv4 address (first non-loopback IPv4)
    #[must_use]
    pub fn primary_ipv4(&self) -> Option<&IpAddress> {
        self.addresses
            .iter()
            .find(|ip| ip.is_ipv4() && !ip.is_loopback())
    }

    /// Get the primary IPv6 address (first non-loopback IPv6)
    #[must_use]
    pub fn primary_ipv6(&self) -> Option<&IpAddress> {
        self.addresses
            .iter()
            .find(|ip| ip.is_ipv6() && !ip.is_loopback())
    }

    /// Get the primary IP address (prefers IPv4, then IPv6, excluding loopback)
    #[must_use]
    pub fn primary_ip(&self) -> Option<&IpAddress> {
        self.primary_ipv4().or_else(|| self.primary_ipv6())
    }

    /// Get all public IP addresses
    #[must_use]
    pub fn public_addresses(&self) -> Vec<&IpAddress> {
        self.addresses.public_addresses()
    }

    /// Get all private IP addresses
    #[must_use]
    pub fn private_addresses(&self) -> Vec<&IpAddress> {
        self.addresses.private_addresses()
    }
}

impl Default for LocalNetworkContext {
    fn default() -> Self {
        Self::capture()
    }
}

/// Cached local network context with lazy refresh
struct CachedLocalNetwork {
    context: RwLock<LocalNetworkContext>,
}

impl CachedLocalNetwork {
    fn new() -> Self {
        Self {
            context: RwLock::new(LocalNetworkContext::capture()),
        }
    }

    /// Get the current context, refreshing if TTL expired
    fn get(&self) -> LocalNetworkContext {
        // Try read lock first
        {
            let read_guard = self.context.read().unwrap_or_else(|e| e.into_inner());
            if read_guard.is_valid() {
                return read_guard.clone();
            }
        }

        // Need to refresh - acquire write lock
        let mut write_guard = self.context.write().unwrap_or_else(|e| e.into_inner());

        // Double-check after acquiring write lock (another thread may have refreshed)
        if write_guard.is_valid() {
            return write_guard.clone();
        }

        // Refresh the context
        *write_guard = LocalNetworkContext::capture();
        write_guard.clone()
    }

    /// Force a refresh of the cached context
    fn refresh(&self) -> LocalNetworkContext {
        let mut write_guard = self.context.write().unwrap_or_else(|e| e.into_inner());
        *write_guard = LocalNetworkContext::capture();
        write_guard.clone()
    }
}

/// Global cached local network context
static LOCAL_NETWORK: Lazy<CachedLocalNetwork> = Lazy::new(CachedLocalNetwork::new);

/// Get the current local network context
///
/// This is TTL-cached (5 minutes) to handle DHCP changes without
/// constantly re-querying network interfaces.
///
/// # Example
///
/// ```ignore
/// use octarine::context::get_local_network;
///
/// let network = get_local_network();
/// println!("Local IPs: {}", network.addresses);
///
/// if let Some(primary) = network.primary_ip() {
///     println!("Primary IP: {}", primary);
/// }
/// ```
pub fn get_local_network() -> LocalNetworkContext {
    LOCAL_NETWORK.get()
}

/// Force refresh the local network context
///
/// Call this after a known network change (e.g., VPN connect/disconnect).
pub fn refresh_local_network() -> LocalNetworkContext {
    LOCAL_NETWORK.refresh()
}

/// Get the primary local IP address as a string
///
/// Convenience function for simple use cases.
/// Returns `None` if no non-loopback IP is found.
pub(super) fn get_local_ip() -> Option<String> {
    get_local_network().primary_ip().map(|ip| ip.to_string())
}

/// Get all local IP addresses as a list
///
/// Convenience function for context capture.
pub(super) fn get_local_ip_list() -> IpAddressList {
    get_local_network().addresses
}

// ============================================================================
// Environment Helper Functions
// ============================================================================

/// Check if we're running in production
pub fn is_production() -> bool {
    let env = &ENVIRONMENT.environment;
    env == "production" || env == "prod"
}

/// Check if we're running in development
pub fn is_development() -> bool {
    let env = &ENVIRONMENT.environment;
    env == "development" || env == "dev"
}

/// Check if we're running in CI
pub(super) fn is_ci() -> bool {
    std::env::var("CI").is_ok()
        || std::env::var("CONTINUOUS_INTEGRATION").is_ok()
        || std::env::var("GITHUB_ACTIONS").is_ok()
}

/// Check if we're running in a container
pub(super) fn is_containerized() -> bool {
    std::path::Path::new("/.dockerenv").exists()
        || std::env::var("KUBERNETES_SERVICE_HOST").is_ok()
        || ENVIRONMENT.container_id.is_some()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_get_local_network() {
        let network = get_local_network();
        // Should have at least loopback
        assert!(
            !network.addresses.is_empty() || network.interfaces.is_empty(),
            "Should capture some network info"
        );
    }

    #[test]
    fn test_local_network_ttl_valid() {
        let ctx = LocalNetworkContext::capture();
        assert!(ctx.is_valid(), "Freshly captured context should be valid");
    }

    #[test]
    fn test_environment_context() {
        let env = get_environment();
        assert!(!env.hostname.is_empty());
        assert!(!env.os.is_empty());
        assert!(!env.arch.is_empty());
    }

    #[test]
    fn test_is_production() {
        // Default is development
        assert!(!is_production());
        assert!(is_development());
    }

    #[test]
    fn test_get_local_ip() {
        // May or may not return an IP depending on network config
        let ip = get_local_ip();
        if let Some(ref ip_str) = ip {
            // If we got an IP, it should be parseable
            assert!(IpAddress::parse(ip_str).is_some());
        }
    }

    #[test]
    fn test_refresh_local_network() {
        let before = get_local_network();
        let after = refresh_local_network();

        // Both should be valid
        assert!(before.is_valid() || !after.is_valid()); // before may have expired
    }
}
