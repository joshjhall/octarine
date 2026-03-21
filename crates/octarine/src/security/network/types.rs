//! Public types for network security operations
//!
//! These types form the public API for network security validation.
//! They wrap the internal primitives types for the stable public API.
//!
//! # Why Wrapper Types?
//!
//! Wrapper types are necessary for two reasons:
//! 1. **Visibility bridging**: Primitives are `pub(crate)`, so we can't directly
//!    re-export them as `pub`. Wrapper types provide the public API surface.
//! 2. **API stability**: Wrappers allow the public API to evolve independently
//!    from internal primitives.
//!
//! # Naming Convention
//!
//! Types are namespaced under their submodule:
//! - `octarine::data::network::HostType` (public)
//! - `crate::primitives::security::network::HostType` (internal)

// ============================================================================
// Host Classification
// ============================================================================

/// Type of host identifier
///
/// Used to classify whether a host string is an IP address or domain name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostType {
    /// IPv4 address (e.g., 192.168.1.1)
    Ipv4,
    /// IPv6 address (e.g., ::1, 2001:db8::1)
    Ipv6,
    /// Domain name (e.g., example.com)
    Domain,
    /// Unknown or invalid
    Unknown,
}

impl std::fmt::Display for HostType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4 => write!(f, "IPv4"),
            Self::Ipv6 => write!(f, "IPv6"),
            Self::Domain => write!(f, "Domain"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl From<crate::primitives::security::network::HostType> for HostType {
    fn from(h: crate::primitives::security::network::HostType) -> Self {
        match h {
            crate::primitives::security::network::HostType::Ipv4 => Self::Ipv4,
            crate::primitives::security::network::HostType::Ipv6 => Self::Ipv6,
            crate::primitives::security::network::HostType::Domain => Self::Domain,
            crate::primitives::security::network::HostType::Unknown => Self::Unknown,
        }
    }
}

// ============================================================================
// Port Range
// ============================================================================

/// Port range specification
///
/// Used for port classification and validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortRange {
    /// All valid ports (1-65535)
    #[default]
    All,
    /// Well-known ports (0-1023) - require root/admin
    WellKnown,
    /// Registered ports (1024-49151)
    Registered,
    /// Dynamic/private ports (49152-65535)
    Dynamic,
    /// User-defined range
    Custom {
        /// Minimum port in range
        min: u16,
        /// Maximum port in range
        max: u16,
    },
}

impl PortRange {
    /// Create a custom port range
    #[must_use]
    pub fn custom(min: u16, max: u16) -> Self {
        Self::Custom { min, max }
    }

    /// Classify a port number into its range
    #[must_use]
    pub fn classify(port: u16) -> Self {
        match port {
            0..=1023 => Self::WellKnown,
            1024..=49151 => Self::Registered,
            49152..=65535 => Self::Dynamic,
        }
    }

    /// Check if a port is within this range
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        match self {
            Self::All => port >= 1,
            Self::WellKnown => port <= 1023,
            Self::Registered => (1024..=49151).contains(&port),
            Self::Dynamic => port >= 49152,
            Self::Custom { min, max } => (*min..=*max).contains(&port),
        }
    }
}

impl std::fmt::Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => write!(f, "All (1-65535)"),
            Self::WellKnown => write!(f, "Well-Known (0-1023)"),
            Self::Registered => write!(f, "Registered (1024-49151)"),
            Self::Dynamic => write!(f, "Dynamic (49152-65535)"),
            Self::Custom { min, max } => write!(f, "Custom ({min}-{max})"),
        }
    }
}

impl From<crate::primitives::security::network::PortRange> for PortRange {
    fn from(p: crate::primitives::security::network::PortRange) -> Self {
        match p {
            crate::primitives::security::network::PortRange::All => Self::All,
            crate::primitives::security::network::PortRange::WellKnown => Self::WellKnown,
            crate::primitives::security::network::PortRange::Registered => Self::Registered,
            crate::primitives::security::network::PortRange::Dynamic => Self::Dynamic,
            crate::primitives::security::network::PortRange::Custom { min, max } => {
                Self::Custom { min, max }
            }
        }
    }
}

impl From<PortRange> for crate::primitives::security::network::PortRange {
    fn from(p: PortRange) -> Self {
        match p {
            PortRange::All => Self::All,
            PortRange::WellKnown => Self::WellKnown,
            PortRange::Registered => Self::Registered,
            PortRange::Dynamic => Self::Dynamic,
            PortRange::Custom { min, max } => Self::Custom { min, max },
        }
    }
}

// ============================================================================
// Network Security Hostname Config
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
    /// Create strict RFC-compliant config
    #[must_use]
    pub fn strict() -> Self {
        Self::default()
    }

    /// Create lenient config (allows underscores)
    #[must_use]
    pub fn lenient() -> Self {
        Self {
            allow_underscores: true,
            ..Default::default()
        }
    }
}

impl From<&NetworkSecurityHostnameConfig>
    for crate::primitives::security::network::NetworkSecurityHostnameConfig
{
    fn from(config: &NetworkSecurityHostnameConfig) -> Self {
        Self {
            max_length: config.max_length,
            max_label_length: config.max_label_length,
            allow_underscores: config.allow_underscores,
            allow_numeric_labels: config.allow_numeric_labels,
        }
    }
}

// ============================================================================
// Network Security URL Config
// ============================================================================

/// Configuration for URL validation
#[derive(Debug, Clone)]
pub struct NetworkSecurityUrlConfig {
    /// Require HTTPS only (block HTTP)
    pub require_https: bool,
    /// Maximum URL length
    pub max_length: usize,
    /// Allowed URL schemes
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
    /// Create config requiring HTTPS only
    #[must_use]
    pub fn https_only() -> Self {
        Self {
            require_https: true,
            allowed_schemes: vec!["https".to_string()],
            ..Default::default()
        }
    }

    /// Create strict config (HTTPS, shorter max length)
    #[must_use]
    pub fn strict() -> Self {
        Self {
            require_https: true,
            max_length: 1024,
            allowed_schemes: vec!["https".to_string()],
        }
    }
}

impl From<&NetworkSecurityUrlConfig>
    for crate::primitives::security::network::NetworkSecurityUrlConfig
{
    fn from(config: &NetworkSecurityUrlConfig) -> Self {
        Self {
            require_https: config.require_https,
            max_length: config.max_length,
            allowed_schemes: config.allowed_schemes.clone(),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_type_display() {
        assert_eq!(format!("{}", HostType::Ipv4), "IPv4");
        assert_eq!(format!("{}", HostType::Domain), "Domain");
    }

    #[test]
    fn test_port_range_classify() {
        assert_eq!(PortRange::classify(80), PortRange::WellKnown);
        assert_eq!(PortRange::classify(8080), PortRange::Registered);
    }

    #[test]
    fn test_hostname_config() {
        let strict = NetworkSecurityHostnameConfig::strict();
        assert!(!strict.allow_underscores);

        let lenient = NetworkSecurityHostnameConfig::lenient();
        assert!(lenient.allow_underscores);
    }

    #[test]
    fn test_url_config() {
        let default = NetworkSecurityUrlConfig::default();
        assert!(!default.require_https);

        let https = NetworkSecurityUrlConfig::https_only();
        assert!(https.require_https);
    }
}
