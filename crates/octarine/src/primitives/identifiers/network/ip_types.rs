//! IP address types for validated network addresses
//!
//! Provides strongly-typed IP address primitives that wrap `std::net::IpAddr`
//! with classification methods and serialization support.
//!
//! # Use Cases
//!
//! - **Observability**: Capture local and remote IPs in audit events
//! - **Validation**: Ensure IP addresses are valid before use
//! - **Classification**: Distinguish private, public, loopback, etc.
//!
//! # Example
//!
//! ```ignore
//! // Internal module - access via observe::get_local_network() API
//! use octarine::primitives::identifiers::network::{IpAddress, IpAddressList};
//!
//! // Parse and classify an IP
//! let ip = IpAddress::parse("192.168.1.1").unwrap();
//! assert!(ip.is_private());
//! assert!(!ip.is_public());
//!
//! // Collect multiple IPs
//! let mut list = IpAddressList::new();
//! list.push(ip);
//! list.push(IpAddress::parse("10.0.0.1").unwrap());
//! assert_eq!(list.ipv4_count(), 2);
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

// ============================================================================
// IpAddress - Single validated IP address
// ============================================================================

/// A validated IP address (IPv4 or IPv6)
///
/// Wraps `std::net::IpAddr` with additional classification methods
/// and serialization support for use in observability and validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IpAddress(IpAddr);

impl IpAddress {
    /// Create from a `std::net::IpAddr`
    #[must_use]
    pub fn new(addr: IpAddr) -> Self {
        Self(addr)
    }

    /// Create from an IPv4 address
    #[must_use]
    pub fn from_ipv4(addr: Ipv4Addr) -> Self {
        Self(IpAddr::V4(addr))
    }

    /// Create from an IPv6 address
    #[must_use]
    pub fn from_ipv6(addr: Ipv6Addr) -> Self {
        Self(IpAddr::V6(addr))
    }

    /// Parse from a string
    ///
    /// Returns `None` if the string is not a valid IP address.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        IpAddr::from_str(s.trim()).ok().map(Self)
    }

    /// Get the underlying `std::net::IpAddr`
    #[must_use]
    pub fn inner(&self) -> IpAddr {
        self.0
    }

    /// Check if this is an IPv4 address
    #[must_use]
    pub fn is_ipv4(&self) -> bool {
        self.0.is_ipv4()
    }

    /// Check if this is an IPv6 address
    #[must_use]
    pub fn is_ipv6(&self) -> bool {
        self.0.is_ipv6()
    }

    /// Check if this is a loopback address (127.x.x.x or ::1)
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        self.0.is_loopback()
    }

    /// Check if this is an unspecified address (0.0.0.0 or ::)
    #[must_use]
    pub fn is_unspecified(&self) -> bool {
        self.0.is_unspecified()
    }

    /// Check if this is a private/internal network address
    ///
    /// Includes:
    /// - IPv4: 10.x.x.x, 172.16-31.x.x, 192.168.x.x (RFC 1918)
    /// - IPv6: fc00::/7 unique local addresses (RFC 4193)
    #[must_use]
    pub fn is_private(&self) -> bool {
        match self.0 {
            IpAddr::V4(ipv4) => ipv4.is_private(),
            IpAddr::V6(ipv6) => {
                // fc00::/7 - unique local addresses
                let segments = ipv6.segments();
                (segments[0] & 0xfe00) == 0xfc00
            }
        }
    }

    /// Check if this is a link-local address
    ///
    /// - IPv4: 169.254.x.x (RFC 3927)
    /// - IPv6: fe80::/10 (RFC 4291)
    #[must_use]
    pub fn is_link_local(&self) -> bool {
        match self.0 {
            IpAddr::V4(ipv4) => ipv4.is_link_local(),
            IpAddr::V6(ipv6) => {
                // fe80::/10
                let segments = ipv6.segments();
                (segments[0] & 0xffc0) == 0xfe80
            }
        }
    }

    /// Check if this is a multicast address
    #[must_use]
    pub fn is_multicast(&self) -> bool {
        self.0.is_multicast()
    }

    /// Check if this is a broadcast address (255.255.255.255)
    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        match self.0 {
            IpAddr::V4(ipv4) => ipv4.is_broadcast(),
            IpAddr::V6(_) => false, // IPv6 doesn't have broadcast
        }
    }

    /// Check if this is a documentation/example address
    ///
    /// - IPv4: 192.0.2.x, 198.51.100.x, 203.0.113.x (RFC 5737)
    /// - IPv6: 2001:db8::/32 (RFC 3849)
    #[must_use]
    pub fn is_documentation(&self) -> bool {
        match self.0 {
            IpAddr::V4(ipv4) => ipv4.is_documentation(),
            IpAddr::V6(ipv6) => {
                // 2001:db8::/32
                let segments = ipv6.segments();
                segments[0] == 0x2001 && segments[1] == 0x0db8
            }
        }
    }

    /// Check if this is a globally routable (public) address
    ///
    /// Returns true if the address is not:
    /// - Loopback, unspecified, private, link-local
    /// - Multicast, broadcast, documentation
    #[must_use]
    pub fn is_public(&self) -> bool {
        !self.is_loopback()
            && !self.is_unspecified()
            && !self.is_private()
            && !self.is_link_local()
            && !self.is_multicast()
            && !self.is_broadcast()
            && !self.is_documentation()
    }

    /// Check if this is a cloud metadata endpoint
    ///
    /// These addresses are security-sensitive as they can leak cloud credentials:
    /// - 169.254.169.254 (AWS, GCP, Azure IMDS)
    /// - 169.254.170.2 (AWS ECS task metadata)
    /// - fd00:ec2::254 (AWS IMDSv2 IPv6)
    #[must_use]
    pub fn is_cloud_metadata(&self) -> bool {
        match self.0 {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // 169.254.169.254 - AWS/GCP/Azure IMDS
                (octets == [169, 254, 169, 254])
                    // 169.254.170.2 - AWS ECS task metadata
                    || (octets == [169, 254, 170, 2])
            }
            IpAddr::V6(ipv6) => {
                // fd00:ec2::254 - AWS IMDSv2 IPv6
                let segments = ipv6.segments();
                segments[0] == 0xfd00
                    && segments[1] == 0x0ec2
                    && segments[2..7] == [0, 0, 0, 0, 0]
                    && segments[7] == 0x0254
            }
        }
    }

    /// Get the classification of this IP address
    #[must_use]
    pub fn classification(&self) -> IpClassification {
        if self.is_loopback() {
            IpClassification::Loopback
        } else if self.is_unspecified() {
            IpClassification::Unspecified
        } else if self.is_cloud_metadata() {
            IpClassification::CloudMetadata
        } else if self.is_private() {
            IpClassification::Private
        } else if self.is_link_local() {
            IpClassification::LinkLocal
        } else if self.is_multicast() {
            IpClassification::Multicast
        } else if self.is_broadcast() {
            IpClassification::Broadcast
        } else if self.is_documentation() {
            IpClassification::Documentation
        } else {
            IpClassification::Public
        }
    }

    /// Convert to IPv4 if possible
    #[must_use]
    pub fn to_ipv4(self) -> Option<Ipv4Addr> {
        match self.0 {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(v6) => v6.to_ipv4(),
        }
    }

    /// Convert to IPv6
    ///
    /// IPv4 addresses are converted to IPv4-mapped IPv6 (::ffff:x.x.x.x)
    #[must_use]
    pub fn to_ipv6(self) -> Ipv6Addr {
        match self.0 {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        }
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<IpAddr> for IpAddress {
    fn from(addr: IpAddr) -> Self {
        Self(addr)
    }
}

impl From<Ipv4Addr> for IpAddress {
    fn from(addr: Ipv4Addr) -> Self {
        Self::from_ipv4(addr)
    }
}

impl From<Ipv6Addr> for IpAddress {
    fn from(addr: Ipv6Addr) -> Self {
        Self::from_ipv6(addr)
    }
}

impl From<IpAddress> for IpAddr {
    fn from(addr: IpAddress) -> Self {
        addr.0
    }
}

impl FromStr for IpAddress {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IpAddr::from_str(s.trim()).map(Self)
    }
}

// ============================================================================
// IpClassification - IP address category
// ============================================================================

/// Classification of an IP address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpClassification {
    /// Loopback address (127.x.x.x, ::1)
    Loopback,
    /// Unspecified address (0.0.0.0, ::)
    Unspecified,
    /// Private network (RFC 1918, RFC 4193)
    Private,
    /// Link-local address (169.254.x.x, fe80::/10)
    LinkLocal,
    /// Multicast address
    Multicast,
    /// Broadcast address (255.255.255.255)
    Broadcast,
    /// Documentation/example address (RFC 5737, RFC 3849)
    Documentation,
    /// Cloud metadata endpoint (security-sensitive)
    CloudMetadata,
    /// Globally routable public address
    Public,
}

impl IpClassification {
    /// Check if this classification represents an internal/non-routable address
    #[must_use]
    pub fn is_internal(&self) -> bool {
        matches!(
            self,
            Self::Loopback
                | Self::Unspecified
                | Self::Private
                | Self::LinkLocal
                | Self::Documentation
        )
    }

    /// Check if this classification is security-sensitive
    #[must_use]
    pub fn is_security_sensitive(&self) -> bool {
        matches!(self, Self::CloudMetadata)
    }
}

impl fmt::Display for IpClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Loopback => "loopback",
            Self::Unspecified => "unspecified",
            Self::Private => "private",
            Self::LinkLocal => "link-local",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Documentation => "documentation",
            Self::CloudMetadata => "cloud-metadata",
            Self::Public => "public",
        };
        write!(f, "{s}")
    }
}

// ============================================================================
// IpAddressList - Collection of IP addresses
// ============================================================================

/// A collection of IP addresses
///
/// Used to represent multiple IPs on a host (multiple NICs, IPv4+IPv6),
/// or a chain of IPs (X-Forwarded-For proxy chain).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpAddressList {
    addresses: Vec<IpAddress>,
}

impl IpAddressList {
    /// Create an empty list
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from a vector of IP addresses
    #[must_use]
    pub fn from_vec(addresses: Vec<IpAddress>) -> Self {
        Self { addresses }
    }

    /// Create from an iterator of parseable strings
    ///
    /// Invalid addresses are skipped.
    pub fn parse_all<'a>(iter: impl IntoIterator<Item = &'a str>) -> Self {
        let addresses = iter.into_iter().filter_map(IpAddress::parse).collect();
        Self { addresses }
    }

    /// Add an IP address to the list
    pub fn push(&mut self, addr: IpAddress) {
        self.addresses.push(addr);
    }

    /// Check if the list is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Get the number of addresses
    #[must_use]
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Get all addresses as a slice
    #[must_use]
    pub fn as_slice(&self) -> &[IpAddress] {
        &self.addresses
    }

    /// Get the first address (if any)
    #[must_use]
    pub fn first(&self) -> Option<&IpAddress> {
        self.addresses.first()
    }

    /// Get the primary IPv4 address (first IPv4 found)
    #[must_use]
    pub fn primary_ipv4(&self) -> Option<&IpAddress> {
        self.addresses.iter().find(|ip| ip.is_ipv4())
    }

    /// Get the primary IPv6 address (first IPv6 found)
    #[must_use]
    pub fn primary_ipv6(&self) -> Option<&IpAddress> {
        self.addresses.iter().find(|ip| ip.is_ipv6())
    }

    /// Get all IPv4 addresses
    #[must_use]
    pub fn ipv4_addresses(&self) -> Vec<&IpAddress> {
        self.addresses.iter().filter(|ip| ip.is_ipv4()).collect()
    }

    /// Get all IPv6 addresses
    #[must_use]
    pub fn ipv6_addresses(&self) -> Vec<&IpAddress> {
        self.addresses.iter().filter(|ip| ip.is_ipv6()).collect()
    }

    /// Count IPv4 addresses
    #[must_use]
    pub fn ipv4_count(&self) -> usize {
        self.addresses.iter().filter(|ip| ip.is_ipv4()).count()
    }

    /// Count IPv6 addresses
    #[must_use]
    pub fn ipv6_count(&self) -> usize {
        self.addresses.iter().filter(|ip| ip.is_ipv6()).count()
    }

    /// Get all public addresses
    #[must_use]
    pub fn public_addresses(&self) -> Vec<&IpAddress> {
        self.addresses.iter().filter(|ip| ip.is_public()).collect()
    }

    /// Get all private addresses
    #[must_use]
    pub fn private_addresses(&self) -> Vec<&IpAddress> {
        self.addresses.iter().filter(|ip| ip.is_private()).collect()
    }

    /// Check if any address is a cloud metadata endpoint
    #[must_use]
    pub fn is_cloud_metadata_present(&self) -> bool {
        self.addresses.iter().any(|ip| ip.is_cloud_metadata())
    }

    /// Convert to a comma-separated string
    #[must_use]
    pub fn to_comma_string(&self) -> String {
        self.addresses
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Iterate over addresses
    pub fn iter(&self) -> impl Iterator<Item = &IpAddress> {
        self.addresses.iter()
    }
}

impl IntoIterator for IpAddressList {
    type Item = IpAddress;
    type IntoIter = std::vec::IntoIter<IpAddress>;

    fn into_iter(self) -> Self::IntoIter {
        self.addresses.into_iter()
    }
}

impl<'a> IntoIterator for &'a IpAddressList {
    type Item = &'a IpAddress;
    type IntoIter = std::slice::Iter<'a, IpAddress>;

    fn into_iter(self) -> Self::IntoIter {
        self.addresses.iter()
    }
}

impl FromIterator<IpAddress> for IpAddressList {
    fn from_iter<T: IntoIterator<Item = IpAddress>>(iter: T) -> Self {
        Self {
            addresses: iter.into_iter().collect(),
        }
    }
}

impl fmt::Display for IpAddressList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_comma_string())
    }
}

// ============================================================================
// NetworkInterface - Interface with its IPs
// ============================================================================

/// A network interface with its associated IP addresses
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// Interface name (e.g., "eth0", "en0", "wlan0")
    pub name: String,
    /// IP addresses assigned to this interface
    pub addresses: IpAddressList,
}

impl NetworkInterface {
    /// Create a new network interface
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            addresses: IpAddressList::new(),
        }
    }

    /// Add an IP address to this interface
    pub fn add_address(&mut self, addr: IpAddress) {
        self.addresses.push(addr);
    }

    /// Check if this interface has any addresses
    #[must_use]
    pub fn is_address_present(&self) -> bool {
        !self.addresses.is_empty()
    }

    /// Check if this is a loopback interface
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        // Common loopback interface names
        self.name == "lo" || self.name == "lo0" || self.name.starts_with("loopback")
    }
}

impl fmt::Display for NetworkInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.addresses)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_address_parse() {
        assert!(IpAddress::parse("192.168.1.1").is_some());
        assert!(IpAddress::parse("::1").is_some());
        assert!(IpAddress::parse("2001:db8::1").is_some());
        assert!(IpAddress::parse("invalid").is_none());
        assert!(IpAddress::parse("").is_none());
    }

    #[test]
    fn test_ip_address_classification() {
        // Loopback
        let lo4 = IpAddress::parse("127.0.0.1").expect("valid");
        assert!(lo4.is_loopback());
        assert_eq!(lo4.classification(), IpClassification::Loopback);

        let lo6 = IpAddress::parse("::1").expect("valid");
        assert!(lo6.is_loopback());

        // Private
        let priv1 = IpAddress::parse("10.0.0.1").expect("valid");
        assert!(priv1.is_private());
        assert_eq!(priv1.classification(), IpClassification::Private);

        let priv2 = IpAddress::parse("192.168.1.1").expect("valid");
        assert!(priv2.is_private());

        let priv3 = IpAddress::parse("172.16.0.1").expect("valid");
        assert!(priv3.is_private());

        // Public
        let pub1 = IpAddress::parse("8.8.8.8").expect("valid");
        assert!(pub1.is_public());
        assert_eq!(pub1.classification(), IpClassification::Public);

        // Link-local
        let link = IpAddress::parse("169.254.1.1").expect("valid");
        assert!(link.is_link_local());
        assert_eq!(link.classification(), IpClassification::LinkLocal);

        // Cloud metadata
        let meta = IpAddress::parse("169.254.169.254").expect("valid");
        assert!(meta.is_cloud_metadata());
        assert_eq!(meta.classification(), IpClassification::CloudMetadata);

        // Documentation
        let doc = IpAddress::parse("192.0.2.1").expect("valid");
        assert!(doc.is_documentation());
        assert_eq!(doc.classification(), IpClassification::Documentation);
    }

    #[test]
    fn test_ip_address_list() {
        let mut list = IpAddressList::new();
        list.push(IpAddress::parse("192.168.1.1").expect("valid"));
        list.push(IpAddress::parse("10.0.0.1").expect("valid"));
        list.push(IpAddress::parse("::1").expect("valid"));

        assert_eq!(list.len(), 3);
        assert_eq!(list.ipv4_count(), 2);
        assert_eq!(list.ipv6_count(), 1);
        assert!(list.primary_ipv4().is_some());
        assert!(list.primary_ipv6().is_some());
    }

    #[test]
    fn test_ip_address_list_parse_all() {
        let list = IpAddressList::parse_all(["192.168.1.1", "invalid", "10.0.0.1", "::1"]);
        assert_eq!(list.len(), 3); // "invalid" is skipped
    }

    #[test]
    fn test_ip_address_serialization() {
        let ip = IpAddress::parse("192.168.1.1").expect("valid");
        let json = serde_json::to_string(&ip).expect("serialize");
        assert_eq!(json, "\"192.168.1.1\"");

        let parsed: IpAddress = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, ip);
    }

    #[test]
    fn test_ip_address_list_serialization() {
        let list = IpAddressList::parse_all(["192.168.1.1", "10.0.0.1"]);
        let json = serde_json::to_string(&list).expect("serialize");
        assert!(json.contains("192.168.1.1"));
        assert!(json.contains("10.0.0.1"));

        let parsed: IpAddressList = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn test_network_interface() {
        let mut iface = NetworkInterface::new("eth0");
        iface.add_address(IpAddress::parse("192.168.1.100").expect("valid"));
        iface.add_address(IpAddress::parse("fe80::1").expect("valid"));

        assert_eq!(iface.name, "eth0");
        assert!(iface.is_address_present());
        assert!(!iface.is_loopback());

        let lo = NetworkInterface::new("lo");
        assert!(lo.is_loopback());
    }

    #[test]
    fn test_ip_classification_properties() {
        assert!(IpClassification::Private.is_internal());
        assert!(IpClassification::Loopback.is_internal());
        assert!(!IpClassification::Public.is_internal());
        assert!(IpClassification::CloudMetadata.is_security_sensitive());
        assert!(!IpClassification::Public.is_security_sensitive());
    }
}
