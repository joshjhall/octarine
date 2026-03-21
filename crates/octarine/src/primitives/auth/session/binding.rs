//! Session binding for enhanced security
//!
//! Implements ASVS V3.2.1: Session tokens should be bound to the user's session.

use sha2::{Digest, Sha256};

/// Session binding information
///
/// Binds a session to client characteristics to detect session hijacking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBinding {
    /// Hash of the user agent string (if bound)
    pub user_agent_hash: Option<String>,
    /// IP address or network (if bound)
    pub ip_binding: Option<String>,
}

impl SessionBinding {
    /// Create a new session binding from context
    #[must_use]
    pub fn from_context(user_agent: Option<&str>, ip: Option<&str>) -> Self {
        Self {
            user_agent_hash: user_agent.map(compute_binding_hash),
            ip_binding: ip.map(|s| s.to_string()),
        }
    }

    /// Create a binding with only user agent
    #[must_use]
    pub fn user_agent_only(user_agent: &str) -> Self {
        Self {
            user_agent_hash: Some(compute_binding_hash(user_agent)),
            ip_binding: None,
        }
    }

    /// Create a binding with only IP
    #[must_use]
    pub fn ip_only(ip: &str) -> Self {
        Self {
            user_agent_hash: None,
            ip_binding: Some(ip.to_string()),
        }
    }

    /// Create a binding with only network prefix (for NAT tolerance)
    ///
    /// Binds to a /24 network (IPv4) or /48 network (IPv6) to handle
    /// users behind NAT or with dynamic IPs.
    #[must_use]
    pub fn network_only(ip: &str) -> Self {
        Self {
            user_agent_hash: None,
            ip_binding: Some(compute_network_prefix(ip)),
        }
    }

    /// Check if the binding matches the given context
    #[must_use]
    pub fn matches(&self, user_agent: Option<&str>, ip: Option<&str>) -> bool {
        // Check user agent binding
        if let Some(ref expected_hash) = self.user_agent_hash {
            match user_agent {
                Some(ua) => {
                    let actual_hash = compute_binding_hash(ua);
                    if expected_hash != &actual_hash {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Check IP binding
        if let Some(ref expected_ip) = self.ip_binding {
            match ip {
                Some(actual_ip) => {
                    // Support both exact match and network prefix match
                    if expected_ip != actual_ip && expected_ip != &compute_network_prefix(actual_ip)
                    {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }

    /// Check if any binding is configured
    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.user_agent_hash.is_some() || self.ip_binding.is_some()
    }
}

/// Compute a binding hash for a value
///
/// Uses SHA-256 truncated to 16 bytes for storage efficiency.
#[must_use]
fn compute_binding_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let result = hasher.finalize();
    // SHA-256 produces 32 bytes, so taking first 16 is always safe
    result.get(..16).map(hex::encode).unwrap_or_default()
}

/// Compute network prefix for NAT-tolerant binding
///
/// Returns /24 for IPv4 and /48 for IPv6.
fn compute_network_prefix(ip: &str) -> String {
    if ip.contains(':') {
        // IPv6: use first 3 segments (48 bits)
        let mut parts = ip.split(':');
        if let (Some(p0), Some(p1), Some(p2)) = (parts.next(), parts.next(), parts.next()) {
            return format!("{p0}:{p1}:{p2}::/48");
        }
    } else {
        // IPv4: use first 3 octets (/24)
        let mut parts = ip.split('.');
        if let (Some(p0), Some(p1), Some(p2)) = (parts.next(), parts.next(), parts.next()) {
            return format!("{p0}.{p1}.{p2}.0/24");
        }
    }
    // Fallback to full IP
    ip.to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_binding_from_context() {
        let binding = SessionBinding::from_context(Some("Mozilla/5.0"), Some("192.168.1.1"));

        assert!(binding.user_agent_hash.is_some());
        assert_eq!(binding.ip_binding, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_binding_matches() {
        let binding = SessionBinding::from_context(Some("Mozilla/5.0"), Some("192.168.1.1"));

        assert!(binding.matches(Some("Mozilla/5.0"), Some("192.168.1.1")));
        assert!(!binding.matches(Some("Chrome/100"), Some("192.168.1.1")));
        assert!(!binding.matches(Some("Mozilla/5.0"), Some("10.0.0.1")));
        assert!(!binding.matches(None, Some("192.168.1.1")));
        assert!(!binding.matches(Some("Mozilla/5.0"), None));
    }

    #[test]
    fn test_user_agent_only_binding() {
        let binding = SessionBinding::user_agent_only("Mozilla/5.0");

        assert!(binding.user_agent_hash.is_some());
        assert!(binding.ip_binding.is_none());
        assert!(binding.matches(Some("Mozilla/5.0"), None));
        assert!(binding.matches(Some("Mozilla/5.0"), Some("any-ip")));
    }

    #[test]
    fn test_ip_only_binding() {
        let binding = SessionBinding::ip_only("192.168.1.1");

        assert!(binding.user_agent_hash.is_none());
        assert!(binding.ip_binding.is_some());
        assert!(binding.matches(None, Some("192.168.1.1")));
        assert!(binding.matches(Some("any-ua"), Some("192.168.1.1")));
    }

    #[test]
    fn test_network_prefix_ipv4() {
        let prefix = compute_network_prefix("192.168.1.100");
        assert_eq!(prefix, "192.168.1.0/24");
    }

    #[test]
    fn test_network_prefix_ipv6() {
        let prefix = compute_network_prefix("2001:db8:85a3::8a2e:370:7334");
        assert_eq!(prefix, "2001:db8:85a3::/48");
    }

    #[test]
    fn test_binding_hash_consistency() {
        let hash1 = compute_binding_hash("Mozilla/5.0");
        let hash2 = compute_binding_hash("Mozilla/5.0");
        let hash3 = compute_binding_hash("Chrome/100");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        // 16 bytes as hex = 32 chars
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_is_bound_both() {
        let binding = SessionBinding::from_context(Some("Mozilla/5.0"), Some("192.168.1.1"));
        assert!(binding.is_bound());
    }

    #[test]
    fn test_is_bound_user_agent_only() {
        let binding = SessionBinding::user_agent_only("Mozilla/5.0");
        assert!(binding.is_bound());
    }

    #[test]
    fn test_is_bound_ip_only() {
        let binding = SessionBinding::ip_only("192.168.1.1");
        assert!(binding.is_bound());
    }

    #[test]
    fn test_is_bound_none() {
        let binding = SessionBinding::from_context(None, None);
        assert!(!binding.is_bound());
    }

    #[test]
    fn test_binding_empty_strings() {
        // Empty strings should still create bindings (hashed)
        let binding = SessionBinding::from_context(Some(""), Some(""));
        assert!(binding.is_bound());
    }

    #[test]
    fn test_network_binding_nat_tolerance() {
        // Network binding should allow IPs in same /24
        let binding = SessionBinding::network_only("192.168.1.100");
        assert!(binding.matches(None, Some("192.168.1.100")));
        assert!(binding.matches(None, Some("192.168.1.50")));
        assert!(binding.matches(None, Some("192.168.1.1")));
        // Different /24 should fail
        assert!(!binding.matches(None, Some("192.168.2.1")));
    }
}
