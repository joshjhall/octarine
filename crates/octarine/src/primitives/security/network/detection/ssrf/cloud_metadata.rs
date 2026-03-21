//! Cloud Metadata Detection
//!
//! Detection functions for cloud provider metadata endpoints.

// Allow dead_code: These are Layer 1 primitives that will be used by observe module
#![allow(dead_code)]

// ============================================================================
// Constants
// ============================================================================

/// Known cloud provider metadata endpoint IPs
///
/// These endpoints provide instance credentials and sensitive configuration.
pub const CLOUD_METADATA_IPS: &[&str] = &[
    "169.254.169.254", // AWS EC2, Azure, GCP, DigitalOcean, Oracle Cloud
    "169.254.170.2",   // AWS ECS task metadata endpoint
    "169.254.170.23",  // AWS EKS pod identity agent
    "100.100.100.200", // Alibaba Cloud metadata
    "fd00:ec2::254",   // AWS EC2 IPv6 metadata
];

/// Known cloud provider metadata hostnames
pub const CLOUD_METADATA_HOSTS: &[&str] = &[
    "metadata.google.internal",
    "metadata.gke.internal",
    "metadata",
    "instance-data",
    "metadata.azure.internal",
    "metadata.azure.com",
    "169.254.169.254.nip.io",
];

/// Patterns that indicate metadata-related endpoints
const METADATA_PATTERNS: &[&str] = &[
    "metadata",
    "instance-data",
    "latest/meta-data",
    "latest/user-data",
    "latest/dynamic",
    "computeMetadata",
    "opc/v1", // Oracle Cloud
    "opc/v2",
];

// ============================================================================
// Detection Functions
// ============================================================================

/// Check if host is a cloud metadata endpoint
///
/// Detects AWS, Azure, GCP, Alibaba, Oracle, and other cloud metadata endpoints.
///
/// # Security Note
///
/// Cloud metadata endpoints contain:
/// - IAM credentials and access tokens
/// - SSH keys
/// - Database credentials
/// - API keys
/// - Instance identity documents
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::detection::ssrf::is_cloud_metadata_endpoint;
///
/// assert!(is_cloud_metadata_endpoint("169.254.169.254"));
/// assert!(is_cloud_metadata_endpoint("metadata.google.internal"));
/// assert!(!is_cloud_metadata_endpoint("api.example.com"));
/// ```
#[must_use]
pub fn is_cloud_metadata_endpoint(host: &str) -> bool {
    let lower = host.to_lowercase();
    let trimmed = lower.trim();

    // Check exact IP matches
    for &ip in CLOUD_METADATA_IPS {
        if trimmed == ip {
            return true;
        }
    }

    // Check hostname matches
    for &hostname in CLOUD_METADATA_HOSTS {
        if trimmed == hostname || trimmed.ends_with(&format!(".{hostname}")) {
            return true;
        }
    }

    // Check for metadata patterns in hostname
    is_metadata_pattern_present(trimmed)
}

/// Check if host contains metadata-related keywords
///
/// More aggressive detection that catches obfuscated metadata access attempts.
#[must_use]
pub fn is_metadata_pattern_present(host: &str) -> bool {
    let lower = host.to_lowercase();

    for &pattern in METADATA_PATTERNS {
        if lower.contains(pattern) {
            return true;
        }
    }

    false
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_metadata_ips() {
        assert!(is_cloud_metadata_endpoint("169.254.169.254"));
        assert!(is_cloud_metadata_endpoint("169.254.170.2"));
        assert!(is_cloud_metadata_endpoint("100.100.100.200"));
        assert!(!is_cloud_metadata_endpoint("8.8.8.8"));
        assert!(!is_cloud_metadata_endpoint("10.0.0.1"));
    }

    #[test]
    fn test_cloud_metadata_hosts() {
        assert!(is_cloud_metadata_endpoint("metadata.google.internal"));
        assert!(is_cloud_metadata_endpoint("metadata.azure.internal"));
        assert!(is_cloud_metadata_endpoint("instance-data"));
        assert!(!is_cloud_metadata_endpoint("api.example.com"));
    }

    #[test]
    fn test_metadata_patterns() {
        assert!(is_metadata_pattern_present("latest/meta-data"));
        assert!(is_metadata_pattern_present("computeMetadata/v1"));
        assert!(is_metadata_pattern_present("opc/v1/instance"));
        assert!(!is_metadata_pattern_present("api/users"));
    }
}
