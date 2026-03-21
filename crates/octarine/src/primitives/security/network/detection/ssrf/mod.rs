//! SSRF Detection Primitives
//!
//! Pure detection functions for Server-Side Request Forgery prevention.
//! No observe dependencies - used by Layer 2 and Layer 3 modules.
//!
//! ## Security Background
//!
//! SSRF attacks trick servers into making requests to unintended destinations:
//! - **Cloud metadata endpoints**: Access IAM credentials, SSH keys, secrets
//! - **Internal services**: Access admin interfaces, databases, APIs
//! - **File access**: Read local files via file:// scheme
//! - **Port scanning**: Enumerate internal network services
//!
//! ## Module Organization
//!
//! - [`cloud_metadata`] - Cloud provider metadata endpoint detection
//! - [`url_shorteners`] - URL shortener service detection
//! - [`internal_hosts`] - Localhost, private IP, and internal domain detection
//! - [`schemes`] - Dangerous URL scheme detection
//! - [`combined`] - High-level combined SSRF detection
//!
//! ## Compliance Coverage
//!
//! | Check | OWASP | CWE | Notes |
//! |-------|-------|-----|-------|
//! | Cloud metadata | API7:2023 | CWE-918 | Critical - credential theft |
//! | Internal hosts | API7:2023 | CWE-918 | Network reconnaissance |
//! | Dangerous schemes | API7:2023 | CWE-918 | File access, protocol abuse |
//! | URL shorteners | API7:2023 | CWE-601 | Redirect attacks |

mod cloud_metadata;
mod combined;
mod internal_hosts;
mod schemes;
mod url_shorteners;

// Re-export cloud metadata detection
pub use cloud_metadata::{
    CLOUD_METADATA_HOSTS, CLOUD_METADATA_IPS, is_cloud_metadata_endpoint,
    is_metadata_pattern_present,
};

// Re-export URL shortener detection
pub use url_shorteners::{URL_SHORTENERS, is_url_shortener};

// Re-export internal host detection
pub use internal_hosts::{
    is_dns_rebinding_service, is_internal_domain_pattern, is_internal_host,
    is_link_local_ipv4_range, is_localhost, is_loopback_ipv4_range, is_private_ipv4_range,
    is_private_ipv6,
};

// Re-export scheme detection
pub use schemes::{DANGEROUS_SCHEMES, SAFE_SCHEMES, is_dangerous_scheme, is_safe_scheme};

// Re-export combined detection
pub use combined::{extract_host_for_ssrf_check, is_potential_ssrf, is_test_ssrf_url};
