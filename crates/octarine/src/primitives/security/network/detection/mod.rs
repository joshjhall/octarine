// Allow unused imports: These are crate-internal re-exports
#![allow(unused_imports)]

//! Network security detection primitives
//!
//! Pure detection functions for network security concerns.
//! No observe dependencies - used by Layer 2 and Layer 3 modules.
//!
//! # Module Organization
//!
//! - [`ssrf`] - SSRF detection (cloud metadata, internal hosts, schemes, URL shorteners)
//! - [`url`] - URL parsing and extraction
//! - [`host`] - Host classification

pub(crate) mod host;
pub(crate) mod ssrf;
pub(crate) mod url;

// Re-export SSRF detection for crate-internal use
pub(crate) use ssrf::{
    // Constants
    CLOUD_METADATA_HOSTS,
    CLOUD_METADATA_IPS,
    DANGEROUS_SCHEMES,
    SAFE_SCHEMES,
    URL_SHORTENERS,
    // Detection functions
    extract_host_for_ssrf_check,
    is_cloud_metadata_endpoint,
    is_dangerous_scheme,
    is_internal_domain_pattern,
    is_internal_host,
    is_link_local_ipv4_range,
    is_localhost,
    is_loopback_ipv4_range,
    is_metadata_pattern_present,
    is_potential_ssrf,
    is_private_ipv4_range,
    is_private_ipv6,
    is_safe_scheme,
    is_test_ssrf_url,
    is_url_shortener,
};

// Re-export URL detection for crate-internal use
pub(crate) use url::{extract_host, extract_scheme, is_absolute_url, is_relative_url};

// Re-export host classification for crate-internal use
pub(crate) use host::{HostType, classify_host, is_domain_host, is_ip_address_host};
