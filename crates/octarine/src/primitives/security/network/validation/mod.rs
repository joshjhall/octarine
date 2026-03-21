// Allow unused imports: These are crate-internal re-exports
#![allow(unused_imports)]

//! Network security validation primitives
//!
//! Pure validation functions for network security concerns.
//! No observe dependencies - returns Result types for error handling.

pub(crate) mod hostname;
pub(crate) mod port;
pub(crate) mod ssrf;
pub(crate) mod url;

// Re-export SSRF validation for crate-internal use
pub(crate) use ssrf::{
    validate_not_cloud_metadata, validate_not_internal, validate_not_url_shortener,
    validate_safe_scheme, validate_ssrf_safe,
};

// Re-export URL validation for crate-internal use
pub(crate) use url::{NetworkSecurityUrlConfig, validate_url_format, validate_url_scheme};

// Re-export hostname validation for crate-internal use
pub(crate) use hostname::{
    NetworkSecurityHostnameConfig, validate_hostname, validate_hostname_length,
};

// Re-export port validation for crate-internal use
pub(crate) use port::{PortRange, validate_port, validate_port_range};
