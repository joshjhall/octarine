//! Hostname and TLD validation functions
//!
//! Pure validation functions for hostnames and top-level domains.
//!
//! ## Module Structure
//!
//! - `rfc1123` - RFC 1123 hostname validation
//! - `tld` - Top-level domain validation and common TLD list

mod rfc1123;
mod tld;

// Re-export hostname validation
pub use rfc1123::validate_hostname_rfc1123;

// Re-export TLD validation
pub use tld::{
    extract_tld, is_common_tld, validate_domain_tld, validate_tld_against_iana, validate_tld_format,
};
