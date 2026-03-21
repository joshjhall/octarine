//! Network identifier validation (primitives layer)
//!
//! Pure validation functions for network identifiers with NO logging.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Important Note
//!
//! This module validates **identifier formats** for network data, not the actual
//! network connectivity or validity. Actual network validation requires external
//! services and is outside the scope of this module.
//!
//! # Note on SSRF Validation
//!
//! SSRF (Server-Side Request Forgery) validation is in
//! `primitives::data::network::validation::ssrf` as it's a security concern,
//! not PII validation.

// Domain-specific validation modules
mod hostname;
mod ip;
mod mac;
mod phone;
mod port;
mod uuid;

// Re-export all validation functions

// UUID validation
pub use uuid::{validate_uuid, validate_uuid_v4, validate_uuid_v5};

// MAC address validation
pub use mac::validate_mac_address;

// IP address classification
pub use ip::{
    is_broadcast_ipv4, is_link_local_ipv4, is_link_local_ipv6, is_loopback_ipv4, is_loopback_ipv6,
    is_multicast_ipv4, is_multicast_ipv6, is_private_ipv4, is_public_ipv4, is_public_ipv6,
    is_reserved_ipv4, is_special_use_ipv4, is_special_use_ipv6, is_unique_local_ipv6,
};

// Phone validation
pub use phone::validate_phone_international;

// Hostname and TLD validation
pub use hostname::{
    extract_tld, is_common_tld, validate_domain_tld, validate_hostname_rfc1123,
    validate_tld_against_iana, validate_tld_format,
};

// Port validation
pub use port::{
    PortRange, get_port_range, is_common_port, validate_port_number, validate_port_user_safe,
    validate_port_well_known,
};
