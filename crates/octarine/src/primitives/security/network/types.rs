//! Network types
//!
//! Re-exports IP address types from identifiers module.
//! The types themselves are PII-related (IP addresses can identify users),
//! while this network module provides security operations on them.

// Re-export IP types from identifiers module
// IP addresses are identifiers (PII in some jurisdictions), so the types live there
pub use crate::primitives::identifiers::network::ip_types::{
    IpAddress, IpAddressList, IpClassification, NetworkInterface,
};
