//! Network identifier detection (primitives layer)
//!
//! Pure detection functions for network identifiers with NO logging.
//! Uses patterns from `primitives/identifiers/common/patterns.rs`.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Supported Network Types
//!
//! - **UUIDs**: Universally Unique Identifiers (v4, v5, any version)
//! - **IP Addresses**: IPv4 and IPv6 addresses
//! - **MAC Addresses**: Hardware addresses (colon, hyphen, dot formats)
//! - **URLs**: Web addresses with protocol schemes (HTTP, HTTPS, FTP)
//! - **Domains**: Domain names without protocol
//! - **Hostnames**: Internal hostnames
//! - **Ports**: Port numbers
//! - **API Keys**: Cloud provider keys (AWS, GCP, Azure, etc.)
//!
//! # Security Considerations
//!
//! - **GDPR**: IP addresses can be PII in some jurisdictions
//! - **PCI DSS**: API keys and tokens require secure handling
//! - **OWASP**: Predictable session IDs enable session hijacking
//!
//! # Note on SSRF Detection
//!
//! SSRF (Server-Side Request Forgery) detection is in
//! `primitives::data::network::detection::ssrf` as it's a security concern,
//! not PII detection.

// Submodules by identifier type
mod api_keys;
mod common;
mod domain;
mod ip;
mod mac;
mod phone;
mod url;
mod uuid;

// Re-export all public functions and types for unified API

// API keys and JWT (delegated to token detection, re-exported here for unified network API)
pub use api_keys::{
    find_api_keys_in_text, is_api_key, is_aws_access_key, is_aws_secret_key, is_aws_session_token,
    is_azure_key, is_bearer_token, is_gcp_api_key, is_github_token, is_gitlab_token, is_jwt,
    is_onepassword_token, is_onepassword_vault_ref, is_stripe_key, is_url_with_credentials,
};

// Common/aggregate functions
pub use common::{
    detect_network_identifier, find_all_network_in_text, is_network_identifier, is_network_present,
};

// Domain, hostname, port
pub use domain::{
    find_domains_in_text, find_hostnames_in_text, find_ports_in_text, is_domain, is_hostname,
    is_port, is_test_domain, is_test_hostname,
};

// IP addresses
pub use ip::{find_ip_addresses_in_text, is_ip_address, is_ipv4, is_ipv6, is_test_ip};

// MAC addresses
pub use mac::{find_mac_addresses_in_text, is_mac_address, is_test_mac};

// Phone numbers
pub use phone::is_phone_international;

// URLs
pub use url::{find_urls_in_text, is_test_url, is_url};

// UUIDs
pub use uuid::{
    UuidVersion, detect_uuid_version, find_uuids_in_text, is_test_uuid, is_uuid, is_uuid_v4,
    is_uuid_v5,
};
