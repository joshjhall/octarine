//! Network identifier sanitization (primitives layer)
//!
//! Pure redaction functions for network identifiers with NO logging.
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
//! - **UUIDs**: Universally Unique Identifiers
//! - **IP Addresses**: IPv4 and IPv6 addresses
//! - **MAC Addresses**: Hardware addresses
//! - **URLs**: Web addresses with protocol schemes
//! - **API Keys**: Cloud provider keys (AWS, GCP, Azure, etc.)
//! - **Hostnames**: Internal hostnames
//! - **Ports**: Port numbers
//! - **Phones**: International phone numbers
//!
//! # Design Pattern
//!
//! ## Individual Redaction Functions
//!
//! All redaction functions require explicit strategy (suffix: `_with_strategy`):
//! - `redact_uuid_with_strategy(uuid, strategy)` - Full control over UUID redaction
//! - `redact_ip_with_strategy(ip, strategy)` - Full control over IP redaction
//! - etc.
//!
//! ## Text Redaction Functions
//!
//! Use `TextRedactionPolicy` for consistent behavior:
//! - `redact_uuids_in_text(text, policy)` - Scan and redact UUIDs
//! - `redact_ips_in_text(text, policy)` - Scan and redact IPs
//! - etc.

// Submodules by identifier type
mod api_keys;
mod common;
mod domain;
mod ip;
mod mac;
mod phone;
mod url;
mod uuid;

// Re-export redaction strategies from parent redaction module
pub use super::redaction::{
    ApiKeyRedactionStrategy, HostnameRedactionStrategy, IpRedactionStrategy, MacRedactionStrategy,
    PhoneRedactionStrategy, PortRedactionStrategy, TextRedactionPolicy, UrlRedactionStrategy,
    UuidRedactionStrategy,
};

// Re-export all public functions and types for unified API

// API keys
pub use api_keys::{redact_api_key_with_strategy, redact_api_keys_in_text};

// Common/aggregate functions
pub use common::redact_all_network_in_text;

// Domain, hostname, port
pub use domain::{redact_hostname_with_strategy, redact_port};

// IP addresses
pub use ip::{redact_ip_with_strategy, redact_ips_in_text};

// MAC addresses
pub use mac::{redact_mac_with_strategy, redact_macs_in_text};

// Phone numbers
pub use phone::redact_phone_with_strategy;

// URLs
pub use url::{redact_url_with_strategy, redact_urls_in_text};

// UUIDs
pub use uuid::{redact_uuid_with_strategy, redact_uuids_in_text};
