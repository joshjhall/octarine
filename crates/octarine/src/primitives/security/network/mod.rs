// Allow unused imports: This module exports public API that may not be used within the crate
#![allow(unused_imports)]

//! Network security primitives
//!
//! Pure validation and detection functions for network security concerns.
//! No observe dependencies - used by Layer 2 and Layer 3 modules.
//!
//! # Purpose
//!
//! This module handles **network security operations**:
//! - SSRF (Server-Side Request Forgery) protection
//! - URL scheme validation
//! - Internal/private host detection
//! - Cloud metadata endpoint blocking
//! - Port validation
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Distinction from identifiers/network
//!
//! | This module (`network/`) | `identifiers/network/` |
//! |--------------------------|------------------------|
//! | Security validation | PII detection |
//! | "Is this URL safe to fetch?" | "Find IPs in text for redaction" |
//! | SSRF protection | Redaction strategies |
//! | Scheme allowlists | Batch PII processing |
//!
//! # Security Coverage
//!
//! ## SSRF Protection (OWASP)
//!
//! - **Scheme validation**: Block dangerous schemes (file://, gopher://, ldap://)
//! - **Internal host detection**: Block localhost, private IPs, internal domains
//! - **Cloud metadata blocking**: Block AWS/GCP/Azure metadata endpoints
//! - **URL shortener detection**: Warn about redirect-based attacks
//!
//! ## Compliance
//!
//! | Check | OWASP | CWE | Notes |
//! |-------|-------|-----|-------|
//! | SSRF | A10:2021 | CWE-918 | Server-Side Request Forgery |
//! | Scheme validation | A10:2021 | CWE-918 | Dangerous protocol access |
//! | Internal access | A01:2021 | CWE-441 | Unintended proxy/intermediary |
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::data::network::{
//!     validate_ssrf_safe, is_internal_host, is_safe_scheme
//! };
//!
//! // Full SSRF validation
//! validate_ssrf_safe("https://api.example.com/data")?;
//!
//! // Individual checks
//! if is_internal_host("192.168.1.1") {
//!     // Block internal access
//! }
//!
//! if !is_safe_scheme("file:///etc/passwd") {
//!     // Block dangerous scheme
//! }
//! ```
//!
//! # Module Organization
//!
//! ```text
//! network/
//! ├── mod.rs              # Public API and re-exports
//! ├── types.rs            # IP types, classifications
//! ├── detection/          # Security detection functions
//! │   ├── ssrf/           # SSRF-specific detection
//! │   │   ├── schemes.rs      # Dangerous/safe scheme detection
//! │   │   ├── internal_hosts.rs # Private IP, localhost detection
//! │   │   ├── cloud_metadata.rs # AWS/GCP/Azure metadata endpoints
//! │   │   └── url_shorteners.rs # URL shortener detection
//! │   ├── url.rs          # URL parsing utilities
//! │   └── host.rs         # Host extraction and classification
//! ├── validation/         # Security validation functions
//! │   ├── ssrf.rs         # Combined SSRF validation
//! │   ├── url.rs          # URL validation
//! │   ├── hostname.rs     # Hostname validation
//! │   └── port.rs         # Port validation
//! └── builder.rs          # NetworkSecurityBuilder API
//! ```

// Internal submodules - accessed via builder
mod builder;
mod detection;
mod types;
mod validation;

// Re-export the builder as the primary API
pub(crate) use builder::NetworkSecurityBuilder;

// Re-export config types needed by builder users
pub(crate) use builder::{NetworkSecurityHostnameConfig, NetworkSecurityUrlConfig, PortRange};
pub(crate) use detection::host::HostType;
pub(crate) use types::{IpAddress, IpAddressList, IpClassification, NetworkInterface};

// Re-export constants for crate-internal use (these are data, not functions)
pub(crate) use detection::ssrf::{
    CLOUD_METADATA_HOSTS, CLOUD_METADATA_IPS, DANGEROUS_SCHEMES, SAFE_SCHEMES, URL_SHORTENERS,
};

// Re-export test helper
pub(crate) use detection::ssrf::is_test_ssrf_url;
