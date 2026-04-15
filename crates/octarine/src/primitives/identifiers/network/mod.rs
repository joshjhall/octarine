//! Network identifier primitives
//!
//! Pure detection, validation, and sanitization for network identifiers.
//! No observe dependencies - used by Layer 2 and Layer 3 modules.
//!
//! # Supported Identifiers
//!
//! - **UUIDs**: Universally Unique Identifiers (v4, v5, any version)
//! - **IP Addresses**: IPv4 and IPv6 addresses
//! - **MAC Addresses**: Hardware addresses (colon, hyphen, dot formats)
//! - **URLs**: Web addresses with protocol schemes (HTTP, HTTPS, FTP)
//! - **Phones**: International phone numbers with country codes
//! - **JWT**: JSON Web Tokens
//! - **API Keys**: Generic and Stripe-specific API keys
//!
//! # Security Considerations
//!
//! Network identifiers have varying sensitivity levels:
//! - **GDPR**: IP addresses can be PII in some jurisdictions
//! - **PCI DSS**: API keys and tokens require secure handling
//! - **OWASP**: Predictable session IDs enable session hijacking
//! - **BIPA**: MAC addresses are hardware identifiers
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::identifiers::network::NetworkIdentifierBuilder;
//!
//! let builder = NetworkIdentifierBuilder::new();
//!
//! // Detection
//! if builder.is_uuid("550e8400-e29b-41d4-a716-446655440000") {
//!     println!("Found UUID");
//! }
//!
//! // Validation
//! if builder.validate_uuid_v4("550e8400-e29b-41d4-a716-446655440000") {
//!     println!("Valid UUID v4");
//! }
//!
//! // Sanitization
//! let safe = builder.redact_all_in_text("UUID: 550e8400-e29b-41d4-a716-446655440000");
//! ```
//!
//! ## Compliance Coverage
//!
//! Network identifiers have varying regulatory requirements:
//!
//! | Identifier | GDPR | PCI DSS | OWASP | Notes |
//! |------------|------|---------|-------|-------|
//! | IP Address | Art. 4(1) - Can be PII | N/A | Sensitive in logs | May identify individuals |
//! | MAC Address | Persistent tracking concern | N/A | Hardware fingerprint | Device identification |
//! | API Key | N/A | Level 1 Data | Critical Secret | Unauthorized access risk |
//! | JWT | N/A when anonymized | Level 1 if contains PII | Session tracking | Contains user claims |
//! | UUID | Linkable across systems | N/A | Session tracking | Correlation risk |
//! | URL | May contain PII in params | N/A | Info disclosure | Query strings risky |
//! | Phone | Art. 4(1) - Personal data | N/A | Contact info | Direct identifier |
//! | Hostname | May identify organization | N/A | Infrastructure info | Network topology |
//!
//! ## Performance Characteristics
//!
//! ### Computational Complexity
//!
//! | Operation | Time | Space | Notes |
//! |-----------|------|-------|-------|
//! | `is_uuid` | O(n) | O(1) | Regex match with length check (max 1000 chars) |
//! | `is_ip_address` | O(n) | O(1) | Delegates to std::net parser |
//! | `is_mac_address` | O(n) | O(1) | Regex match, 3 format variants |
//! | `is_url` | O(n) | O(1) | Regex match with protocol check |
//! | `is_api_key` | O(n) | O(1) | Multiple provider patterns |
//! | `find_uuids_in_text` | O(n) | O(m) | n = text length, m = matches found |
//! | `find_ips_in_text` | O(n) | O(m) | n = text length, m = matches found |
//! | `redact_uuid` | O(n) | O(n) | n = UUID length, strategy-dependent |
//! | `redact_ip` | O(n) | O(n) | n = IP length, strategy-dependent |
//! | `redact_uuids_in_text` | O(n) | O(m) | Cow optimization: O(1) space if no matches |
//! | `validate_uuid_v4` | O(n) | O(1) | Uses detection layer |
//! | `validate_mac_address` | O(n) | O(1) | Additional broadcast/null checks |
//! | `normalize_url` | O(n) | O(n) | Lowercases and normalizes URL |
//!
//! ### Memory Usage
//!
//! - **Regex patterns**: ~25KB lazily initialized (shared across calls)
//! - **Per-call overhead**: Minimal, typically < 1KB for single identifiers
//! - **Text scanning**: Linear with text size plus detected matches
//! - **Cow optimization**: Zero allocation when text contains no identifiers
//! - **No caching**: Network identifier operations are cheap (simple regex/parsing),
//!   so no LRU caches are used. This keeps the module simple and avoids memory overhead.
//!
//! ### ReDoS Protection
//!
//! All detection functions include length limits:
//! - **Single identifier**: Max 1,000 characters
//! - **Text scanning**: Max 10,000 characters (10KB)
//! - Exceeding limits returns `false` or empty Vec immediately
//!
//! ## Module Structure
//!
//! The network module is organized by identifier type for maintainability:
//!
//! ```text
//! network/
//! ├── mod.rs              # Public API and re-exports
//! ├── builder/            # NetworkIdentifierBuilder implementation
//! ├── redaction.rs        # Redaction strategy enums
//! ├── detection/          # Detection functions (8 submodules by identifier type)
//! │   ├── uuid.rs         # UUID detection and test patterns
//! │   ├── ip.rs           # IPv4/IPv6 detection
//! │   ├── mac.rs          # MAC address detection
//! │   ├── url.rs          # URL detection
//! │   ├── domain.rs       # Domain, hostname, port detection
//! │   ├── api_keys.rs     # API key and JWT detection
//! │   ├── phone.rs        # International phone detection
//! │   └── common.rs       # Aggregate detection functions
//! ├── sanitization/       # Sanitization functions (mirrors detection structure)
//! │   ├── uuid.rs         # UUID redaction
//! │   ├── ip.rs           # IP redaction
//! │   ├── mac.rs          # MAC redaction
//! │   ├── url.rs          # URL redaction
//! │   ├── domain.rs       # Hostname and port redaction
//! │   ├── api_keys.rs     # API key redaction
//! │   ├── phone.rs        # Phone redaction
//! │   └── common.rs       # Aggregate redaction functions
//! ├── validation/         # Validation functions
//! ├── conversion.rs       # Format conversion functions
//! └── batch.rs            # Batch processing utilities
//! ```
//!
//! ## Recommendations
//!
//! - **For large documents (>10KB)**: Process in chunks or use streaming
//! - **For API logs**: Use `redact_api_keys_in_text()` with `Complete` policy before logging
//! - **For GDPR compliance**: Redact IP addresses in user-facing logs with `Partial` or `Complete` policy
//! - **For performance**: Use `Cow<str>` returns to avoid allocations when text is clean
//! - **For security**: Always redact API keys and JWTs in logs (never use `None` policy)

pub(crate) mod batch;
pub(crate) mod builder;
pub(crate) mod ip_types;
pub(crate) mod redaction;

// Internal modules - not directly accessible outside network/
// (streaming.rs doesn't use network module)
mod conversion;
mod detection;
mod sanitization;
mod validation;

// Re-export builder for convenient access
pub use builder::NetworkIdentifierBuilder;

// Re-export IP types for use across the codebase
pub use ip_types::{IpAddress, IpAddressList, IpClassification, NetworkInterface};

// Re-export redaction strategies for type-safe redaction API
pub use redaction::{
    ApiKeyRedactionStrategy, HostnameRedactionStrategy, IpRedactionStrategy, MacRedactionStrategy,
    PhoneRedactionStrategy, PortRedactionStrategy, TextRedactionPolicy, UrlRedactionStrategy,
    UuidRedactionStrategy,
};

// Export batch processing functions (high-level utilities for observe module)
pub use batch::{
    count_by_type, filter_valid_identifiers, partition_identifiers, validate_batch_as,
};

// Export detection types (needed for builder return types)
pub use detection::UuidVersion;
pub use validation::PortRange;

// Export redaction functions with explicit strategies (observe module wraps these)
pub use sanitization::{
    redact_api_key_with_strategy, redact_hostname_with_strategy, redact_ip_with_strategy,
    redact_mac_with_strategy, redact_phone_with_strategy, redact_url_with_strategy,
    redact_uuid_with_strategy,
};

// Export text redaction functions
pub use sanitization::{
    redact_api_keys_in_text, redact_ips_in_text, redact_macs_in_text, redact_urls_in_text,
    redact_uuids_in_text,
};

// Export common normalization functions (observe module convenience)
pub use conversion::{normalize_mac, normalize_url};

// Export test pattern detection functions (observe module testing)
pub use detection::{
    is_test_domain, is_test_hostname, is_test_ip, is_test_mac, is_test_url, is_test_uuid,
};
