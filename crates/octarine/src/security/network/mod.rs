// Allow unused imports: This module exports public API that may not be used within the crate
#![allow(unused_imports)]

//! Network security operations with built-in observability
//!
//! This module provides network security validation and detection operations
//! with observe instrumentation for compliance-grade audit trails.
//!
//! # Architecture
//!
//! This is **Layer 3 (security)** - wraps primitives with observe instrumentation:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  security/network (Public API)              │
//! │  - NetworkSecurityBuilder                                   │
//! │  - Shortcuts for common operations                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │              primitives/security/network (Internal)         │
//! │  - Pure detection, validation functions                     │
//! │  - No logging, no side effects                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    observe/ (Internal)                      │
//! │  - Logging, metrics, tracing                                │
//! │  - Audit trail for compliance                               │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Features
//!
//! - **SSRF Protection**: Detect and prevent Server-Side Request Forgery attacks
//! - **URL Validation**: Validate URL formats and schemes
//! - **Hostname Validation**: RFC-compliant hostname validation
//! - **Port Validation**: Port number and range validation
//!
//! # Note on PII Detection
//!
//! For detecting IP addresses, MACs, or other identifiers in text (PII concerns),
//! use [`crate::identifiers::NetworkBuilder`] instead. This module focuses
//! on security operations, not PII detection.
//!
//! # Examples
//!
//! ```ignore
//! use octarine::security::network::{validate_ssrf_safe, validate_url};
//!
//! // Validate a URL is safe from SSRF attacks
//! validate_ssrf_safe("https://api.example.com/data")?;
//!
//! // Validate URL format
//! validate_url("https://example.com")?;
//! ```

// Private submodules - re-export at network level
mod builder;
mod shortcuts;
mod types;

// Re-export the builder
pub use builder::NetworkSecurityBuilder;

// Re-export types for public API (wrapper types for visibility bridging)
pub use types::{HostType, NetworkSecurityHostnameConfig, NetworkSecurityUrlConfig, PortRange};

// Re-export shortcuts at module level
pub use shortcuts::*;
