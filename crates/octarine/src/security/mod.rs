// Allow unused imports: This module exports public API that may not be used within the crate
#![allow(unused_imports)]

//! Security operations with built-in observability
//!
//! This module provides security threat detection, validation, and sanitization
//! with observe instrumentation for compliance-grade audit trails.
//!
//! # Architecture
//!
//! This is **Layer 3 (security)** - wraps primitives with observe instrumentation:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  security/ (Public API)                     │
//! │  - NetworkSecurityBuilder, PathSecurityBuilder              │
//! │  - Shortcuts for common operations                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │                primitives/security/ (Internal)              │
//! │  - Pure detection, validation functions                     │
//! │  - No logging, no side effects                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    observe/ (Internal)                      │
//! │  - Logging, metrics, tracing                                │
//! │  - Audit trail for compliance                               │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Modules
//!
//! - `network` - SSRF protection, URL/hostname validation
//! - `paths` - Path traversal detection, injection prevention
//! - `text` - Log injection, control character detection (coming soon)
//!
//! # Three Orthogonal Concerns
//!
//! Security is one of three orthogonal concerns in Octarine:
//!
//! | Concern | Purpose | Question |
//! |---------|---------|----------|
//! | [`crate::data`] | FORMAT | "How should this be structured?" |
//! | [`crate::security`] | THREATS | "Is this dangerous?" |
//! | [`crate::identifiers`] | CLASSIFICATION | "What is it? Is it PII?" |
//!
//! # Examples
//!
//! ## Network Security (SSRF Protection)
//!
//! ```ignore
//! use octarine::security::network::{validate_ssrf_safe, is_internal_host};
//!
//! // Validate URL is safe for server-side requests
//! validate_ssrf_safe("https://api.example.com/data")?;
//!
//! // Check if host is internal (SSRF risk)
//! if is_internal_host("192.168.1.1") {
//!     // Block internal access
//! }
//! ```
//!
//! ## Using Builders
//!
//! ```ignore
//! use octarine::security::network::NetworkSecurityBuilder;
//!
//! let security = NetworkSecurityBuilder::new();
//!
//! // Check for SSRF threats
//! if security.is_ssrf_target("http://169.254.169.254/metadata") {
//!     // Block cloud metadata access
//! }
//! ```

mod facade;

pub mod commands;
#[cfg(feature = "formats")]
pub mod formats;
pub mod network;
pub mod paths;
#[cfg(feature = "database")]
pub mod queries;

// Re-export the Security facade at module level
pub use facade::Security;

// Future modules:
// pub mod text;   // Log injection, control chars
