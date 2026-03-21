//! Authentication & Verification with observability
//!
//! Message authentication codes and constant-time comparison utilities
//! with built-in audit trails and compliance support.
//!
//! # Architecture
//!
//! This module wraps `primitives::crypto::auth` with observe instrumentation:
//!
//! - **hmac** - HMAC-SHA3-256 message authentication with security events
//!
//! # When to Use
//!
//! | Function | Use Case |
//! |----------|----------|
//! | `auth::compute` | Generate authentication tag for data |
//! | `auth::verify` | Verify data hasn't been tampered with |
//! | `auth::with_domain` | Cross-protocol safe authentication |
//! | `auth::multipart` | Authenticate structured data |
//!
//! # Examples
//!
//! ## Basic HMAC
//!
//! ```ignore
//! use octarine::crypto::auth;
//!
//! // Compute HMAC (generates security event)
//! let mac = auth::compute(&key, b"message");
//!
//! // Verify HMAC (generates security event)
//! if auth::verify(&key, b"message", &mac) {
//!     // Data is authentic
//! }
//! ```
//!
//! ## Domain-Separated HMAC
//!
//! ```ignore
//! use octarine::crypto::auth;
//!
//! // Different domains produce different MACs (prevents cross-protocol attacks)
//! let mac = auth::with_domain(&key, "api:v1", b"request-body");
//! ```

mod hmac;

// Re-export hmac functions (flattened - no hmac:: namespace in public API)
pub use self::hmac::*;

// Re-export types directly from primitives (no wrapper needed)
pub use crate::primitives::crypto::auth::HmacSha3_256;

// Re-export constant-time functions (no observe needed - low level primitives)
pub use crate::primitives::crypto::auth::{
    ct_copy_if, ct_eq, ct_eq_array, ct_is_zero_array, ct_is_zero_slice, ct_select_u8,
    ct_select_u32, ct_select_u64, ct_select_usize,
};
