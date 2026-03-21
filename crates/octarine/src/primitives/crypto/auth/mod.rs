//! Authentication & Verification
//!
//! Message authentication codes and constant-time comparison utilities.
//!
//! ## Module Structure
//!
//! - [`hmac`] - HMAC-SHA3-256 message authentication
//! - [`timing`] - Constant-time comparison to prevent timing attacks
//!
//! ## When to Use
//!
//! | Function | Use Case |
//! |----------|----------|
//! | `hmac_sha3_256` | Generate authentication tag for data |
//! | `verify_hmac` | Verify data hasn't been tampered with |
//! | `ct_eq` | Compare secrets without timing leaks |
//!
//! ## Example
//!
//! ```ignore
//! use crate::primitives::crypto::auth::{hmac_sha3_256, verify_hmac, ct_eq};
//!
//! // Generate HMAC for data
//! let mac = hmac_sha3_256(&key, b"message");
//!
//! // Verify HMAC (constant-time)
//! let valid = verify_hmac(&key, b"message", &mac);
//!
//! // Compare two secrets (constant-time)
//! let equal = ct_eq(&secret1, &secret2);
//! ```

// Allow dead_code: Layer 1 primitives used by Layer 2/3
#![allow(dead_code)]

mod hmac;
mod timing;

// Re-export HMAC functions
pub use hmac::{
    HmacSha3_256, MAC_LENGTH, hmac_multipart, hmac_sha3_256, hmac_sha3_256_hex, hmac_with_domain,
    verify_hmac, verify_hmac_hex, verify_hmac_multipart, verify_hmac_strict,
    verify_hmac_with_domain,
};

// Re-export timing functions
pub use timing::{
    ct_copy_if, ct_eq, ct_eq_array, ct_is_zero_array, ct_is_zero_slice, ct_select_u8,
    ct_select_u32, ct_select_u64, ct_select_usize,
};
