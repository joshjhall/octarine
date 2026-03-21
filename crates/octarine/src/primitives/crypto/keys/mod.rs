//! Key Generation & Derivation
//!
//! Secure random generation and key derivation functions.
//!
//! ## Module Structure
//!
//! - [`random`] - Cryptographically secure random generation
//! - [`kdf`] - HKDF-SHA3-256 key derivation (for high-entropy input)
//! - [`password`] - Argon2id password hashing (for low-entropy passwords)
//!
//! ## When to Use Each
//!
//! | Function | Input | Use Case |
//! |----------|-------|----------|
//! | `random_*` | None | Generate new keys, nonces, IVs |
//! | `hkdf_sha3_256` | High-entropy key | Derive subkeys from master key |
//! | `derive_key_from_password` | User password | Key derivation from password |
//!
//! ## Example
//!
//! ```ignore
//! use crate::primitives::crypto::keys::{
//!     random_key_256, hkdf_sha3_256, derive_key_from_password, DomainSeparator
//! };
//!
//! // Generate a random 256-bit key
//! let key = random_key_256()?;
//!
//! // Derive subkeys from a master key (high-entropy input only!)
//! let subkey = hkdf_sha3_256(&master_key, Some(b"salt"), DomainSeparator::new("enc:v1"), 32)?;
//!
//! // Derive key from user password (uses Argon2id)
//! let key = derive_key_from_password("user_password", &salt, 32)?;
//! ```

// Allow dead_code: Layer 1 primitives used by Layer 2/3
#![allow(dead_code)]

mod kdf;
pub mod password;
mod random;

// Re-export KDF functions
pub use kdf::{
    DomainSeparator, derive_key_hkdf, derive_multiple_keys, derive_versioned_key, hkdf_sha3_256,
};

// Re-export password functions
// Async functions (primary API)
pub use password::{
    PasswordCharset, PasswordError, PasswordProfile, PasswordStrength, derive_key_from_password,
    derive_key_from_password_with_profile, derive_multiple_keys_from_password,
    derive_multiple_keys_with_profile, estimate_password_strength, generate_password,
    hash_password, hash_password_with_profile, verify_password,
};
// Sync functions (legacy/blocking contexts)
pub use password::{
    derive_key_from_password_sync, derive_key_from_password_with_profile_sync,
    derive_multiple_keys_from_password_sync, derive_multiple_keys_with_profile_sync,
    hash_password_sync, hash_password_with_profile_sync, verify_password_sync,
};

// Re-export random functions
pub use random::{
    fill_random, random_base64, random_base64_url, random_bytes, random_bytes_vec, random_choice,
    random_hex, random_iv_16, random_key_128, random_key_256, random_nonce_12, random_nonce_24,
    random_salt, random_salt_sized, random_sample, random_u8, random_u16, random_u32,
    random_u32_bounded, random_u32_range, random_u64, random_u64_bounded, random_u64_range,
    random_u128, random_usize, random_usize_bounded, random_uuid_v4, shuffle,
};
