//! Crypto Prelude - Convenient Imports
//!
//! This module provides a convenient way to import the most commonly used
//! cryptographic types and functions with a single `use` statement.
//!
//! ## Usage
//!
//! ```ignore
//! use crate::primitives::crypto::prelude::*;
//!
//! // Now you have access to:
//! // - CryptoBuilder (main entry point)
//! // - PrimitiveSecureBuffer, EphemeralEncryption, PersistentEncryption
//! // - CryptoError
//! // - Constant-time comparison functions
//! // - Key derivation functions
//!
//! // For Secret types, use the secrets submodule:
//! use crate::primitives::crypto::secrets::{Secret, ExposeSecret};
//! ```
//!
//! ## What's Included
//!
//! ### Main Entry Point
//! - [`CryptoBuilder`] - Builder for all cryptographic operations
//!
//! ### Encryption Types
//! - [`PrimitiveSecureBuffer`] - Encrypted in-memory storage
//! - [`EphemeralEncryption`] - Forward-secrecy encryption
//! - [`HybridEncryption`] - Post-quantum hybrid encryption (ML-KEM + X25519)
//! - [`PersistentEncryption`] - Post-quantum persistent encryption
//! - [`SecureStorage`] - ML-KEM based storage manager
//!
//! ### Error Type
//! - [`CryptoError`] - All cryptographic errors
//!
//! ### Security Utilities
//! - [`ct_eq`] - Constant-time byte comparison
//! - [`ct_eq_array`] - Constant-time array comparison
//! - [`hkdf_sha3_256`] - Key derivation function
//! - [`DomainSeparator`] - Domain separation for key derivation

// Allow unused imports: Prelude exports for external use
#![allow(unused_imports)]

// ============================================================================
// Core Types
// ============================================================================

// Main builder entry point
pub use super::CryptoBuilder;

// Domain-specific builders
pub use super::{
    BufferBuilder, EphemeralBuilder, HmacBuilder, HybridBuilder, PasswordBuilder,
    PersistentBuilder, RandomBuilder, SecretBuilder,
};

// Error type
pub use super::CryptoError;

// ============================================================================
// From secrets/
// ============================================================================

pub use super::secrets::{
    PrimitiveLockedBox, PrimitiveLockedSecret, PrimitiveSecureBuffer, is_mlock_supported,
    max_lockable_memory, try_mlock, try_munlock,
};

// Note: Secret, SecretString, SecretBytes, ExposeSecret are also in secrets:: submodule
// Use: crate::primitives::crypto::secrets::{Secret, ExposeSecret, ...}

// ============================================================================
// From encryption/
// ============================================================================

pub use super::encryption::{
    EncryptedComponents, EphemeralEncryption, HybridEncryptedComponents, HybridEncryption,
    HybridKeyPair, HybridPublicKey, PersistentEncryptedComponents, PersistentEncryption,
    SecureStorage,
};

// ============================================================================
// From auth/
// ============================================================================

// Constant-time utilities
pub use super::auth::{
    ct_copy_if, ct_eq, ct_eq_array, ct_is_zero_array, ct_is_zero_slice, ct_select_u8,
    ct_select_u32, ct_select_u64, ct_select_usize,
};

// HMAC-SHA3-256 functions
pub use super::auth::{
    HmacSha3_256, MAC_LENGTH, hmac_multipart, hmac_sha3_256, hmac_sha3_256_hex, hmac_with_domain,
    verify_hmac, verify_hmac_hex, verify_hmac_multipart, verify_hmac_strict,
    verify_hmac_with_domain,
};

// ============================================================================
// From keys/
// ============================================================================

// HKDF functions
pub use super::keys::{
    DomainSeparator, derive_key_hkdf, derive_multiple_keys, derive_versioned_key, hkdf_sha3_256,
};

// Password hashing and key derivation
pub use super::keys::{
    PasswordCharset, PasswordProfile, PasswordStrength, derive_key_from_password,
    derive_key_from_password_with_profile, derive_multiple_keys_from_password,
    derive_multiple_keys_with_profile, estimate_password_strength, generate_password,
    hash_password, hash_password_with_profile, verify_password,
};

// Random generation
pub use super::keys::{
    fill_random, random_base64, random_base64_url, random_bytes, random_bytes_vec, random_choice,
    random_hex, random_iv_16, random_key_128, random_key_256, random_nonce_12, random_nonce_24,
    random_salt, random_salt_sized, random_sample, random_u8, random_u16, random_u32,
    random_u32_bounded, random_u32_range, random_u64, random_u64_bounded, random_u64_range,
    random_u128, random_usize, random_usize_bounded, random_uuid_v4, shuffle,
};
