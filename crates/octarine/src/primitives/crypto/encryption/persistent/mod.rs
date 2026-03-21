//! Persistent Encryption with Post-Quantum Security
//!
//! Long-term storage encryption using ML-KEM 1024 (FIPS 203) with dual
//! symmetric encryption for defense in depth.
//!
//! ## Security Model
//!
//! - **Post-Quantum Security**: ML-KEM 1024 provides security against
//!   quantum computer attacks (NIST Level 5)
//! - **Dual Encryption**: Data is encrypted with both ChaCha20-Poly1305
//!   and AES-256-GCM. If either algorithm is broken, the other still protects.
//! - **Forward Secrecy**: Each encryption uses a fresh KEM encapsulation
//! - **Platform Isolation**: Instance-specific keys prevent cross-instance decryption
//!
//! ## Cryptographic Flow
//!
//! ```text
//! Encryption:
//! 1. ML-KEM encapsulate → (ciphertext, shared_secret)
//! 2. Derive keys: SHA3-256(shared_secret || "chacha") → chacha_key
//!                 SHA3-256(shared_secret || "aes") → aes_key
//! 3. ChaCha20-Poly1305(plaintext, chacha_key) → intermediate
//! 4. AES-256-GCM(intermediate, aes_key) → final_ciphertext
//! 5. Encrypt shared_secret with platform key for storage
//!
//! Decryption:
//! 1. Decrypt shared_secret with platform key
//! 2. Derive chacha_key and aes_key from shared_secret
//! 3. AES-256-GCM decrypt → intermediate
//! 4. ChaCha20-Poly1305 decrypt → plaintext
//! ```
//!
//! ## Example
//!
//! ```ignore
//! use crate::primitives::crypto::persistent::{SecureStorage, PersistentEncryption};
//!
//! // Create storage instance
//! let storage = SecureStorage::new()?;
//!
//! // Encrypt sensitive data
//! let data = b"long-term-secret";
//! let encrypted = storage.encrypt(data)?;
//!
//! // Later, decrypt
//! let decrypted = storage.decrypt(&encrypted)?;
//! assert_eq!(decrypted.as_slice(), data);
//! ```
//!
//! ## Key Rotation
//!
//! `SecureStorage` supports key versioning for rotation. When rotating keys:
//! 1. Create a new storage instance (gets new platform key)
//! 2. Re-encrypt existing data with the new instance
//! 3. The `key_version` field in encrypted components tracks the key used
//!
//! ## Module Structure
//!
//! - [`encryption`] - `PersistentEncryption` data structure and serialization
//! - [`storage`] - `SecureStorage` for encrypt/decrypt operations
//! - [`keys`] - ML-KEM keypair management (internal)
//!
//! ## See Also
//!
//! - [`HybridEncryption`](super::HybridEncryption) - Post-quantum encryption for
//!   communication between parties (ML-KEM + X25519)
//! - [`EphemeralEncryption`](super::EphemeralEncryption) - Classical ephemeral encryption
//!   for short-lived secrets
//! - [`PrimitiveSecureBuffer`](super::secrets::PrimitiveSecureBuffer) - In-memory encrypted storage (not persistent)

// Allow dead_code: These are Layer 1 primitives that will be used by Layer 2/3 modules
#![allow(dead_code)]

mod encryption;
mod keys;
mod storage;

// Re-export public types
pub use encryption::{PersistentEncryptedComponents, PersistentEncryption};
pub use storage::SecureStorage;

// Internal imports from crypto module
use crate::primitives::crypto::{CryptoError, keys::fill_random};

// ============================================================================
// Constants
// ============================================================================

/// ChaCha20-Poly1305 key size (256 bits)
const CHACHA_KEY_SIZE: usize = 32;

/// ChaCha20-Poly1305 nonce size (96 bits)
const CHACHA_NONCE_SIZE: usize = 12;

/// AES-256-GCM key size (256 bits)
const AES_KEY_SIZE: usize = 32;

/// AES-256-GCM nonce size (96 bits)
const AES_NONCE_SIZE: usize = 12;

/// Platform key size (256 bits)
const PLATFORM_KEY_SIZE: usize = 32;

/// Maximum number of historical keys to retain for rotation
const MAX_KEY_HISTORY: usize = 5;
