// Allow unused imports: Layer 1 primitives that will be used by Layer 2/3 modules
#![allow(unused_imports)]

//! Cryptographic Primitives
//!
//! Pure cryptographic operations with NO observe dependencies.
//! These are foundation building blocks used by both observe (for encrypted logging)
//! and security (for secret management).
//!
//! ## Architecture Layer
//!
//! This is part of **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! ## Module Structure
//!
//! Organized by use case:
//!
//! - [`secrets`] - Secret handling & storage (`Secret<T>`, `PrimitiveSecureBuffer`, `PrimitiveLockedSecret`)
//! - [`encryption`] - Encryption operations (ephemeral, persistent, hybrid)
//! - [`keys`] - Key generation & derivation (random, KDF, password)
//! - [`auth`] - Authentication & verification (HMAC, constant-time ops)
//! - [`builder`] - `CryptoBuilder` fluent API for all operations
//! - [`error`] - `CryptoError` for cryptographic operation failures
//!
//! ## Entry Point
//!
//! Use [`CryptoBuilder`] as the main entry point for all cryptographic operations:
//!
//! ```ignore
//! use crate::primitives::crypto::CryptoBuilder;
//!
//! let crypto = CryptoBuilder::new();
//!
//! // Create secure buffers
//! let buffer = crypto.buffer().create(b"secret".to_vec())?;
//!
//! // Ephemeral encryption with forward secrecy
//! let encrypted = crypto.ephemeral().encrypt(b"data")?;
//!
//! // Post-quantum secure storage
//! let storage = crypto.persistent().create_storage()?;
//!
//! // Secret wrappers with auto-zeroization
//! let secret = crypto.secret().string("password".to_string());
//! ```
//!
//! ## Security Features
//!
//! | Component | Algorithm | Security Level | Use Case |
//! |-----------|-----------|----------------|----------|
//! | `PrimitiveSecureBuffer` | ChaCha20-Poly1305 | 256-bit | In-memory secrets |
//! | `EphemeralEncryption` | ChaCha20-Poly1305 | 256-bit | Forward secrecy |
//! | `HybridEncryption` | ML-KEM 1024 + X25519 | Post-quantum hybrid | Key exchange |
//! | `PersistentEncryption` | ML-KEM 1024 + ChaCha20 + AES-256 | Post-quantum | Long-term storage |
//! | `Secret<T>` | Zeroization | N/A | Safe secret handling |
//!
//! ## Defense in Depth
//!
//! - **ChaCha20-Poly1305** - AEAD encryption for data protection
//! - **AES-256-GCM** - Second layer in persistent encryption
//! - **ML-KEM 1024** - Post-quantum key encapsulation (FIPS 203)
//! - **SHA3-256** - Key derivation with domain separation
//! - **Automatic Zeroization** - Sensitive data cleared on drop
//! - **Per-Buffer Ephemeral Keys** - Each buffer has unique encryption keys
//! - **Safe Access Patterns** - Closure-based access prevents key leakage
//!
//! ## Direct Usage (Alternative to Builder)
//!
//! You can also use types directly if preferred:
//!
//! ```ignore
//! use crate::primitives::crypto::secrets::PrimitiveSecureBuffer;
//! use crate::primitives::crypto::CryptoError;
//!
//! // Create a secure buffer with sensitive data
//! let secret = b"my-api-key-12345".to_vec();
//! let buffer = PrimitiveSecureBuffer::new(secret)?;
//!
//! // Access data safely via closure (decrypted only during closure)
//! buffer.with_decrypted(|data| {
//!     println!("Secret length: {}", data.len());
//! })?;
//!
//! // Data is automatically zeroized when buffer is dropped
//! ```

// ============================================================================
// Submodules (organized by use case)
// ============================================================================

// Domain modules - accessible as crate::primitives::crypto::<domain>::*
pub(crate) mod auth;
pub(crate) mod encryption;
pub(crate) mod keys;
pub(crate) mod secrets;

// Internal modules
mod builder;
mod error;

// Public prelude for convenient imports
pub(crate) mod prelude;

// ============================================================================
// Primary Export: CryptoBuilder
// ============================================================================

// The main entry point for all cryptographic operations
pub use builder::{
    BufferBuilder, CryptoBuilder, EphemeralBuilder, HmacBuilder, HybridBuilder, PasswordBuilder,
    PersistentBuilder, RandomBuilder, SecretBuilder,
};

// ============================================================================
// Error Type
// ============================================================================

pub use error::CryptoError;

// ============================================================================
// Domain modules are accessed via their namespace:
//   crate::primitives::crypto::auth::*
//   crate::primitives::crypto::encryption::*
//   crate::primitives::crypto::keys::*
//   crate::primitives::crypto::secrets::*
// ============================================================================
