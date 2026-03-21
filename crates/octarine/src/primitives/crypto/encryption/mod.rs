//! Encryption Operations
//!
//! Encryption and decryption for different security requirements.
//!
//! ## Module Structure
//!
//! - [`ephemeral`] - Forward-secrecy encryption (new keys per operation)
//! - [`persistent`] - Long-term storage encryption with post-quantum security
//! - [`hybrid`] - Post-quantum hybrid encryption (ML-KEM + X25519)
//!
//! ## When to Use Each Type
//!
//! | Type | Use Case | Key Lifetime |
//! |------|----------|--------------|
//! | `EphemeralEncryption` | Session data, temp files | Single use |
//! | `PersistentEncryption` | Database fields, config | Long-term |
//! | `HybridEncryption` | Key exchange, future-proof | Per exchange |
//!
//! ## Security Levels
//!
//! | Component | Algorithm | Security Level |
//! |-----------|-----------|----------------|
//! | Ephemeral | ChaCha20-Poly1305 | 256-bit |
//! | Persistent | ML-KEM 1024 + ChaCha20 + AES-256 | Post-quantum |
//! | Hybrid | ML-KEM 1024 + X25519 | Post-quantum hybrid |
//!
//! ## Example
//!
//! ```ignore
//! use crate::primitives::crypto::encryption::{
//!     EphemeralEncryption, PersistentEncryption, HybridEncryption
//! };
//!
//! // Ephemeral encryption (forward secrecy)
//! let encrypted = EphemeralEncryption::encrypt(b"session data")?;
//! let decrypted = encrypted.decrypt()?;
//!
//! // Persistent encryption (long-term storage)
//! let storage = PersistentEncryption::create_storage()?;
//! let encrypted = storage.encrypt(b"database field")?;
//! ```

// Allow dead_code: Layer 1 primitives used by Layer 2/3
#![allow(dead_code)]

mod ephemeral;
mod hybrid;
mod persistent;

// Re-export ephemeral types
pub use ephemeral::{EncryptedComponents, EphemeralEncryption};

// Re-export persistent types
pub use persistent::{PersistentEncryptedComponents, PersistentEncryption, SecureStorage};

// Re-export hybrid types
pub use hybrid::{HybridEncryptedComponents, HybridEncryption, HybridKeyPair, HybridPublicKey};
