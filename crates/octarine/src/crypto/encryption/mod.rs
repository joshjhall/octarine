//! Encryption Operations with observability
//!
//! Encryption and decryption for different security requirements,
//! wrapped with observe instrumentation for audit trails.
//!
//! # Architecture
//!
//! This module wraps `primitives::crypto::encryption` with observe instrumentation:
//!
//! - **ephemeral** - Forward-secrecy encryption with security events
//! - **persistent** - Long-term storage encryption with security events
//! - **hybrid** - Post-quantum hybrid encryption with security events
//!
//! # When to Use Each Type
//!
//! | Module | Use Case | Key Lifetime |
//! |--------|----------|--------------|
//! | `ephemeral` | Session data, temp files | Single use |
//! | `persistent` | Database fields, config | Long-term |
//! | `hybrid` | Key exchange, future-proof | Per exchange |
//!
//! # Examples
//!
//! ## Ephemeral Encryption (Forward Secrecy)
//!
//! ```ignore
//! use octarine::crypto::encryption::ephemeral;
//!
//! // Encrypt with forward secrecy (generates security event)
//! let encrypted = ephemeral::encrypt(b"session-token")?;
//!
//! // Decrypt when needed (generates security event)
//! let plaintext = ephemeral::decrypt(&encrypted)?;
//! ```
//!
//! ## Persistent Encryption (Long-term Storage)
//!
//! ```ignore
//! use octarine::crypto::encryption::persistent;
//!
//! // Create storage with post-quantum security
//! let storage = persistent::create_storage()?;
//!
//! // Encrypt for long-term storage (generates security event)
//! let encrypted = persistent::encrypt(&storage, b"database-field")?;
//!
//! // Decrypt when needed (generates security event)
//! let plaintext = persistent::decrypt(&storage, &encrypted)?;
//! ```
//!
//! ## Hybrid Encryption (Post-Quantum Key Exchange)
//!
//! ```ignore
//! use octarine::crypto::encryption::hybrid;
//!
//! // Generate key pair
//! let keypair = hybrid::generate_keypair()?;
//!
//! // Encrypt to a public key (generates security event)
//! let encrypted = hybrid::encrypt(&keypair.public_key(), b"message")?;
//!
//! // Decrypt with private key (generates security event)
//! let plaintext = hybrid::decrypt(&keypair, &encrypted)?;
//! ```

// Submodules with different security properties - accessible as encryption::ephemeral, etc.
pub mod ephemeral;
pub mod hybrid;
pub mod persistent;

// Re-export types for convenience at the encryption level
pub use crate::primitives::crypto::encryption::{
    EncryptedComponents, EphemeralEncryption, HybridEncryptedComponents, HybridEncryption,
    HybridKeyPair, HybridPublicKey, PersistentEncryptedComponents, PersistentEncryption,
    SecureStorage,
};
