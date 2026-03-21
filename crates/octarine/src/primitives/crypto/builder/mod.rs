//! Builder pattern for cryptographic operations
//!
//! Provides the main entry point for all cryptographic operations including
//! secure buffers, ephemeral encryption, persistent storage, and secret handling.
//!
//! ## Design Philosophy
//!
//! - **Single entry point**: All crypto operations through one builder
//! - **Domain delegation**: Routes to domain-specific builders
//! - **No business logic**: Pure interface, all work done by domain modules
//! - **Defense in depth**: Multiple layers of protection available
//!
//! ## Security Model
//!
//! The crypto module provides several levels of protection:
//!
//! | Type | Use Case | Post-Quantum | Key Lifetime |
//! |------|----------|--------------|--------------|
//! | `Secret<T>` | In-memory secrets | N/A | Until drop |
//! | `PrimitiveSecureBuffer` | Encrypted memory | No | Per-buffer |
//! | `EphemeralEncryption` | One-time encryption | No | Per-message |
//! | `HybridEncryption` | Key exchange | Yes (ML-KEM+X25519) | Per-message |
//! | `PersistentEncryption` | Long-term storage | Yes (ML-KEM) | Configurable |
//!
//! ## Example
//!
//! ```ignore
//! use crate::primitives::crypto::CryptoBuilder;
//!
//! let crypto = CryptoBuilder::new();
//!
//! // Create a secure buffer for sensitive data
//! let buffer = crypto.buffer().create(b"api-key-12345".to_vec())?;
//!
//! // Encrypt with forward secrecy
//! let encrypted = crypto.ephemeral().encrypt(b"temporary-token")?;
//!
//! // Create post-quantum secure storage
//! let storage = crypto.persistent().create_storage()?;
//! ```
//!
//! ## Module Structure
//!
//! - [`CryptoBuilder`] - Main entry point
//! - [`BufferBuilder`] - Secure in-memory buffers
//! - [`EphemeralBuilder`] - Forward-secrecy encryption
//! - [`HmacBuilder`] - Message authentication
//! - [`HybridBuilder`] - Post-quantum hybrid encryption
//! - [`PasswordBuilder`] - Password hashing and key derivation
//! - [`PersistentBuilder`] - Post-quantum secure storage
//! - [`RandomBuilder`] - Secure random generation
//! - [`SecretBuilder`] - Secret value wrappers

// Allow dead_code: Layer 1 primitives used by Layer 2/3 modules
#![allow(dead_code)]

mod buffer;
mod ephemeral;
mod hmac;
mod hybrid;
mod password;
mod persistent;
mod random;
mod secret;

// Re-export all builders
pub use buffer::BufferBuilder;
pub use ephemeral::EphemeralBuilder;
pub use hmac::HmacBuilder;
pub use hybrid::HybridBuilder;
pub use password::PasswordBuilder;
pub use persistent::PersistentBuilder;
pub use random::RandomBuilder;
pub use secret::SecretBuilder;

// ============================================================================
// CryptoBuilder - Main Entry Point
// ============================================================================

/// Builder for all cryptographic operations
///
/// Provides access to domain-specific builders for different cryptographic
/// needs: secure buffers, ephemeral encryption, persistent storage, and
/// secret management.
///
/// # Thread Safety
///
/// `CryptoBuilder` is `Send + Sync` and can be shared across threads.
/// All operations are stateless and create new instances.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::crypto::CryptoBuilder;
///
/// let crypto = CryptoBuilder::new();
///
/// // Access buffer operations
/// let buffer = crypto.buffer().create(b"secret".to_vec())?;
///
/// // Access ephemeral encryption
/// let encrypted = crypto.ephemeral().encrypt(b"data")?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct CryptoBuilder {
    buffer: BufferBuilder,
    ephemeral: EphemeralBuilder,
    hmac: HmacBuilder,
    hybrid: HybridBuilder,
    password: PasswordBuilder,
    persistent: PersistentBuilder,
    random: RandomBuilder,
    secret: SecretBuilder,
}

impl CryptoBuilder {
    /// Create a new CryptoBuilder
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: BufferBuilder::new(),
            ephemeral: EphemeralBuilder::new(),
            hmac: HmacBuilder::new(),
            hybrid: HybridBuilder::new(),
            password: PasswordBuilder::new(),
            persistent: PersistentBuilder::new(),
            random: RandomBuilder::new(),
            secret: SecretBuilder::new(),
        }
    }

    /// Get the secure buffer builder
    ///
    /// Access operations for creating and managing encrypted in-memory buffers.
    /// Buffers use ChaCha20-Poly1305 with per-buffer ephemeral keys.
    ///
    /// # Use Cases
    ///
    /// - API keys and tokens in memory
    /// - Session data requiring encryption at rest
    /// - Any sensitive data that needs secure in-memory storage
    #[must_use]
    pub fn buffer(&self) -> &BufferBuilder {
        &self.buffer
    }

    /// Get the ephemeral encryption builder
    ///
    /// Access operations for one-time encryption with maximum forward secrecy.
    /// Each encryption generates unique keys that are destroyed after use.
    ///
    /// # Use Cases
    ///
    /// - Temporary tokens
    /// - Session data with forward secrecy requirements
    /// - Encrypted log entries
    /// - Any data requiring maximum forward secrecy
    #[must_use]
    pub fn ephemeral(&self) -> &EphemeralBuilder {
        &self.ephemeral
    }

    /// Get the HMAC operations builder
    ///
    /// Access operations for message authentication using HMAC-SHA3-256.
    /// Provides message integrity and authenticity verification.
    ///
    /// # Use Cases
    ///
    /// - API request signing
    /// - Message authentication
    /// - Cookie/token integrity verification
    /// - Commitment schemes
    #[must_use]
    pub fn hmac(&self) -> &HmacBuilder {
        &self.hmac
    }

    /// Get the hybrid encryption builder
    ///
    /// Access operations for post-quantum hybrid encryption using ML-KEM 1024
    /// combined with X25519 for defense in depth. Provides security even if
    /// one algorithm is broken.
    ///
    /// # Use Cases
    ///
    /// - Encrypted messages between parties
    /// - Secure key exchange
    /// - Post-quantum safe session establishment
    /// - Secure file transfer
    #[must_use]
    pub fn hybrid(&self) -> &HybridBuilder {
        &self.hybrid
    }

    /// Get the password operations builder
    ///
    /// Access operations for password hashing and password-based key derivation
    /// using Argon2id (RFC 9106). Use this for low-entropy input like user passwords.
    ///
    /// # Use Cases
    ///
    /// - User password hashing for storage
    /// - Password verification on login
    /// - Deriving encryption keys from passphrases
    /// - Master key derivation from passwords
    ///
    /// # Warning
    ///
    /// Do NOT use HKDF (from `kdf.rs`) for passwords. HKDF expects high-entropy
    /// input. Passwords are low-entropy and require memory-hard functions.
    #[must_use]
    pub fn password(&self) -> &PasswordBuilder {
        &self.password
    }

    /// Get the persistent encryption builder
    ///
    /// Access operations for long-term encrypted storage with post-quantum
    /// security (ML-KEM 1024). Provides defense in depth with hybrid
    /// classical/post-quantum encryption.
    ///
    /// # Use Cases
    ///
    /// - Long-term secret storage
    /// - Configuration files with sensitive data
    /// - Audit logs requiring post-quantum security
    /// - Any data that must remain secure against quantum computers
    #[must_use]
    pub fn persistent(&self) -> &PersistentBuilder {
        &self.persistent
    }

    /// Get the secure random generation builder
    ///
    /// Access operations for generating cryptographically secure random data
    /// including bytes, keys, nonces, salts, and identifiers.
    ///
    /// # Use Cases
    ///
    /// - Generating encryption keys
    /// - Creating nonces for AEAD encryption
    /// - Generating salts for key derivation
    /// - Creating random UUIDs and tokens
    /// - Secure shuffling and sampling
    #[must_use]
    pub fn random(&self) -> &RandomBuilder {
        &self.random
    }

    /// Get the secret wrapper builder
    ///
    /// Access operations for wrapping sensitive values with automatic
    /// zeroization and safe debug output.
    ///
    /// # Use Cases
    ///
    /// - Passwords (before hashing)
    /// - API keys and tokens
    /// - Any value that should be zeroized on drop
    #[must_use]
    pub fn secret(&self) -> &SecretBuilder {
        &self.secret
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::primitives::crypto::secrets::ExposeSecretCore;

    #[test]
    fn test_builder_creation() {
        let crypto = CryptoBuilder::new();
        // Just verify it compiles and creates without panic
        let _ = format!("{:?}", crypto);
    }

    #[test]
    fn test_default() {
        let crypto = CryptoBuilder::default();
        let _ = format!("{:?}", crypto);
    }

    #[test]
    fn test_full_workflow() {
        let crypto = CryptoBuilder::new();

        // 1. Create a secret password
        let password = crypto.secret().string("super-secret-password".to_string());
        assert_eq!(password.expose_secret(), "super-secret-password");

        // 2. Store it in a secure buffer
        let buffer = crypto
            .buffer()
            .create(password.expose_secret().as_bytes().to_vec())
            .expect("Failed to create buffer");

        // 3. Verify we can retrieve it
        buffer
            .with_decrypted(|data| {
                assert_eq!(data, b"super-secret-password");
            })
            .expect("Failed to decrypt");

        // 4. Create persistent storage for long-term
        let storage = crypto
            .persistent()
            .create_storage()
            .expect("Failed to create storage");

        let encrypted = storage
            .encrypt(b"long-term-secret")
            .expect("Failed to encrypt");

        let decrypted = storage.decrypt(&encrypted).expect("Failed to decrypt");
        assert_eq!(decrypted.as_slice(), b"long-term-secret");
    }

    #[test]
    fn test_clone() {
        let crypto = CryptoBuilder::new();
        let cloned = crypto.clone();

        // Both should work independently
        let buf1 = crypto.buffer().create(b"data1".to_vec()).expect("buf1");
        let buf2 = cloned.buffer().create(b"data2".to_vec()).expect("buf2");

        buf1.with_decrypted(|d| assert_eq!(d, b"data1"))
            .expect("decrypt1");
        buf2.with_decrypted(|d| assert_eq!(d, b"data2"))
            .expect("decrypt2");
    }
}
