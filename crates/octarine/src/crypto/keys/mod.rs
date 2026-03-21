//! Key Generation & Derivation with observability
//!
//! Secure key generation, derivation, and password hashing with built-in
//! audit trails and compliance support.
//!
//! # Architecture
//!
//! This module wraps `primitives::crypto::keys` with observe instrumentation:
//!
//! - **password** - Argon2id password hashing with auth events (async-first)
//! - **kdf** - HKDF-SHA3-256 key derivation with security events
//! - **random** - Secure random generation (no instrumentation - too noisy)
//!
//! # Async-First Design
//!
//! The `password` module uses async-first APIs because password operations are
//! intentionally slow (~100ms+) to resist brute-force attacks. The async API
//! offloads work to a blocking thread pool. Sync variants are available with
//! `*_sync()` suffix.
//!
//! # When to Use Each
//!
//! | Module | Input | Use Case |
//! |--------|-------|----------|
//! | `random` | None | Generate new keys, nonces, IVs |
//! | `kdf` | High-entropy key | Derive subkeys from master key |
//! | `password` | User password | Authentication, password storage |
//!
//! # Examples
//!
//! ## Password Hashing (Async - Recommended)
//!
//! ```ignore
//! use octarine::crypto::keys::password;
//!
//! // Hash a password for storage (runs on blocking thread pool)
//! let hash = password::hash("user_password").await?;
//!
//! // Verify password
//! if password::verify("user_password", &hash).await? {
//!     // Login successful
//! }
//! ```
//!
//! ## Password Hashing (Sync)
//!
//! ```ignore
//! use octarine::crypto::keys::password;
//!
//! // Hash synchronously (blocks current thread)
//! let hash = password::hash_sync("user_password")?;
//!
//! // Verify synchronously
//! if password::verify_sync("user_password", &hash)? {
//!     // Login successful
//! }
//! ```
//!
//! ## Key Derivation
//!
//! ```ignore
//! use octarine::crypto::keys::{kdf, DomainSeparator};
//!
//! // Derive subkey from master key (generates security event)
//! let subkey = kdf::derive(&master_key, Some(b"salt"), DomainSeparator::new("enc:v1"), 32)?;
//! ```
//!
//! ## Random Generation
//!
//! ```ignore
//! use octarine::crypto::keys::random;
//!
//! // Generate random key (no instrumentation)
//! let key = random::key_256()?;
//! let nonce = random::nonce_12()?;
//! ```

// Submodules with different domains and verbs - accessible as keys::kdf, keys::password, keys::random
pub mod kdf;
pub mod password;
pub mod random;

// Also re-export commonly used types at the keys level for convenience
pub use self::kdf::DomainSeparator;
pub use self::password::{PasswordCharset, PasswordError, PasswordProfile, PasswordStrength};
