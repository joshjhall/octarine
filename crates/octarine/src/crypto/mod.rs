//! Cryptographic operations with built-in observability
//!
//! This module provides cryptographic operations wrapped with observe
//! instrumentation for audit trails, metrics, and compliance support.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    crypto/ (Public API)                     │
//! │  - Three-layer: octarine::crypto::<domain>::*               │
//! │  - Wrapped crypto operations with audit trails              │
//! ├─────────────────────────────────────────────────────────────┤
//! │                primitives/crypto/ (Internal)                │
//! │  - Pure crypto operations                                   │
//! │  - secrets/, encryption/, keys/, auth/                      │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    observe/ (Internal)                      │
//! │  - Logging, metrics, tracing                                │
//! │  - Audit trail for compliance                               │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Modules
//!
//! - `auth` - HMAC-SHA3-256 message authentication with security events
//! - `encryption` - Encryption operations with security events
//!   - `encryption::ephemeral` - Forward-secrecy encryption (ChaCha20-Poly1305)
//!   - `encryption::persistent` - Post-quantum long-term storage (ML-KEM + dual symmetric)
//!   - `encryption::hybrid` - Post-quantum key exchange (ML-KEM + X25519)
//! - `keys` - Key generation, derivation, and password hashing
//!   - `keys::kdf` - HKDF key derivation (high-entropy input)
//!   - `keys::password` - Argon2id password hashing (low-entropy input)
//!   - `keys::random` - Secure random generation
//! - `secrets` - Secure secret storage and environment building
//!
//! # Examples
//!
//! ## Message Authentication (HMAC)
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
//! ## Password Hashing
//!
//! ```ignore
//! use octarine::crypto::keys::password;
//!
//! // Hash a password for storage (generates auth event)
//! let hash = password::hash("user_password")?;
//!
//! // Verify password (generates auth event)
//! if password::verify("user_password", &hash)? {
//!     // Login successful
//! }
//! ```
//!
//! ## Key Derivation
//!
//! ```ignore
//! use octarine::crypto::keys::{kdf, DomainSeparator};
//!
//! // Derive subkeys from master key (generates security event)
//! let subkey = kdf::derive(&master_key, Some(b"salt"), DomainSeparator::new("enc"), 32)?;
//! ```
//!
//! ## Random Generation
//!
//! ```ignore
//! use octarine::crypto::keys::random;
//!
//! let key = random::key_256()?;
//! let nonce = random::nonce_12()?;
//! let uuid = random::uuid_v4()?;
//! ```
//!
//! ## SecureMap
//!
//! ```ignore
//! use octarine::crypto::secrets::SecureMap;
//!
//! let mut secrets = SecureMap::new();
//! secrets.insert("API_KEY", "sk-secret-key");
//! secrets.insert("DB_PASSWORD", "hunter2");
//!
//! // Debug output masks all values
//! println!("{:?}", secrets);
//! // SecureMap { API_KEY: [REDACTED], DB_PASSWORD: [REDACTED] }
//!
//! // Explicit access when needed
//! if let Some(key) = secrets.get("API_KEY") {
//!     // Use the secret...
//! }
//! ```
//!
//! ## SecureEnvBuilder
//!
//! ```ignore
//! use octarine::crypto::secrets::{SecureEnvBuilder, SecureEnv};
//!
//! let env: SecureEnv = SecureEnvBuilder::new()
//!     .inherit_safe()              // Inherit only safe env vars
//!     .with_secret("API_KEY", key) // Add secrets
//!     .with_var("LOG_LEVEL", "info") // Add non-secret vars
//!     .build();
//!
//! // Pass to Command::envs()
//! std::process::Command::new("app")
//!     .envs(env.iter())
//!     .spawn()?;
//! ```

// Three-layer API: octarine::crypto::<domain>::*
// Each domain (auth, encryption, keys, secrets) has its own module with wrapped operations
pub mod auth;
pub mod encryption;
pub mod keys;
pub mod secrets;

// Crypto input validation (feature-gated)
#[cfg(feature = "crypto-validation")]
pub mod validation;
