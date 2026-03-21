//! Secure secret handling with observability
//!
//! Provides types for secure storage and passing of secrets with:
//! - Automatic value masking in Debug/Display
//! - Memory zeroization on drop
//! - Memory locking to prevent swapping
//! - Safe environment variable construction
//! - Audit trails via observe
//! - NIST-compliant metadata (classification, TTL, rotation)
//!
//! # Types
//!
//! ## Secret Wrappers
//!
//! - [`Secret`] - Generic wrapper for sensitive data with zeroization
//! - [`SecretString`] - Alias for `Secret<String>`
//! - [`SecretBytes`] - Alias for `Secret<Vec<u8>>`
//! - [`ExposeSecret`] - Trait for accessing secret values
//!
//! ## Typed Secrets (NIST-compliant)
//!
//! - [`TypedSecret`] - Secret with classification, TTL, and audit logging
//! - [`SecretType`] - Semantic types (ApiKey, Password, EncryptionKey, etc.)
//! - [`Classification`] - Data classification levels (Public to Restricted)
//! - [`SecretState`] - Lifecycle states (Active, Suspended, Compromised, etc.)
//! - [`RotationPolicy`] - Rotation interval and grace period configuration
//!
//! ## Environment Variables
//!
//! - [`SecureVar`] - Load env vars with automatic type detection
//! - [`SecureVarError`] - Error type for SecureVar operations
//!
//! ## Encrypted Storage
//!
//! - [`SecureBuffer`] - Encrypted in-memory buffer with closure-based access
//! - [`LockedBox`] - Heap-allocated buffer with memory locking
//! - [`LockedSecret`] - Secret value with memory locking
//! - [`EncryptedSecretStorage`] - Per-secret encryption with closure-based access
//!
//! ## Named Storage
//!
//! - [`SecretStorage`] - Named secret storage with audit trails and TTL (sync)
//! - [`ManagedSecretStorage`] - Async storage with automatic background cleanup
//! - [`ManagedStorageBuilder`] - Builder for ManagedSecretStorage
//!
//! ## Collections & Builders
//!
//! - [`SecureMap`] - A map for storing named secrets with masking (primitive)
//! - [`SecureEnvBuilder`] - Builder for safe subprocess environment construction
//! - [`SecureEnv`] - Built environment ready for subprocess execution
//!
//! # Example
//!
//! ```ignore
//! use octarine::crypto::secrets::{Secret, SecretString, ExposeSecret};
//!
//! // Simple secret wrapper (zeroizes on drop)
//! let api_key: SecretString = Secret::new("sk-12345".to_string());
//!
//! // Debug is safe - shows [REDACTED]
//! println!("{:?}", api_key);  // Secret([REDACTED])
//!
//! // Explicit access when needed
//! let key = api_key.expose_secret();
//! ```
//!
//! # Typed Secrets with Audit Trails
//!
//! ```ignore
//! use octarine::crypto::secrets::{TypedSecret, SecretType, Classification};
//! use std::time::Duration;
//!
//! // Create a typed API key with classification and TTL
//! let api_key = TypedSecret::new("sk-12345".to_string())
//!     .with_type(SecretType::ApiKey)
//!     .with_classification(Classification::Confidential)
//!     .with_ttl(Duration::from_secs(86400))
//!     .with_id("prod-api-key");
//!
//! // Audited access logs the operation
//! if api_key.is_usable() {
//!     let value = api_key.expose_secret_audited("authenticate_request");
//! }
//! ```

mod buffer;
mod encrypted_storage;
mod env;
mod map;
mod mlock;
mod secret;
mod secure_var;
mod storage;
mod typed;

// Re-export public Secret types (Layer 3 wrappers over primitives)
pub use secret::{ExposeSecret, Secret, SecretBytes, SecretString};

// Re-export typed secret types (Layer 3 with observe)
pub use typed::TypedSecret;

// Re-export SecureVar for environment variable loading
pub use secure_var::{SecureVar, SecureVarError};

// Re-export SecretStorage for named secret management
pub use storage::{
    ManagedSecretStorage, ManagedStorageBuilder, ManagedStorageConfig, SecretStorage,
};

// Re-export metadata types from primitives (shared between Layer 1 and Layer 3)
pub use crate::primitives::crypto::secrets::{
    Classification, RotationPolicy, SecretState, SecretType,
};

pub use buffer::SecureBuffer;
pub use encrypted_storage::{
    EncryptedSecretStorage, EncryptedStorageBuilder, EncryptedStorageConfig, EncryptedStorageError,
};
pub use env::{SecureEnv, SecureEnvBuilder};
pub use map::SecureMap;
pub use mlock::{
    LockedBox, LockedSecret, is_mlock_supported, max_lockable_memory, try_mlock, try_munlock,
};
