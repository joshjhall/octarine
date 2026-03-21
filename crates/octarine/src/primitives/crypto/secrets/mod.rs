//! Secret Handling & Storage (Layer 1 Primitives)
//!
//! Types for secure storage of sensitive data with automatic zeroization.
//! These are Layer 1 primitives - pure implementations without observability.
//!
//! ## Module Structure
//!
//! - [`secret`] - `Secret<T>` wrapper for sensitive data with auto-zeroization
//! - [`buffer`] - `PrimitiveSecureBuffer` for encrypted in-memory storage
//! - [`mlock`] - Memory locking to prevent swapping (`PrimitiveLockedBox`, `PrimitiveLockedSecret`)
//! - [`map`] - `PrimitiveSecureMap` for storing named secrets
//! - [`env`] - `PrimitiveSecureEnvBuilder` for subprocess environment construction
//!
//! ## When to Use Each Type
//!
//! | Type | Use Case | Memory Protection |
//! |------|----------|-------------------|
//! | `Secret<T>` | API keys, passwords, tokens | Zeroized on drop |
//! | `PrimitiveSecureBuffer` | Encryption keys, certificates | Encrypted + zeroized |
//! | `PrimitiveLockedSecret` | High-security keys | Encrypted + mlock + zeroized |
//! | `PrimitiveSecureMap` | Named secret storage | Zeroized on drop |
//! | `PrimitiveSecureEnv` | Subprocess environments | Zeroized on drop |
//!
//! ## Example
//!
//! ```ignore
//! use crate::primitives::crypto::secrets::{Secret, PrimitiveSecureBuffer, PrimitiveLockedSecret};
//! use crate::primitives::crypto::secrets::{PrimitiveSecureMap, PrimitiveSecureEnvBuilder};
//!
//! // Simple secret wrapper
//! let api_key = Secret::new("sk-12345".to_string());
//!
//! // Encrypted in-memory buffer
//! let buffer = PrimitiveSecureBuffer::new(b"encryption-key".to_vec())?;
//!
//! // Memory-locked secret (prevents swapping)
//! let locked = PrimitiveLockedSecret::new(b"master-key".to_vec());
//!
//! // Named secret storage
//! let mut secrets = PrimitiveSecureMap::new();
//! secrets.insert("API_KEY", "sk-12345");
//!
//! // Subprocess environment
//! let env = PrimitiveSecureEnvBuilder::new()
//!     .inherit_safe()
//!     .with_secret("DB_PASSWORD", "hunter2")
//!     .build_simple();
//! ```

// Allow dead_code: Layer 1 primitives used by Layer 2/3
#![allow(dead_code)]

mod buffer;
mod env;
mod map;
mod mlock;
mod secret;
mod typed;

// Re-export secret types (internal Core types)
pub(crate) use secret::{ExposeSecretCore, SecretBytesCore, SecretCore, SecretStringCore};

// Re-export buffer types
pub use buffer::PrimitiveSecureBuffer;

// Re-export mlock types
pub use mlock::{
    PrimitiveLockedBox, PrimitiveLockedSecret, is_mlock_supported, max_lockable_memory, try_mlock,
    try_munlock,
};

// Re-export map types
pub use map::PrimitiveSecureMap;

// Re-export env types
pub use env::{PrimitiveSecureEnv, PrimitiveSecureEnvBuilder};

// Re-export typed secret types
pub use typed::{
    Classification, PrimitiveTypedSecret, RotationPolicy, SecretState, SecretType,
    TypedSecretBytes, TypedSecretString,
};
