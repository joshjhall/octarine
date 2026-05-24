//! SecretStorage - Named secret storage with audit trails
//!
//! Provides secure storage for named secrets with:
//! - NIST-compliant metadata (classification, TTL)
//! - Full audit trail for all operations via observe
//! - Automatic expiration checking
//! - Memory zeroization on drop
//! - Optional background cleanup of expired secrets
//!
//! Split from the original 1193-LOC `storage.rs` into per-section
//! submodules:
//!
//! - `basic`: `SecretStorage` struct + impls + `Drop` + `Debug`
//! - `managed`: `ManagedSecretStorage`, `ManagedStorageConfig`,
//!   `ManagedStorageBuilder` + the `DEFAULT_CLEANUP_INTERVAL` constant
//! - `tests`: `#[cfg(test)]` unit tests
//!
//! # Types
//!
//! - [`SecretStorage`] - Basic storage (manual cleanup via `purge_expired()`)
//! - [`ManagedSecretStorage`] - Storage with automatic background cleanup
//!
//! # Example
//!
//! Pre-existing example - ignored at compile until adapted.
//! ```ignore
//! use octarine::crypto::secrets::{SecretStorage, SecretType, Classification};
//! use std::time::Duration;
//!
//! let mut storage = SecretStorage::new();
//!
//! // Store a secret with metadata
//! storage.insert_typed(
//!     "api_key",
//!     "sk-12345".to_string(),
//!     SecretType::ApiKey,
//!     Classification::Confidential,
//!     Some(Duration::from_secs(86400)),
//! );
//!
//! // Access with audit logging
//! if let Some(value) = storage.get_audited("api_key", "authenticate") {
//!     // Use the value...
//! }
//! ```
//!
//! # Managed Storage with Background Cleanup
//!
//! Pre-existing example - ignored at compile until adapted.
//! ```ignore
//! use octarine::crypto::secrets::ManagedSecretStorage;
//! use std::time::Duration;
//!
//! // Create storage with automatic cleanup every 60 seconds
//! let storage = ManagedSecretStorage::new()
//!     .with_id("app-secrets")
//!     .with_cleanup_interval(Duration::from_secs(60))
//!     .build();
//!
//! // Start background cleanup task
//! storage.start_cleanup().await;
//!
//! // Use storage...
//! storage.insert("temp_token", "abc123".to_string()).await;
//!
//! // Stop cleanup on shutdown
//! storage.stop_cleanup().await;
//! ```

mod basic;
mod managed;

pub use basic::SecretStorage;
pub use managed::{ManagedSecretStorage, ManagedStorageBuilder, ManagedStorageConfig};

#[cfg(test)]
mod tests;
