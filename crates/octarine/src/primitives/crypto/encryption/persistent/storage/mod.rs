//! Secure storage for persistent encryption.
//!
//! Uses ML-KEM 1024 for post-quantum security with dual symmetric
//! encryption (ChaCha20-Poly1305 + AES-256-GCM) for defense in depth.
//!
//! ## Module Organization
//!
//! - [`core`] - SecureStorage struct and constructors
//! - [`rotation`] - Key rotation functionality
//! - [`operations`] - Encryption and decryption operations

mod core;
mod operations;
mod rotation;

pub use self::core::SecureStorage;
