//! Integration tests for the crypto module
//!
//! These tests verify end-to-end cryptographic workflows:
//! - Hybrid encrypt/decrypt round-trip (post-quantum)
//! - Password hash + verify through public API
//! - KDF-derived key used with HMAC signing
//! - EncryptedSecretStorage lifecycle with TTL expiration

mod crypto;
