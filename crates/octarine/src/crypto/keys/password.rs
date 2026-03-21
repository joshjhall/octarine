//! Password Hashing & Key Derivation with observability
//!
//! Layer 3 wrapper around `primitives::crypto::keys::password` that adds
//! observe instrumentation for audit trails and compliance support.
//!
//! # Async-First Design
//!
//! Password operations are intentionally slow (~100ms+) to resist brute-force
//! attacks. This module provides async-first APIs that offload CPU-intensive
//! work to a blocking thread pool:
//!
//! - Primary API is async (`hash()`, `verify()`, etc.)
//! - Sync variants available with `*_sync()` suffix
//!
//! # Security Events
//!
//! - Password hashing generates `auth.password_hash` events
//! - Password verification generates `auth.password_verify` events
//! - Key derivation generates `security.key_derived` events
//!
//! # Examples
//!
//! ## Async Usage (Recommended)
//!
//! ```ignore
//! use octarine::crypto::keys::password;
//!
//! // Hash a password (runs on blocking thread pool)
//! let hash = password::hash("user_password").await?;
//!
//! // Verify password
//! if password::verify("user_password", &hash).await? {
//!     // Success
//! }
//!
//! // Derive encryption key from password
//! let key = password::derive_key_from_password("password", &salt, 32).await?;
//! ```
//!
//! ## Sync Usage
//!
//! ```ignore
//! use octarine::crypto::keys::password;
//!
//! // Hash synchronously (blocks current thread)
//! let hash = password::hash_sync("user_password")?;
//!
//! // Verify synchronously
//! if password::verify_sync("user_password", &hash)? {
//!     // Success
//! }
//! ```

use std::time::Instant;

use crate::observe;
use crate::primitives::crypto::CryptoError;
use crate::primitives::crypto::keys::password as prim;

// Re-export types from primitives
pub use prim::{PasswordCharset, PasswordError, PasswordProfile, PasswordStrength};

// ============================================================================
// Async Password Hashing (Primary API)
// ============================================================================

/// Hash a password for secure storage with audit trail.
///
/// Uses Argon2id with the Interactive profile (64 MiB, 3 iterations).
/// Runs on a blocking thread pool.
///
/// # Example
///
/// ```ignore
/// let hash = password::hash("my_password").await?;
/// ```
pub async fn hash(password: &str) -> Result<String, PasswordError> {
    hash_with_profile(password, PasswordProfile::Interactive).await
}

/// Hash a password with a specific security profile.
///
/// Runs on a blocking thread pool.
pub async fn hash_with_profile(
    password: &str,
    profile: PasswordProfile,
) -> Result<String, PasswordError> {
    let start = Instant::now();
    observe::debug(
        "password_hash",
        format!("Starting password hash (profile: {profile:?})"),
    );

    let result = prim::hash_password_with_profile(password, profile).await;

    let elapsed = start.elapsed();
    match &result {
        Ok(_) => {
            observe::info(
                "password_hash",
                format!("Password hashed successfully in {elapsed:?}"),
            );
        }
        Err(e) => {
            observe::warn(
                "password_hash",
                format!("Password hashing failed after {elapsed:?}: {e}"),
            );
        }
    }

    result
}

/// Verify a password against a stored hash with audit trail.
///
/// Runs on a blocking thread pool. Performs constant-time comparison.
///
/// # Example
///
/// ```ignore
/// if password::verify("user_input", &stored_hash).await? {
///     // Login successful
/// }
/// ```
pub async fn verify(password: &str, hash: &str) -> Result<bool, PasswordError> {
    let start = Instant::now();
    observe::debug("password_verify", "Starting password verification");

    let result = prim::verify_password(password, hash).await;

    let elapsed = start.elapsed();
    match &result {
        Ok(true) => {
            observe::info(
                "password_verify",
                format!("Password verification succeeded in {elapsed:?}"),
            );
        }
        Ok(false) => {
            observe::warn(
                "password_verify",
                format!("Password verification failed - incorrect password ({elapsed:?})"),
            );
        }
        Err(e) => {
            observe::warn(
                "password_verify",
                format!("Password verification error after {elapsed:?}: {e}"),
            );
        }
    }

    result
}

// ============================================================================
// Async Key Derivation
// ============================================================================

/// Derive an encryption key from a password with audit trail.
///
/// Runs on a blocking thread pool.
pub async fn derive_key_from_password(
    password: &str,
    salt: &[u8],
    key_len: usize,
) -> Result<Vec<u8>, PasswordError> {
    derive_key_from_password_with_profile(password, salt, key_len, PasswordProfile::Interactive)
        .await
}

/// Derive an encryption key with a specific security profile.
///
/// Runs on a blocking thread pool.
pub async fn derive_key_from_password_with_profile(
    password: &str,
    salt: &[u8],
    key_len: usize,
    profile: PasswordProfile,
) -> Result<Vec<u8>, PasswordError> {
    let start = Instant::now();
    observe::debug(
        "key_derived",
        format!("Starting key derivation ({key_len} bytes, profile: {profile:?})"),
    );

    let result =
        prim::derive_key_from_password_with_profile(password, salt, key_len, profile).await;

    let elapsed = start.elapsed();
    match &result {
        Ok(_) => {
            observe::info(
                "key_derived",
                format!("Derived {key_len}-byte key from password in {elapsed:?}"),
            );
        }
        Err(e) => {
            observe::warn(
                "key_derived",
                format!("Key derivation failed after {elapsed:?}: {e}"),
            );
        }
    }

    result
}

/// Derive multiple keys from a single password.
///
/// Runs on a blocking thread pool.
pub async fn derive_multiple_keys(
    password: &str,
    salt: &[u8],
    domains: &[&str],
    key_len: usize,
) -> Result<Vec<Vec<u8>>, PasswordError> {
    derive_multiple_keys_with_profile(
        password,
        salt,
        domains,
        key_len,
        PasswordProfile::Interactive,
    )
    .await
}

/// Derive multiple keys with a specific security profile.
///
/// Runs on a blocking thread pool.
pub async fn derive_multiple_keys_with_profile(
    password: &str,
    salt: &[u8],
    domains: &[&str],
    key_len: usize,
    profile: PasswordProfile,
) -> Result<Vec<Vec<u8>>, PasswordError> {
    let domain_count = domains.len();
    let start = Instant::now();
    observe::debug(
        "key_derived",
        format!("Starting multi-key derivation ({domain_count} keys, {key_len} bytes each)"),
    );

    let result =
        prim::derive_multiple_keys_with_profile(password, salt, domains, key_len, profile).await;

    let elapsed = start.elapsed();
    match &result {
        Ok(keys) => {
            observe::info(
                "key_derived",
                format!(
                    "Derived {} keys ({key_len} bytes each) in {elapsed:?}",
                    keys.len()
                ),
            );
        }
        Err(e) => {
            observe::warn(
                "key_derived",
                format!("Multiple key derivation failed after {elapsed:?}: {e}"),
            );
        }
    }

    result
}

// ============================================================================
// Sync Variants
// ============================================================================

/// Hash a password synchronously.
///
/// **Warning**: Blocks the current thread. Use `hash()` in async contexts.
pub fn hash_sync(password: &str) -> Result<String, CryptoError> {
    hash_with_profile_sync(password, PasswordProfile::Interactive)
}

/// Hash a password with a specific profile, synchronously.
pub fn hash_with_profile_sync(
    password: &str,
    profile: PasswordProfile,
) -> Result<String, CryptoError> {
    let result = prim::hash_password_with_profile_sync(password, profile);

    match &result {
        Ok(_) => observe::info("password_hash", "Password hashed successfully"),
        Err(e) => observe::warn("password_hash", format!("Password hashing failed: {e}")),
    }

    result
}

/// Verify a password synchronously.
///
/// **Warning**: Blocks the current thread. Use `verify()` in async contexts.
pub fn verify_sync(password: &str, hash: &str) -> Result<bool, CryptoError> {
    let result = prim::verify_password_sync(password, hash);

    match &result {
        Ok(true) => observe::info("password_verify", "Password verification succeeded"),
        Ok(false) => observe::warn(
            "password_verify",
            "Password verification failed - incorrect password",
        ),
        Err(e) => observe::warn(
            "password_verify",
            format!("Password verification error: {e}"),
        ),
    }

    result
}

/// Alias for `verify_sync` following naming conventions.
///
/// **Warning**: Blocks the current thread. Use `verify()` in async contexts.
pub fn validate_sync(password: &str, hash: &str) -> Result<bool, CryptoError> {
    verify_sync(password, hash)
}

/// Derive a key from password synchronously.
///
/// **Warning**: Blocks the current thread.
pub fn derive_key_from_password_sync(
    password: &str,
    salt: &[u8],
    key_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    derive_key_from_password_with_profile_sync(
        password,
        salt,
        key_len,
        PasswordProfile::Interactive,
    )
}

/// Derive a key with a specific profile, synchronously.
pub fn derive_key_from_password_with_profile_sync(
    password: &str,
    salt: &[u8],
    key_len: usize,
    profile: PasswordProfile,
) -> Result<Vec<u8>, CryptoError> {
    let result = prim::derive_key_from_password_with_profile_sync(password, salt, key_len, profile);

    match &result {
        Ok(_) => observe::info(
            "key_derived",
            format!("Derived {key_len}-byte key from password"),
        ),
        Err(e) => observe::warn("key_derived", format!("Key derivation failed: {e}")),
    }

    result
}

/// Derive multiple keys synchronously.
///
/// **Warning**: Blocks the current thread.
pub fn derive_multiple_keys_sync(
    password: &str,
    salt: &[u8],
    domains: &[&str],
    key_len: usize,
) -> Result<Vec<Vec<u8>>, CryptoError> {
    derive_multiple_keys_with_profile_sync(
        password,
        salt,
        domains,
        key_len,
        PasswordProfile::Interactive,
    )
}

/// Derive multiple keys with a specific profile, synchronously.
pub fn derive_multiple_keys_with_profile_sync(
    password: &str,
    salt: &[u8],
    domains: &[&str],
    key_len: usize,
    profile: PasswordProfile,
) -> Result<Vec<Vec<u8>>, CryptoError> {
    let result =
        prim::derive_multiple_keys_with_profile_sync(password, salt, domains, key_len, profile);

    match &result {
        Ok(keys) => observe::info(
            "key_derived",
            format!("Derived {} keys ({key_len} bytes each)", keys.len()),
        ),
        Err(e) => observe::warn(
            "key_derived",
            format!("Multiple key derivation failed: {e}"),
        ),
    }

    result
}

// ============================================================================
// Utility Functions (always sync - fast operations)
// ============================================================================

/// Estimate password strength.
///
/// Fast operation, no async variant needed.
#[inline]
pub fn estimate_strength(password: &str) -> PasswordStrength {
    prim::estimate_password_strength(password)
}

/// Generate a secure random password.
///
/// Fast operation, no async variant needed.
#[inline]
pub fn generate(length: usize, charset: PasswordCharset) -> Result<String, CryptoError> {
    prim::generate_password(length, charset)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_sync() {
        let hash = hash_sync("test_password").expect("Hash failed");
        assert!(hash.starts_with("$argon2id$"));

        assert!(verify_sync("test_password", &hash).expect("Verify failed"));
        assert!(!verify_sync("wrong_password", &hash).expect("Verify failed"));
    }

    #[test]
    fn test_derive_key_from_password_sync() {
        let salt = b"unique-test-salt";
        let key = derive_key_from_password_sync("password", salt, 32).expect("Derive failed");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_estimate_strength() {
        assert_eq!(estimate_strength("abc"), PasswordStrength::VeryWeak);
        assert!(estimate_strength("Password123!").is_acceptable());
    }

    #[test]
    fn test_generate_password() {
        let password = generate(16, PasswordCharset::AlphanumericSymbols).expect("Generate failed");
        assert_eq!(password.len(), 16);
    }

    #[tokio::test]
    async fn test_hash_and_verify_async() {
        let hash = hash("test_password").await.expect("Hash failed");
        assert!(hash.starts_with("$argon2id$"));

        assert!(verify("test_password", &hash).await.expect("Verify failed"));
        assert!(
            !verify("wrong_password", &hash)
                .await
                .expect("Verify failed")
        );
    }

    #[tokio::test]
    async fn test_derive_key_from_password_async() {
        let salt = b"unique-test-salt";
        let key = derive_key_from_password("password", salt, 32)
            .await
            .expect("Derive failed");
        assert_eq!(key.len(), 32);
    }

    #[tokio::test]
    async fn test_derive_multiple_keys_async() {
        let salt = b"multi-key-salt";
        let domains = ["encryption", "authentication"];
        let keys = derive_multiple_keys("password", salt, &domains, 32)
            .await
            .expect("Derive failed");

        assert_eq!(keys.len(), 2);
        assert_ne!(keys[0], keys[1]);
    }
}
