//! Key Derivation Functions with observability
//!
//! HKDF-SHA3-256 key derivation wrapped with observe instrumentation
//! for audit trails and compliance support.
//!
//! # When to Use
//!
//! - **HKDF (this module)**: For high-entropy input (random keys, shared secrets)
//! - **Argon2 (password module)**: For low-entropy input (user passwords)
//!
//! Using HKDF on passwords is a security vulnerability!
//!
//! # Security Events
//!
//! Key derivation operations generate `security.key_derived` events.
//!
//! # Examples
//!
//! ```ignore
//! use octarine::crypto::keys::kdf;
//! use octarine::crypto::keys::DomainSeparator;
//!
//! // Derive a key from a master secret
//! let derived = kdf::derive(
//!     &master_key,
//!     Some(b"salt"),
//!     DomainSeparator::new("encryption:v1"),
//!     32,
//! )?;
//!
//! // Derive multiple keys for different purposes
//! let keys = kdf::derive_multiple(&master_key, &[
//!     ("encryption", 32),
//!     ("authentication", 32),
//! ])?;
//! ```

use crate::observe;
use crate::primitives::crypto::CryptoError;
use crate::primitives::crypto::keys as prim;

// Re-export DomainSeparator from primitives
pub use crate::primitives::crypto::keys::DomainSeparator;

// ============================================================================
// Key Derivation
// ============================================================================

/// Derive key material using HKDF-SHA3-256 with audit trail.
///
/// Implements RFC 5869 HKDF with SHA3-256 for post-quantum security margins.
///
/// # Arguments
///
/// * `ikm` - Input keying material (must be high-entropy)
/// * `salt` - Optional salt value (random but can be public)
/// * `domain` - Domain separator for context binding
/// * `length` - Desired output length in bytes (max 8160)
///
/// # Security
///
/// The input keying material MUST be high-entropy (e.g., from key exchange
/// or random generation). For user passwords, use `password::derive_key_from_password`.
pub fn derive(
    ikm: &[u8],
    salt: Option<&[u8]>,
    domain: DomainSeparator,
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    let result = prim::hkdf_sha3_256(ikm, salt, domain, length);

    match &result {
        Ok(_) => {
            observe::info(
                "key_derived",
                format!("Derived {length}-byte key via HKDF-SHA3-256"),
            );
        }
        Err(e) => {
            observe::warn("key_derived", format!("HKDF key derivation failed: {e}"));
        }
    }

    result
}

/// Derive multiple keys from a single master key with audit trail.
///
/// Useful for deriving separate encryption, authentication, and nonce
/// generation keys from a single master secret.
///
/// # Arguments
///
/// * `master_key` - The master key to derive from
/// * `purposes` - List of (purpose_name, key_length) pairs
///
/// # Example
///
/// ```ignore
/// let keys = kdf::derive_multiple(&master, &[
///     ("encryption", 32),
///     ("authentication", 32),
///     ("nonce", 12),
/// ])?;
/// ```
pub fn derive_multiple(
    master_key: &[u8],
    purposes: &[(&str, usize)],
) -> Result<Vec<Vec<u8>>, CryptoError> {
    let result = prim::derive_multiple_keys(master_key, purposes);

    match &result {
        Ok(keys) => {
            let purpose_names: Vec<&str> = purposes.iter().map(|(p, _)| *p).collect();
            observe::info(
                "key_derived",
                format!(
                    "Derived {} keys from master key (purposes: {:?})",
                    keys.len(),
                    purpose_names
                ),
            );
        }
        Err(e) => {
            observe::warn(
                "key_derived",
                format!("Multiple key derivation failed: {e}"),
            );
        }
    }

    result
}

/// Derive a versioned key for key rotation support.
///
/// Includes the version number in the domain separator to support
/// key rotation while maintaining backwards compatibility.
///
/// # Arguments
///
/// * `master_key` - The master key
/// * `purpose` - The key's purpose (e.g., "encryption")
/// * `version` - The key version number
/// * `length` - Desired key length
pub fn derive_versioned(
    master_key: &[u8],
    purpose: &str,
    version: u32,
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    let result = prim::derive_versioned_key(master_key, purpose, version, length);

    match &result {
        Ok(_) => {
            observe::info(
                "key_derived",
                format!("Derived versioned key: {purpose}:v{version} ({length} bytes)"),
            );
        }
        Err(e) => {
            observe::warn(
                "key_derived",
                format!("Versioned key derivation failed: {e}"),
            );
        }
    }

    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_derive() {
        let ikm = b"high-entropy-master-key-12345678";
        let salt = b"test-salt";

        let key =
            derive(ikm, Some(salt), DomainSeparator::new("test"), 32).expect("Derivation failed");

        assert_eq!(key.len(), 32);

        // Same inputs should produce same output
        let key2 =
            derive(ikm, Some(salt), DomainSeparator::new("test"), 32).expect("Derivation failed");
        assert_eq!(key, key2);

        // Different domain should produce different output
        let key3 =
            derive(ikm, Some(salt), DomainSeparator::new("other"), 32).expect("Derivation failed");
        assert_ne!(key, key3);
    }

    #[test]
    fn test_derive_multiple() {
        let master = b"master-key-for-testing";

        let keys =
            derive_multiple(master, &[("enc", 32), ("auth", 32)]).expect("Multi-derivation failed");

        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].len(), 32);
        assert_eq!(keys[1].len(), 32);
        assert_ne!(keys[0], keys[1]); // Different purposes = different keys
    }

    #[test]
    fn test_derive_versioned() {
        let master = b"master-key";

        let v1 = derive_versioned(master, "enc", 1, 32).expect("V1 failed");
        let v2 = derive_versioned(master, "enc", 2, 32).expect("V2 failed");

        assert_ne!(v1, v2); // Different versions = different keys
    }
}
