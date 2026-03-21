//! Key Derivation Functions
//!
//! Secure key derivation using HKDF (HMAC-based Key Derivation Function)
//! as specified in RFC 5869. Uses SHA3-256 as the underlying hash function
//! for post-quantum security margins.
//!
//! ## When to Use Key Derivation
//!
//! Key derivation is essential when you need to:
//! - Derive multiple keys from a single master secret
//! - Convert non-uniform random data into cryptographic keys
//! - Add domain separation to prevent key reuse across contexts
//!
//! ## HKDF Overview
//!
//! HKDF works in two phases:
//!
//! 1. **Extract**: Concentrates entropy from input keying material
//! 2. **Expand**: Produces output keying material of desired length
//!
//! ```text
//! Input Key Material (IKM) ─┬─> Extract ──> Pseudorandom Key (PRK)
//!                           │
//!                          Salt
//!
//! PRK + Info ─────────────────> Expand ──> Output Key Material (OKM)
//! ```
//!
//! ## Security Considerations
//!
//! - Uses SHA3-256 for quantum resistance margins
//! - Salt should be random but can be public
//! - Info provides domain separation (MUST be unique per use)
//! - Output length is limited to 255 * hash_length bytes
//!
//! ## Example
//!
//! ```ignore
//! use crate::primitives::crypto::kdf::{hkdf_sha3_256, DomainSeparator};
//!
//! // Derive an encryption key from a shared secret
//! let shared_secret = b"shared-secret-from-key-exchange";
//! let salt = b"application-specific-salt";
//!
//! let encryption_key = hkdf_sha3_256(
//!     shared_secret,
//!     Some(salt),
//!     DomainSeparator::new("encryption-v1"),
//!     32, // 256-bit key
//! )?;
//! ```
//!
//! ## IMPORTANT: When NOT to Use HKDF
//!
//! HKDF requires **high-entropy input**. For user passwords or other low-entropy
//! secrets, use [`Argon2id`](super::password) instead.
//!
//! ## See Also
//!
//! - [`password`](super::password) - Argon2id for low-entropy input (user passwords)
//! - [`HybridEncryption`](super::HybridEncryption) - Uses HKDF internally for
//!   hybrid key combination
//! - [`PersistentEncryption`](super::PersistentEncryption) - Uses SHA3-256 derivation
//!   for dual-key encryption

// Allow dead_code: Layer 1 primitives used by Layer 2/3 modules
#![allow(dead_code)]

use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::primitives::crypto::CryptoError;

/// SHA3-256 output size in bytes
const HASH_LEN: usize = 32;

// ============================================================================
// Domain Separator
// ============================================================================

/// Domain separator for key derivation.
///
/// Domain separators ensure that keys derived for different purposes
/// cannot be confused with each other, even if derived from the same
/// input keying material.
///
/// # Security
///
/// Using distinct domain separators for different purposes prevents:
/// - Key reuse attacks
/// - Cross-protocol attacks
/// - Confused deputy problems
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::kdf::DomainSeparator;
///
/// // Different separators for different key types
/// let enc_domain = DomainSeparator::new("myapp:encryption:v1");
/// let mac_domain = DomainSeparator::new("myapp:authentication:v1");
/// ```
#[derive(Debug, Clone)]
pub struct DomainSeparator {
    value: Vec<u8>,
}

impl DomainSeparator {
    /// Create a new domain separator from a string.
    ///
    /// The string should be:
    /// - Unique to the specific use case
    /// - Include version information
    /// - Follow a consistent naming convention
    ///
    /// # Recommended Format
    ///
    /// `"application:purpose:version"` (e.g., `"myapp:encryption:v1"`)
    #[must_use]
    pub fn new(domain: &str) -> Self {
        Self {
            value: domain.as_bytes().to_vec(),
        }
    }

    /// Create a domain separator from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            value: bytes.to_vec(),
        }
    }

    /// Get the domain separator as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }

    /// Combine with additional context.
    ///
    /// Useful for adding runtime-specific information to the domain.
    #[must_use]
    pub fn with_context(&self, context: &[u8]) -> Self {
        let mut combined = self.value.clone();
        combined.push(b':');
        combined.extend_from_slice(context);
        Self { value: combined }
    }
}

impl Default for DomainSeparator {
    fn default() -> Self {
        Self::new("default")
    }
}

// ============================================================================
// HKDF Implementation
// ============================================================================

/// Derive key material using HKDF-SHA3-256.
///
/// Implements HKDF as specified in RFC 5869, using SHA3-256 as the
/// underlying hash function for improved security margins.
///
/// # Arguments
///
/// * `ikm` - Input keying material (the source of entropy)
/// * `salt` - Optional salt value (random but can be public)
/// * `domain` - Domain separator for context binding
/// * `length` - Desired output length in bytes (max 8160 bytes)
///
/// # Returns
///
/// Derived key material of the requested length.
///
/// # Errors
///
/// Returns `CryptoError::InvalidKeyLength` if length exceeds maximum.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::kdf::{hkdf_sha3_256, DomainSeparator};
///
/// let master_key = b"master-secret-key";
/// let derived = hkdf_sha3_256(
///     master_key,
///     Some(b"unique-salt"),
///     DomainSeparator::new("encryption"),
///     32,
/// )?;
/// ```
pub fn hkdf_sha3_256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    domain: DomainSeparator,
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    // Maximum output is 255 * HASH_LEN bytes
    let max_length = 255 * HASH_LEN;
    if length > max_length {
        return Err(CryptoError::key_derivation(format!(
            "Requested length {} exceeds maximum {} bytes",
            length, max_length
        )));
    }

    // Extract phase: PRK = HMAC-Hash(salt, IKM)
    let prk = hkdf_extract(salt.unwrap_or(&[0u8; HASH_LEN]), ikm);

    // Expand phase: OKM = HKDF-Expand(PRK, info, L)
    let okm = hkdf_expand(&prk, domain.as_bytes(), length)?;

    Ok(okm)
}

/// HKDF Extract phase.
///
/// Extracts a pseudorandom key from the input keying material.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
    // PRK = HMAC-SHA3-256(salt, IKM)
    hmac_sha3_256(salt, ikm)
}

/// HKDF Expand phase.
///
/// Expands the PRK into output keying material of the desired length.
fn hkdf_expand(prk: &[u8; HASH_LEN], info: &[u8], length: usize) -> Result<Vec<u8>, CryptoError> {
    // Calculate number of iterations needed using checked arithmetic
    // n = ceil(length / HASH_LEN)
    let n = length
        .checked_add(HASH_LEN)
        .and_then(|v| v.checked_sub(1))
        .map(|v| v / HASH_LEN)
        .ok_or_else(|| CryptoError::key_derivation("Length overflow in HKDF expand"))?;

    let mut okm = Vec::with_capacity(length);
    let mut t = Vec::new();

    for i in 1..=n {
        // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        let mut message = t.clone();
        message.extend_from_slice(info);

        // Safe cast: i is bounded by n which is at most 255 (from max length check)
        let i_byte = u8::try_from(i)
            .map_err(|_| CryptoError::key_derivation("Iteration count exceeded u8 range"))?;
        message.push(i_byte);

        t = hmac_sha3_256(prk, &message).to_vec();
        okm.extend_from_slice(&t);
    }

    okm.truncate(length);
    Ok(okm)
}

/// HMAC-SHA3-256 implementation.
///
/// Computes HMAC using SHA3-256 as the underlying hash function.
fn hmac_sha3_256(key: &[u8], message: &[u8]) -> [u8; HASH_LEN] {
    const BLOCK_SIZE: usize = 136; // SHA3-256 block size

    // Prepare the key: if longer than block size, hash it; otherwise pad with zeros
    let mut k = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let mut hasher = Sha3_256::new();
        hasher.update(key);
        let hash = hasher.finalize();
        // Copy hash into first HASH_LEN bytes of k (safe: HASH_LEN < BLOCK_SIZE)
        for (k_byte, hash_byte) in k.iter_mut().zip(hash.iter()) {
            *k_byte = *hash_byte;
        }
    } else {
        // Copy key into k (safe: key.len() <= BLOCK_SIZE)
        for (k_byte, key_byte) in k.iter_mut().zip(key.iter()) {
            *k_byte = *key_byte;
        }
    }

    // Inner padding (key XOR ipad)
    let mut ipad = [0x36u8; BLOCK_SIZE];
    for (ipad_byte, k_byte) in ipad.iter_mut().zip(k.iter()) {
        *ipad_byte ^= k_byte;
    }

    // Outer padding (key XOR opad)
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for (opad_byte, k_byte) in opad.iter_mut().zip(k.iter()) {
        *opad_byte ^= k_byte;
    }

    // Inner hash: H(ipad || message)
    let mut inner_hasher = Sha3_256::new();
    inner_hasher.update(ipad);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    // Outer hash: H(opad || inner_hash)
    let mut outer_hasher = Sha3_256::new();
    outer_hasher.update(opad);
    outer_hasher.update(inner_hash);
    let result = outer_hasher.finalize();

    // Zeroize sensitive data
    k.zeroize();
    ipad.zeroize();
    opad.zeroize();

    let mut output = [0u8; HASH_LEN];
    // Safe: result is exactly HASH_LEN bytes
    for (out_byte, res_byte) in output.iter_mut().zip(result.iter()) {
        *out_byte = *res_byte;
    }
    output
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Derive a key using HKDF-SHA3-256 with a salt.
///
/// Convenience wrapper for simple key derivation from high-entropy input.
///
/// # Arguments
///
/// * `ikm` - Input keying material (MUST be high-entropy, e.g., shared secret)
/// * `salt` - A unique salt (should be random, at least 16 bytes)
/// * `key_length` - Desired key length in bytes
///
/// # Security
///
/// **WARNING:** This function uses HKDF which requires high-entropy input.
/// For user passwords, use [`password::derive_key_from_password`] (Argon2) instead.
pub fn derive_key_hkdf(ikm: &[u8], salt: &[u8], key_length: usize) -> Result<Vec<u8>, CryptoError> {
    hkdf_sha3_256(
        ikm,
        Some(salt),
        DomainSeparator::new("hkdf-derived-key"),
        key_length,
    )
}

/// Derive multiple keys from a single master key.
///
/// Useful for deriving separate encryption and authentication keys
/// from a single master secret.
///
/// # Arguments
///
/// * `master_key` - The master key to derive from
/// * `purposes` - List of (purpose_name, key_length) pairs
///
/// # Returns
///
/// A vector of derived keys, one for each purpose.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::kdf::derive_multiple_keys;
///
/// let master = b"master-secret";
/// let keys = derive_multiple_keys(master, &[
///     ("encryption", 32),
///     ("authentication", 32),
///     ("nonce", 12),
/// ])?;
///
/// let encryption_key = &keys[0];
/// let auth_key = &keys[1];
/// let nonce = &keys[2];
/// ```
pub fn derive_multiple_keys(
    master_key: &[u8],
    purposes: &[(&str, usize)],
) -> Result<Vec<Vec<u8>>, CryptoError> {
    purposes
        .iter()
        .map(|(purpose, length)| {
            hkdf_sha3_256(master_key, None, DomainSeparator::new(purpose), *length)
        })
        .collect()
}

/// Derive a key with version support for key rotation.
///
/// Includes the version number in the domain separator to support
/// key rotation while maintaining backwards compatibility.
///
/// # Arguments
///
/// * `master_key` - The master key
/// * `purpose` - The key's purpose
/// * `version` - The key version number
/// * `length` - Desired key length
pub fn derive_versioned_key(
    master_key: &[u8],
    purpose: &str,
    version: u32,
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    let domain = format!("{}:v{}", purpose, version);
    hkdf_sha3_256(master_key, None, DomainSeparator::new(&domain), length)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // =========================================================================
    // Domain Separator Tests
    // =========================================================================

    #[test]
    fn test_domain_separator_new() {
        let domain = DomainSeparator::new("test:purpose:v1");
        assert_eq!(domain.as_bytes(), b"test:purpose:v1");
    }

    #[test]
    fn test_domain_separator_from_bytes() {
        let domain = DomainSeparator::from_bytes(b"binary\x00data");
        assert_eq!(domain.as_bytes(), b"binary\x00data");
    }

    #[test]
    fn test_domain_separator_with_context() {
        let domain = DomainSeparator::new("base");
        let extended = domain.with_context(b"extra");
        assert_eq!(extended.as_bytes(), b"base:extra");
    }

    #[test]
    fn test_domain_separator_default() {
        let domain = DomainSeparator::default();
        assert_eq!(domain.as_bytes(), b"default");
    }

    // =========================================================================
    // HKDF Tests
    // =========================================================================

    #[test]
    fn test_hkdf_basic() {
        let ikm = b"input-keying-material";
        let salt = b"random-salt-value";
        let domain = DomainSeparator::new("test");

        let key = hkdf_sha3_256(ikm, Some(salt), domain, 32).expect("HKDF failed");

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_no_salt() {
        let ikm = b"input-keying-material";
        let domain = DomainSeparator::new("test");

        let key = hkdf_sha3_256(ikm, None, domain, 32).expect("HKDF failed");

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"same-input";
        let salt = b"same-salt";
        let domain1 = DomainSeparator::new("same-domain");
        let domain2 = DomainSeparator::new("same-domain");

        let key1 = hkdf_sha3_256(ikm, Some(salt), domain1, 32).expect("HKDF failed");
        let key2 = hkdf_sha3_256(ikm, Some(salt), domain2, 32).expect("HKDF failed");

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_hkdf_different_domains_different_keys() {
        let ikm = b"same-input";
        let salt = b"same-salt";

        let key1 = hkdf_sha3_256(ikm, Some(salt), DomainSeparator::new("domain-a"), 32)
            .expect("HKDF failed");

        let key2 = hkdf_sha3_256(ikm, Some(salt), DomainSeparator::new("domain-b"), 32)
            .expect("HKDF failed");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_hkdf_different_salts_different_keys() {
        let ikm = b"same-input";
        let domain = DomainSeparator::new("same-domain");

        let key1 = hkdf_sha3_256(ikm, Some(b"salt-a"), domain.clone(), 32).expect("HKDF failed");
        let key2 = hkdf_sha3_256(ikm, Some(b"salt-b"), domain, 32).expect("HKDF failed");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_hkdf_various_lengths() {
        let ikm = b"input";
        let domain = DomainSeparator::new("test");

        // Test various output lengths
        for length in [1, 16, 32, 64, 128, 256] {
            let key = hkdf_sha3_256(ikm, None, domain.clone(), length).expect("HKDF failed");
            assert_eq!(key.len(), length);
        }
    }

    #[test]
    fn test_hkdf_max_length() {
        let ikm = b"input";
        let domain = DomainSeparator::new("test");

        // Maximum output: 255 * 32 = 8160 bytes
        let key = hkdf_sha3_256(ikm, None, domain, 8160).expect("HKDF failed");
        assert_eq!(key.len(), 8160);
    }

    #[test]
    fn test_hkdf_exceeds_max_length() {
        let ikm = b"input";
        let domain = DomainSeparator::new("test");

        // Request more than maximum
        let result = hkdf_sha3_256(ikm, None, domain, 8161);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_empty_input() {
        let domain = DomainSeparator::new("test");

        // Empty IKM should still work
        let key = hkdf_sha3_256(&[], None, domain, 32).expect("HKDF failed");
        assert_eq!(key.len(), 32);
    }

    // =========================================================================
    // Convenience Function Tests
    // =========================================================================

    #[test]
    fn test_derive_key_hkdf() {
        let ikm = b"high-entropy-shared-secret-1234";
        let salt = b"unique-salt-1234";

        let key = derive_key_hkdf(ikm, salt, 32).expect("Derivation failed");

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_multiple_keys() {
        let master = b"master-secret";
        let purposes = [("encryption", 32), ("mac", 32), ("nonce", 12)];

        let keys = derive_multiple_keys(master, &purposes).expect("Derivation failed");

        assert_eq!(keys.len(), 3);

        // Use iterator to avoid indexing
        let mut iter = keys.iter();
        let key0 = iter.next().expect("key0");
        let key1 = iter.next().expect("key1");
        let key2 = iter.next().expect("key2");

        assert_eq!(key0.len(), 32);
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 12);

        // All keys should be different
        assert_ne!(key0, key1);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_versioned_key() {
        let master = b"master";

        let v1 = derive_versioned_key(master, "encryption", 1, 32).expect("v1 failed");
        let v2 = derive_versioned_key(master, "encryption", 2, 32).expect("v2 failed");

        assert_eq!(v1.len(), 32);
        assert_eq!(v2.len(), 32);
        assert_ne!(v1, v2); // Different versions produce different keys
    }

    // =========================================================================
    // HMAC Tests
    // =========================================================================

    #[test]
    fn test_hmac_sha3_256_deterministic() {
        let key = b"secret-key";
        let message = b"test message";

        let mac1 = hmac_sha3_256(key, message);
        let mac2 = hmac_sha3_256(key, message);

        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha3_256_different_keys() {
        let message = b"test message";

        let mac1 = hmac_sha3_256(b"key1", message);
        let mac2 = hmac_sha3_256(b"key2", message);

        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha3_256_different_messages() {
        let key = b"same-key";

        let mac1 = hmac_sha3_256(key, b"message1");
        let mac2 = hmac_sha3_256(key, b"message2");

        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_hmac_sha3_256_long_key() {
        // Key longer than block size should be hashed
        let long_key = vec![0xABu8; 200];
        let message = b"test";

        let mac = hmac_sha3_256(&long_key, message);
        assert_eq!(mac.len(), HASH_LEN);
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_hkdf_single_byte_output() {
        let ikm = b"input";
        let domain = DomainSeparator::new("test");

        let key = hkdf_sha3_256(ikm, None, domain, 1).expect("HKDF failed");
        assert_eq!(key.len(), 1);
    }

    #[test]
    fn test_hkdf_zero_length() {
        let ikm = b"input";
        let domain = DomainSeparator::new("test");

        let key = hkdf_sha3_256(ikm, None, domain, 0).expect("HKDF failed");
        assert!(key.is_empty());
    }
}
