//! Plain cryptographic digests — SHA-256, SHA-512, and BLAKE3.
//!
//! Pure one-shot digest helpers with **no** observe dependencies, mirroring the
//! HMAC primitive's style ([`hmac_sha3_256`](super::auth::hmac_sha3_256)). These
//! are the single source of truth for "hash these bytes" across octarine — the
//! anonymizer `Hash` operator and (per epic #604) the PII redactor both build on
//! them, so a digest is computed in exactly one place.
//!
//! ## Algorithm choice
//!
//! | Function   | Algorithm | Output | Use case                                  |
//! |------------|-----------|--------|-------------------------------------------|
//! | [`sha256`] | SHA-256   | 32 B   | Presidio-compatible PII tokenization      |
//! | [`sha512`] | SHA-512   | 64 B   | Wider digest, same SHA-2 family           |
//! | [`blake3`] | BLAKE3    | 32 B   | Fast modern digest (Presidio has none)    |
//!
//! For *keyed* authentication use [`hmac_sha3_256`](super::auth::hmac_sha3_256);
//! for *password* hashing use the Argon2 KDF in
//! [`keys`](super::keys). These plain digests are unkeyed and must be combined
//! with a salt by the caller when collision/pre-image resistance over
//! low-entropy inputs matters.
//!
//! ## Example
//!
//! ```ignore
//! use crate::primitives::crypto::hash::{sha256_hex, blake3_hex};
//!
//! let digest = sha256_hex(b"alice@example.com");
//! assert_eq!(digest.len(), 64); // 32 bytes = 64 hex chars
//!
//! let fast = blake3_hex(b"alice@example.com");
//! assert_eq!(fast.len(), 64);
//! ```

// Allow dead_code: Layer 1 primitives used by Layer 3 modules (anonymize, #604 redactor).
#![allow(dead_code)]

use sha2::{Digest, Sha256, Sha512};

/// SHA-256 output size in bytes (256 bits).
pub const SHA256_LENGTH: usize = 32;

/// SHA-512 output size in bytes (512 bits).
pub const SHA512_LENGTH: usize = 64;

/// BLAKE3 default output size in bytes (256 bits).
pub const BLAKE3_LENGTH: usize = 32;

/// Compute the SHA-256 digest of `data`.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::hash::sha256;
///
/// let digest = sha256(b"data");
/// assert_eq!(digest.len(), 32);
/// ```
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; SHA256_LENGTH] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute the SHA-256 digest of `data` as a lowercase hex string.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// Compute the SHA-512 digest of `data`.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::hash::sha512;
///
/// let digest = sha512(b"data");
/// assert_eq!(digest.len(), 64);
/// ```
#[must_use]
pub fn sha512(data: &[u8]) -> [u8; SHA512_LENGTH] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute the SHA-512 digest of `data` as a lowercase hex string.
#[must_use]
pub fn sha512_hex(data: &[u8]) -> String {
    hex::encode(sha512(data))
}

/// Compute the BLAKE3 digest of `data` (32-byte default output).
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::hash::blake3;
///
/// let digest = blake3(b"data");
/// assert_eq!(digest.len(), 32);
/// ```
#[must_use]
pub fn blake3(data: &[u8]) -> [u8; BLAKE3_LENGTH] {
    *::blake3::hash(data).as_bytes()
}

/// Compute the BLAKE3 digest of `data` as a lowercase hex string.
#[must_use]
pub fn blake3_hex(data: &[u8]) -> String {
    hex::encode(blake3(data))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]

    use super::*;

    // Known-answer vectors (NIST / official test vectors).

    #[test]
    fn sha256_matches_known_vector() {
        // SHA-256("abc")
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_empty_input() {
        // SHA-256("")
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha512_matches_known_vector() {
        // SHA-512("abc")
        assert_eq!(
            sha512_hex(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn blake3_matches_known_vector() {
        // BLAKE3("abc") — official test vector.
        assert_eq!(
            blake3_hex(b"abc"),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn digest_lengths_are_correct() {
        assert_eq!(sha256(b"x").len(), SHA256_LENGTH);
        assert_eq!(sha512(b"x").len(), SHA512_LENGTH);
        assert_eq!(blake3(b"x").len(), BLAKE3_LENGTH);
        assert_eq!(sha256_hex(b"x").len(), SHA256_LENGTH * 2);
        assert_eq!(sha512_hex(b"x").len(), SHA512_LENGTH * 2);
        assert_eq!(blake3_hex(b"x").len(), BLAKE3_LENGTH * 2);
    }

    #[test]
    fn distinct_inputs_distinct_digests() {
        assert_ne!(sha256_hex(b"a"), sha256_hex(b"b"));
        assert_ne!(blake3_hex(b"a"), blake3_hex(b"b"));
    }
}
