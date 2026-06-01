//! Keyed AEAD Encryption with observability
//!
//! Caller-keyed authenticated encryption with additional authenticated data
//! (AAD) and a versioned wire format, wrapped with observe instrumentation for
//! audit trails. Delegates to the Layer 1 keyed-AEAD primitive.
//!
//! Unlike [`ephemeral`](super::ephemeral) — which generates a fresh key per
//! call — this surface lets the caller supply a stable 32-byte key so the same
//! ciphertext can be decrypted later, and binds the ciphertext to a context via
//! AAD. Choose [`Algorithm::ChaCha20Poly1305`] (default) or
//! [`Algorithm::Aes256Gcm`]; choose [`Mode::Random`] for unique ciphertext or
//! [`Mode::Deterministic`] for joinable (stable) output.
//!
//! # Security Events
//!
//! - `encryption.keyed_encrypt` — data sealed with a caller key
//! - `encryption.keyed_decrypt` — keyed ciphertext opened
//!
//! # Examples
//!
//! ```
//! use octarine::crypto::encryption::keyed::{self, Algorithm, Mode};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key = [42u8; 32];
//! let wire = keyed::encrypt(Algorithm::ChaCha20Poly1305, &key, b"secret", b"EMAIL", Mode::Random)?;
//! let plaintext = keyed::decrypt(&key, &wire, b"EMAIL")?;
//! assert_eq!(plaintext, b"secret");
//!
//! // The AAD is authenticated: opening under a different context fails.
//! assert!(keyed::decrypt(&key, &wire, b"PHONE").is_err());
//! # Ok(())
//! # }
//! ```

use crate::observe;
use crate::primitives::crypto::CryptoError;
use crate::primitives::crypto::encryption::{self as prim, AeadAlgo, NonceMode};

/// AEAD key size (256 bits).
pub const KEY_SIZE: usize = 32;

/// Authenticated encryption algorithm.
///
/// AES-CBC is intentionally unavailable: it is unauthenticated and deprecated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// ChaCha20-Poly1305 (default).
    #[default]
    ChaCha20Poly1305,
    /// AES-256-GCM.
    Aes256Gcm,
}

impl From<Algorithm> for AeadAlgo {
    fn from(algo: Algorithm) -> Self {
        match algo {
            Algorithm::ChaCha20Poly1305 => Self::ChaCha20Poly1305,
            Algorithm::Aes256Gcm => Self::Aes256Gcm,
        }
    }
}

/// Nonce-selection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Fresh random nonce — unique ciphertext for identical inputs.
    #[default]
    Random,
    /// Synthetic IV — identical inputs produce identical ciphertext (joinable).
    Deterministic,
}

impl From<Mode> for NonceMode {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::Random => Self::Random,
            Mode::Deterministic => Self::Deterministic,
        }
    }
}

/// Encrypt `plaintext` under a caller-supplied 32-byte `key`, binding `aad`.
///
/// Returns a base64 versioned wire string. Use [`decrypt`] with the same key
/// and AAD to recover the plaintext.
///
/// # Security Events
///
/// Generates `encryption.keyed_encrypt` on success or failure.
pub fn encrypt(
    algo: Algorithm,
    key: &[u8; KEY_SIZE],
    plaintext: &[u8],
    aad: &[u8],
    mode: Mode,
) -> Result<String, CryptoError> {
    let result = prim::seal(algo.into(), key, plaintext, aad, mode.into());

    match &result {
        Ok(_) => observe::info(
            "keyed_encrypt",
            format!(
                "Keyed AEAD encryption completed ({} bytes)",
                plaintext.len()
            ),
        ),
        Err(e) => observe::warn(
            "keyed_encrypt",
            format!("Keyed AEAD encryption failed: {e}"),
        ),
    }

    result
}

/// Decrypt a wire string produced by [`encrypt`].
///
/// Verifies the authentication tag (over ciphertext and `aad`) before returning
/// plaintext. A wrong key, tampered ciphertext, or mismatched `aad` yields an
/// error — plaintext is never returned on authentication failure.
///
/// # Security Events
///
/// Generates `encryption.keyed_decrypt` on success or failure.
pub fn decrypt(key: &[u8; KEY_SIZE], wire: &str, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let result = prim::open(key, wire, aad);

    match &result {
        Ok(plaintext) => observe::info(
            "keyed_decrypt",
            format!(
                "Keyed AEAD decryption completed ({} bytes)",
                plaintext.len()
            ),
        ),
        Err(e) => observe::warn(
            "keyed_decrypt",
            format!("Keyed AEAD decryption failed: {e}"),
        ),
    }

    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_SIZE] = [3u8; KEY_SIZE];

    #[test]
    fn round_trip_default_algo() {
        let wire =
            encrypt(Algorithm::default(), &KEY, b"hi", b"EMAIL", Mode::Random).expect("encrypt");
        let plain = decrypt(&KEY, &wire, b"EMAIL").expect("decrypt");
        assert_eq!(plain.as_slice(), b"hi");
    }

    #[test]
    fn round_trip_aes() {
        let wire =
            encrypt(Algorithm::Aes256Gcm, &KEY, b"hi", b"EMAIL", Mode::Random).expect("encrypt");
        let plain = decrypt(&KEY, &wire, b"EMAIL").expect("decrypt");
        assert_eq!(plain.as_slice(), b"hi");
    }

    #[test]
    fn aad_mismatch_fails() {
        let wire = encrypt(
            Algorithm::ChaCha20Poly1305,
            &KEY,
            b"hi",
            b"EMAIL",
            Mode::Random,
        )
        .expect("encrypt");
        assert!(decrypt(&KEY, &wire, b"PHONE").is_err());
    }

    #[test]
    fn deterministic_is_joinable() {
        let a = encrypt(
            Algorithm::ChaCha20Poly1305,
            &KEY,
            b"x",
            b"EMAIL",
            Mode::Deterministic,
        )
        .expect("encrypt a");
        let b = encrypt(
            Algorithm::ChaCha20Poly1305,
            &KEY,
            b"x",
            b"EMAIL",
            Mode::Deterministic,
        )
        .expect("encrypt b");
        assert_eq!(a, b);
    }
}
