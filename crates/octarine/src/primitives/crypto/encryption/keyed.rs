//! Keyed AEAD Encryption (caller-supplied key, AAD, versioned wire format)
//!
//! Authenticated encryption where the **caller** supplies the 32-byte key and
//! optional additional authenticated data (AAD). Unlike
//! [`EphemeralEncryption`](super::EphemeralEncryption) — which generates a fresh
//! key and nonce per call and supports no AAD — this primitive is built for
//! reversible field-level encryption where the same key must decrypt later and
//! the ciphertext must be bound to a context (e.g. an entity type) via AAD.
//!
//! ## Security Model
//!
//! - **AEAD**: ChaCha20-Poly1305 (default) or AES-256-GCM. The Poly1305 / GCM
//!   tag authenticates both ciphertext and AAD; tampering with either fails
//!   decryption.
//! - **AAD binding**: AAD is folded into the tag. Ciphertext sealed under one
//!   AAD cannot be opened under a different AAD.
//! - **Versioned wire format**: `version ‖ algo_id ‖ nonce(12) ‖ ciphertext‖tag`,
//!   base64 (`URL_SAFE_NO_PAD`). The version byte enables algorithm migration;
//!   `open` reads `algo_id` to dispatch, so callers never guess the algorithm.
//! - **Two nonce modes**: [`NonceMode::Random`] for standard unique-ciphertext
//!   semantics, and [`NonceMode::Deterministic`] which derives a synthetic IV
//!   from `HKDF(key, AAD ‖ plaintext)` so identical inputs produce identical
//!   ciphertext (joinable across documents). The caller never controls the
//!   nonce directly, avoiding the classic nonce-reuse footgun.
//!
//! This is a Layer 1 primitive: pure, `pub(crate)`, no observe dependencies.

// Allow dead_code: Layer 1 primitives consumed by Layer 3 wrappers/operators.
#![allow(dead_code)]

use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce as ChachaNonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::primitives::crypto::{
    CryptoError,
    keys::{DomainSeparator, hkdf_sha3_256, random_nonce_12},
};

/// AEAD key size (256 bits) — both ciphers use a 32-byte key.
const KEY_SIZE: usize = 32;

/// AEAD nonce size (96 bits) — both ciphers use a 12-byte nonce.
const NONCE_SIZE: usize = 12;

/// Current wire-format version. Byte 0 of every sealed payload.
const WIRE_VERSION: u8 = 1;

/// Header length preceding the nonce: `version ‖ algo_id`.
const HEADER_LEN: usize = 2;

/// Offset where the ciphertext begins: after header and nonce.
const NONCE_END: usize = HEADER_LEN + NONCE_SIZE;

/// Domain separator for synthetic-IV derivation (deterministic mode).
const SIV_DOMAIN: &str = "octarine:anonymize:keyed:siv:v1";

/// Supported AEAD algorithms.
///
/// AES-CBC is deliberately **absent**: it is unauthenticated and declared
/// deprecated in the Presidio audit. Only authenticated constructions are
/// offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AeadAlgo {
    /// ChaCha20-Poly1305 (default).
    ChaCha20Poly1305,
    /// AES-256-GCM.
    Aes256Gcm,
}

impl AeadAlgo {
    /// Stable on-wire identifier byte. Persisted in the wire format, so these
    /// values must never change.
    pub(crate) const fn algo_id(self) -> u8 {
        match self {
            Self::ChaCha20Poly1305 => 1,
            Self::Aes256Gcm => 2,
        }
    }

    /// Recover an algorithm from its wire identifier byte.
    pub(crate) const fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(Self::ChaCha20Poly1305),
            2 => Some(Self::Aes256Gcm),
            _ => None,
        }
    }
}

/// How the nonce for a seal operation is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NonceMode {
    /// Fresh random nonce per call — unique ciphertext for identical inputs.
    Random,
    /// Synthetic IV derived from `HKDF(key, AAD ‖ plaintext)` — identical
    /// inputs produce identical ciphertext (joinable).
    Deterministic,
}

/// Encrypt `plaintext` and return the base64 versioned wire string.
///
/// The tag authenticates `aad`. Use [`open`] with the same key and AAD to
/// recover the plaintext.
pub(crate) fn seal(
    algo: AeadAlgo,
    key: &[u8; KEY_SIZE],
    plaintext: &[u8],
    aad: &[u8],
    mode: NonceMode,
) -> Result<String, CryptoError> {
    let nonce = match mode {
        NonceMode::Random => random_nonce_12()?,
        NonceMode::Deterministic => synthetic_nonce(key, aad, plaintext)?,
    };
    let ciphertext = aead_encrypt(algo, key, &nonce, plaintext, aad)?;
    Ok(encode_wire(
        WIRE_VERSION,
        algo.algo_id(),
        &nonce,
        &ciphertext,
    ))
}

/// Decrypt a wire string produced by [`seal`].
///
/// Reads the version and algorithm from the wire header, then verifies the tag
/// (over ciphertext and `aad`) before returning plaintext. Any tampering, a
/// wrong key, or a mismatched `aad` yields [`CryptoError::Decryption`].
pub(crate) fn open(key: &[u8; KEY_SIZE], wire: &str, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (version, algo_id, nonce, ciphertext) = decode_wire(wire)?;
    if version != WIRE_VERSION {
        return Err(CryptoError::decryption(format!(
            "unsupported wire version: {version}"
        )));
    }
    let algo = AeadAlgo::from_id(algo_id)
        .ok_or_else(|| CryptoError::decryption(format!("unknown algo id: {algo_id}")))?;
    aead_decrypt(algo, key, &nonce, &ciphertext, aad)
}

/// Dispatch AEAD encryption over the selected algorithm, binding `aad`.
fn aead_encrypt(
    algo: AeadAlgo,
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match algo {
        AeadAlgo::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| CryptoError::invalid_key(format!("cipher init failed: {e}")))?;
            cipher
                .encrypt(ChachaNonce::from_slice(nonce), payload)
                .map_err(|e| CryptoError::encryption(format!("encryption failed: {e}")))
        }
        AeadAlgo::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| CryptoError::invalid_key(format!("cipher init failed: {e}")))?;
            cipher
                .encrypt(AesNonce::from_slice(nonce), payload)
                .map_err(|e| CryptoError::encryption(format!("encryption failed: {e}")))
        }
    }
}

/// Dispatch AEAD decryption; verifies the tag (over ciphertext and `aad`)
/// before returning plaintext.
fn aead_decrypt(
    algo: AeadAlgo,
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    match algo {
        AeadAlgo::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| CryptoError::invalid_key(format!("cipher init failed: {e}")))?;
            cipher
                .decrypt(ChachaNonce::from_slice(nonce), payload)
                .map_err(|e| CryptoError::decryption(format!("decryption failed: {e}")))
        }
        AeadAlgo::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| CryptoError::invalid_key(format!("cipher init failed: {e}")))?;
            cipher
                .decrypt(AesNonce::from_slice(nonce), payload)
                .map_err(|e| CryptoError::decryption(format!("decryption failed: {e}")))
        }
    }
}

/// Derive a deterministic 96-bit nonce from `HKDF(key, AAD ‖ plaintext)`.
///
/// Identical `(key, aad, plaintext)` triples yield the same nonce — and thus
/// the same ciphertext — enabling joinability. Distinct messages get distinct
/// nonces with overwhelming probability.
fn synthetic_nonce(
    key: &[u8; KEY_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<[u8; NONCE_SIZE], CryptoError> {
    let domain = DomainSeparator::new(SIV_DOMAIN)
        .with_context(aad)
        .with_context(plaintext);
    let okm = hkdf_sha3_256(key, None, domain, NONCE_SIZE)?;
    let slice = okm
        .get(..NONCE_SIZE)
        .ok_or_else(|| CryptoError::key_derivation("synthetic nonce derivation too short"))?;
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(slice);
    Ok(nonce)
}

/// Encode the versioned wire format and base64 (`URL_SAFE_NO_PAD`) it.
fn encode_wire(version: u8, algo_id: u8, nonce: &[u8; NONCE_SIZE], ciphertext: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(NONCE_END.saturating_add(ciphertext.len()));
    bytes.push(version);
    bytes.push(algo_id);
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(ciphertext);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode the base64 wire string into `(version, algo_id, nonce, ciphertext)`.
fn decode_wire(wire: &str) -> Result<(u8, u8, [u8; NONCE_SIZE], Vec<u8>), CryptoError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(wire)
        .map_err(|e| CryptoError::decryption(format!("base64 decode failed: {e}")))?;

    let version = *bytes
        .first()
        .ok_or_else(|| CryptoError::decryption("wire payload empty"))?;
    let algo_id = *bytes
        .get(1)
        .ok_or_else(|| CryptoError::decryption("wire payload missing algo id"))?;

    let nonce_slice = bytes
        .get(HEADER_LEN..NONCE_END)
        .ok_or_else(|| CryptoError::decryption("wire payload missing nonce"))?;
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(nonce_slice);

    let ciphertext = bytes
        .get(NONCE_END..)
        .ok_or_else(|| CryptoError::decryption("wire payload missing ciphertext"))?
        .to_vec();

    Ok((version, algo_id, nonce, ciphertext))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_SIZE] = [7u8; KEY_SIZE];

    #[test]
    fn round_trip_chacha() {
        let wire = seal(
            AeadAlgo::ChaCha20Poly1305,
            &KEY,
            b"secret",
            b"EMAIL",
            NonceMode::Random,
        )
        .expect("seal");
        let plain = open(&KEY, &wire, b"EMAIL").expect("open");
        assert_eq!(plain.as_slice(), b"secret");
    }

    #[test]
    fn round_trip_aes() {
        let wire = seal(
            AeadAlgo::Aes256Gcm,
            &KEY,
            b"secret",
            b"EMAIL",
            NonceMode::Random,
        )
        .expect("seal");
        let plain = open(&KEY, &wire, b"EMAIL").expect("open");
        assert_eq!(plain.as_slice(), b"secret");
    }

    #[test]
    fn aad_mismatch_fails() {
        let wire = seal(
            AeadAlgo::ChaCha20Poly1305,
            &KEY,
            b"secret",
            b"EMAIL",
            NonceMode::Random,
        )
        .expect("seal");
        let result = open(&KEY, &wire, b"PHONE");
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::Decryption(_))));
    }

    #[test]
    fn wrong_key_fails() {
        let wire = seal(
            AeadAlgo::Aes256Gcm,
            &KEY,
            b"secret",
            b"EMAIL",
            NonceMode::Random,
        )
        .expect("seal");
        let other = [9u8; KEY_SIZE];
        assert!(open(&other, &wire, b"EMAIL").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let wire = seal(
            AeadAlgo::ChaCha20Poly1305,
            &KEY,
            b"secret",
            b"EMAIL",
            NonceMode::Random,
        )
        .expect("seal");
        // Flip a bit in the decoded payload's last byte (part of the tag).
        let mut bytes = URL_SAFE_NO_PAD.decode(&wire).expect("decode");
        if let Some(last) = bytes.last_mut() {
            *last ^= 0xFF;
        }
        let tampered = URL_SAFE_NO_PAD.encode(bytes);
        assert!(open(&KEY, &tampered, b"EMAIL").is_err());
    }

    #[test]
    fn random_mode_unique_ciphertext() {
        let a = seal(
            AeadAlgo::ChaCha20Poly1305,
            &KEY,
            b"same",
            b"EMAIL",
            NonceMode::Random,
        )
        .expect("seal a");
        let b = seal(
            AeadAlgo::ChaCha20Poly1305,
            &KEY,
            b"same",
            b"EMAIL",
            NonceMode::Random,
        )
        .expect("seal b");
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic_mode_is_stable() {
        let a = seal(
            AeadAlgo::ChaCha20Poly1305,
            &KEY,
            b"joinable",
            b"EMAIL",
            NonceMode::Deterministic,
        )
        .expect("seal a");
        let b = seal(
            AeadAlgo::ChaCha20Poly1305,
            &KEY,
            b"joinable",
            b"EMAIL",
            NonceMode::Deterministic,
        )
        .expect("seal b");
        assert_eq!(a, b);
        assert_eq!(
            open(&KEY, &a, b"EMAIL").expect("open").as_slice(),
            b"joinable"
        );
    }

    #[test]
    fn deterministic_differs_across_aad() {
        let email = seal(
            AeadAlgo::ChaCha20Poly1305,
            &KEY,
            b"joinable",
            b"EMAIL",
            NonceMode::Deterministic,
        )
        .expect("seal email");
        let phone = seal(
            AeadAlgo::ChaCha20Poly1305,
            &KEY,
            b"joinable",
            b"PHONE",
            NonceMode::Deterministic,
        )
        .expect("seal phone");
        assert_ne!(email, phone);
    }

    #[test]
    fn wire_header_records_version_and_algo() {
        let wire =
            seal(AeadAlgo::Aes256Gcm, &KEY, b"x", b"EMAIL", NonceMode::Random).expect("seal");
        let (version, algo_id, _nonce, _ct) = decode_wire(&wire).expect("decode");
        assert_eq!(version, WIRE_VERSION);
        assert_eq!(algo_id, AeadAlgo::Aes256Gcm.algo_id());
    }

    #[test]
    fn algo_id_round_trips() {
        for algo in [AeadAlgo::ChaCha20Poly1305, AeadAlgo::Aes256Gcm] {
            assert_eq!(AeadAlgo::from_id(algo.algo_id()), Some(algo));
        }
        assert_eq!(AeadAlgo::from_id(0), None);
        assert_eq!(AeadAlgo::from_id(99), None);
    }

    #[test]
    fn empty_wire_decodes_to_error() {
        assert!(open(&KEY, "", b"EMAIL").is_err());
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let wire = seal(
            AeadAlgo::ChaCha20Poly1305,
            &KEY,
            b"",
            b"EMAIL",
            NonceMode::Random,
        )
        .expect("seal");
        assert!(open(&KEY, &wire, b"EMAIL").expect("open").is_empty());
    }
}
