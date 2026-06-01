//! Shared parameter parsing for the [`Encrypt`](super::Encrypt) and
//! [`Decrypt`](super::Decrypt) operators.
//!
//! Both operators accept the same key/algorithm/AAD configuration, so the
//! parsing lives here as a single source of truth. Key material is resolved to
//! a 32-byte AEAD key either from a base64 `key` parameter or by deriving one
//! from a `password` + `salt` through Argon2 — string keys **never** become key
//! bytes directly (the Presidio raw-UTF-8-key footgun is rejected by
//! construction).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use octarine_problem::{Problem, Result};
use zeroize::Zeroizing;

use super::super::OperatorConfig;
use crate::primitives::crypto::encryption::AeadAlgo;
use crate::primitives::crypto::keys::derive_key_from_password_sync;

/// AEAD key length in bytes (256 bits).
pub(super) const KEY_SIZE: usize = 32;

/// Base64 (`URL_SAFE_NO_PAD`) of exactly 32 key bytes.
const PARAM_KEY: &str = "key";
/// Password to derive a key from (Argon2). Mutually exclusive with `key`.
const PARAM_PASSWORD: &str = "password";
/// Salt for password derivation (UTF-8 bytes, ≥ 8 bytes). Required with `password`.
const PARAM_SALT: &str = "salt";
/// AEAD algorithm selector.
const PARAM_ALGO: &str = "algo";
/// Optional extra associated data, folded in after the entity type.
const PARAM_AAD: &str = "aad";

/// Resolve the 32-byte AEAD key from config.
///
/// Exactly one of `key` (base64, 32 bytes) or `password` (+`salt`, Argon2) must
/// be present. The returned key zeroizes itself on drop.
pub(super) fn resolve_key(config: &OperatorConfig) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let has_key = config.params.contains_key(PARAM_KEY);
    let has_password = config.params.contains_key(PARAM_PASSWORD);

    match (has_key, has_password) {
        (true, true) => Err(Problem::Validation(
            "encrypt/decrypt operator: provide exactly one of 'key' or 'password', not both"
                .to_string(),
        )),
        (false, false) => Err(Problem::Validation(
            "encrypt/decrypt operator: a 'key' (base64, 32 bytes) or 'password' + 'salt' is required"
                .to_string(),
        )),
        (true, false) => key_from_base64(config),
        (false, true) => key_from_password(config),
    }
}

/// Decode a base64 `key` parameter into exactly 32 bytes.
fn key_from_base64(config: &OperatorConfig) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let encoded = config.param_str(PARAM_KEY).ok_or_else(|| {
        Problem::Validation("encrypt/decrypt operator: 'key' must be a base64 string".to_string())
    })?;
    let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded).map_err(|e| {
        Problem::Validation(format!(
            "encrypt/decrypt operator: 'key' is not valid base64: {e}"
        ))
    })?);
    if bytes.len() != KEY_SIZE {
        return Err(Problem::Validation(format!(
            "encrypt/decrypt operator: 'key' must decode to {KEY_SIZE} bytes, got {}",
            bytes.len()
        )));
    }
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Derive a 32-byte key from a `password` + `salt` via Argon2.
fn key_from_password(config: &OperatorConfig) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let password = config.param_str(PARAM_PASSWORD).ok_or_else(|| {
        Problem::Validation("encrypt/decrypt operator: 'password' must be a string".to_string())
    })?;
    let salt = config.param_str(PARAM_SALT).ok_or_else(|| {
        Problem::Validation(
            "encrypt/decrypt operator: 'salt' is required when using 'password'".to_string(),
        )
    })?;

    let derived = Zeroizing::new(
        derive_key_from_password_sync(password, salt.as_bytes(), KEY_SIZE)
            .map_err(Problem::from)?,
    );
    if derived.len() != KEY_SIZE {
        return Err(Problem::Validation(
            "encrypt/decrypt operator: derived key has unexpected length".to_string(),
        ));
    }
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    key.copy_from_slice(&derived);
    Ok(key)
}

/// Resolve the AEAD algorithm, defaulting to ChaCha20-Poly1305.
///
/// AES-CBC (and any other unauthenticated or unknown construction) is rejected:
/// only authenticated algorithms are offered.
pub(super) fn resolve_algo(config: &OperatorConfig) -> Result<AeadAlgo> {
    match config.param_str(PARAM_ALGO) {
        None => Ok(AeadAlgo::ChaCha20Poly1305),
        Some(name) => match name.to_ascii_lowercase().as_str() {
            "chacha20poly1305" | "chacha20-poly1305" => Ok(AeadAlgo::ChaCha20Poly1305),
            "aes256gcm" | "aes-256-gcm" => Ok(AeadAlgo::Aes256Gcm),
            other => Err(Problem::Validation(format!(
                "encrypt/decrypt operator: unsupported algo '{other}'; \
                 use 'chacha20poly1305' or 'aes256gcm' (AES-CBC is not supported)"
            ))),
        },
    }
}

/// Build the effective AAD: the entity type, then any caller-supplied `aad`.
///
/// Binding the entity type into the AAD means ciphertext sealed for one entity
/// type cannot be opened under another — replay across entity types fails the
/// tag check.
pub(super) fn build_aad(entity_type: &str, config: &OperatorConfig) -> Vec<u8> {
    let extra = config.param_str(PARAM_AAD).unwrap_or("");
    let mut aad = Vec::with_capacity(
        entity_type
            .len()
            .saturating_add(1)
            .saturating_add(extra.len()),
    );
    aad.extend_from_slice(entity_type.as_bytes());
    aad.push(b':');
    aad.extend_from_slice(extra.as_bytes());
    aad
}
