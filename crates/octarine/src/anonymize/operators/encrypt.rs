//! Encrypt operator — seals a span with authenticated encryption (AEAD).
//!
//! `Encrypt` replaces a detected span with a base64 versioned ciphertext sealed
//! under a caller-supplied key. It is the reversible counterpart to
//! [`Decrypt`](super::Decrypt): the same key, algorithm, and entity type recover
//! the plaintext.
//!
//! # Octarine vs Presidio
//!
//! Presidio's `Encrypt` is unauthenticated AES-CBC with raw-UTF-8-bytes as the
//! key, no AAD, and no version byte. Every one of those is a known footgun.
//! Octarine's `Encrypt`:
//!
//! - **Authenticates** with ChaCha20-Poly1305 (default) or AES-256-GCM — never
//!   AES-CBC. Tampering is detected on decrypt.
//! - **Derives** keys from string `password` + `salt` via Argon2; raw UTF-8
//!   bytes are never used as a key.
//! - **Binds** the ciphertext to the entity type via AAD, so it cannot be
//!   replayed under a different entity type.
//! - **Versions** the wire format, so the algorithm can be migrated later.
//! - **Optionally deterministic** (`mode = "deterministic"`): identical inputs
//!   produce identical ciphertext for joinability across documents — the opt-in
//!   that Presidio issue #1033 has wanted for years — without ever letting the
//!   caller control the nonce.
//!
//! # The cryptography is single-sourced
//!
//! All sealing is performed by the Layer 1 keyed-AEAD primitive
//! (`primitives::crypto::encryption::seal`). This operator only parses and
//! validates parameters, then delegates — no crypto is reimplemented here.

use octarine_problem::{Problem, Result};

use super::super::operator::Operator;
use super::super::{OperatorConfig, OperatorType};
use super::keyed_config;
use crate::primitives::crypto::encryption::{NonceMode, seal};

/// Parameter key selecting the nonce mode (`aead` default | `deterministic`).
const PARAM_MODE: &str = "mode";

/// Seals each span with authenticated encryption.
///
/// Parameters (read from the [`OperatorConfig`]):
///
/// - Key material — exactly one of:
///   - `key`: base64 (`URL_SAFE_NO_PAD`) of 32 key bytes, or
///   - `password` + `salt`: a string password and salt, run through Argon2.
/// - `algo` (optional, default `"chacha20poly1305"`): `"chacha20poly1305"` or
///   `"aes256gcm"`. `"aes-cbc"` (or any other value) is rejected.
/// - `mode` (optional, default `"aead"`): `"aead"` for unique ciphertext, or
///   `"deterministic"` for joinable (stable) ciphertext.
/// - `aad` (optional): extra associated data; the entity type is always bound.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
///
/// use octarine::anonymize::{Decrypt, Encrypt, Operator, OperatorConfig};
/// use serde_json::json;
///
/// // A 32-byte key, base64url-encoded (here: 32 zero bytes).
/// let key_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// let mut params = HashMap::new();
/// params.insert("key".to_string(), json!(key_b64));
/// let enc_config = OperatorConfig::with_params("encrypt", params.clone())?;
/// let dec_config = OperatorConfig::with_params("decrypt", params)?;
///
/// let sealed = Encrypt.operate("alice@example.com", "EMAIL", &enc_config)?;
/// let opened = Decrypt.operate(&sealed, "EMAIL", &dec_config)?;
/// assert_eq!(opened, "alice@example.com");
/// # Ok::<(), octarine_problem::Problem>(())
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Encrypt;

impl Encrypt {
    /// Resolve the nonce mode, defaulting to standard AEAD (random nonce).
    fn parse_mode(config: &OperatorConfig) -> Result<NonceMode> {
        match config.param_str(PARAM_MODE) {
            None => Ok(NonceMode::Random),
            Some(name) => match name.to_ascii_lowercase().as_str() {
                "aead" | "random" => Ok(NonceMode::Random),
                "deterministic" | "joinable" => Ok(NonceMode::Deterministic),
                other => Err(Problem::Validation(format!(
                    "encrypt operator: unsupported mode '{other}'; use 'aead' or 'deterministic'"
                ))),
            },
        }
    }
}

impl Operator for Encrypt {
    fn operate(&self, text: &str, entity_type: &str, config: &OperatorConfig) -> Result<String> {
        let key = keyed_config::resolve_key(config)?;
        let algo = keyed_config::resolve_algo(config)?;
        let mode = Self::parse_mode(config)?;
        let aad = keyed_config::build_aad(entity_type, config);

        seal(algo, &key, text.as_bytes(), &aad, mode).map_err(Problem::from)
    }

    /// Validates the key, algorithm, and mode parameters before any output is
    /// built.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Validation`] if no valid key material is configured,
    /// if both `key` and `password` are supplied, if `algo` names an
    /// unsupported algorithm (including AES-CBC), or if `mode` is invalid.
    fn validate(&self, config: &OperatorConfig) -> Result<()> {
        keyed_config::resolve_key(config)?;
        keyed_config::resolve_algo(config)?;
        Self::parse_mode(config)?;
        Ok(())
    }

    fn operator_name(&self) -> &'static str {
        "encrypt"
    }

    fn operator_type(&self) -> OperatorType {
        OperatorType::Anonymize
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::super::Decrypt;
    use super::*;
    use std::collections::HashMap;

    use proptest::prelude::*;
    use serde_json::json;

    /// 32 zero bytes, base64url-no-pad.
    const KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn config_with(params: &[(&str, serde_json::Value)]) -> OperatorConfig {
        let mut map = HashMap::new();
        for (k, v) in params {
            map.insert((*k).to_string(), v.clone());
        }
        OperatorConfig::with_params("encrypt", map).expect("config")
    }

    #[test]
    fn validate_requires_key_material() {
        let config = OperatorConfig::new("encrypt").expect("config");
        assert!(Encrypt.validate(&config).is_err());
    }

    #[test]
    fn validate_rejects_both_key_and_password() {
        let config = config_with(&[
            ("key", json!(KEY_B64)),
            ("password", json!("hunter2")),
            ("salt", json!("salty-salt")),
        ]);
        assert!(Encrypt.validate(&config).is_err());
    }

    #[test]
    fn validate_rejects_short_key() {
        let config = config_with(&[("key", json!("AAAA"))]);
        assert!(Encrypt.validate(&config).is_err());
    }

    #[test]
    fn validate_rejects_aes_cbc() {
        let config = config_with(&[("key", json!(KEY_B64)), ("algo", json!("aes-cbc"))]);
        assert!(Encrypt.validate(&config).is_err());
    }

    #[test]
    fn validate_rejects_bad_mode() {
        let config = config_with(&[("key", json!(KEY_B64)), ("mode", json!("nonsense"))]);
        assert!(Encrypt.validate(&config).is_err());
    }

    #[test]
    fn encrypt_produces_distinct_ciphertext_in_aead_mode() {
        let config = config_with(&[("key", json!(KEY_B64))]);
        let a = Encrypt.operate("secret", "EMAIL", &config).expect("a");
        let b = Encrypt.operate("secret", "EMAIL", &config).expect("b");
        assert_ne!(a, b, "random nonce should make each ciphertext unique");
    }

    #[test]
    fn deterministic_mode_is_joinable() {
        let config = config_with(&[("key", json!(KEY_B64)), ("mode", json!("deterministic"))]);
        let a = Encrypt.operate("secret", "EMAIL", &config).expect("a");
        let b = Encrypt.operate("secret", "EMAIL", &config).expect("b");
        assert_eq!(a, b, "deterministic mode should be stable for joinability");
    }

    #[test]
    fn password_key_path_seals() {
        let config = config_with(&[
            ("password", json!("correct horse battery staple")),
            ("salt", json!("a-unique-salt-value")),
        ]);
        assert!(Encrypt.operate("secret", "EMAIL", &config).is_ok());
    }

    proptest! {
        /// Round-trip in standard AEAD mode: `decrypt(encrypt(text)) == text`
        /// for arbitrary UTF-8 input and entity type.
        #[test]
        fn round_trip_aead(text in ".*", entity in "[A-Z_]{1,16}") {
            let enc = config_with(&[("key", json!(KEY_B64))]);
            let dec = {
                let mut map = HashMap::new();
                map.insert("key".to_string(), json!(KEY_B64));
                OperatorConfig::with_params("decrypt", map).expect("config")
            };
            let sealed = Encrypt.operate(&text, &entity, &enc).expect("seal");
            let opened = Decrypt.operate(&sealed, &entity, &dec).expect("open");
            prop_assert_eq!(opened, text);
        }

        /// Round-trip in deterministic mode, and the same input seals to the
        /// same ciphertext (joinability).
        #[test]
        fn round_trip_deterministic(text in ".*", entity in "[A-Z_]{1,16}") {
            let enc = config_with(&[("key", json!(KEY_B64)), ("mode", json!("deterministic"))]);
            let dec = {
                let mut map = HashMap::new();
                map.insert("key".to_string(), json!(KEY_B64));
                OperatorConfig::with_params("decrypt", map).expect("config")
            };
            let first = Encrypt.operate(&text, &entity, &enc).expect("seal first");
            let second = Encrypt.operate(&text, &entity, &enc).expect("seal second");
            prop_assert_eq!(&first, &second);
            let opened = Decrypt.operate(&first, &entity, &dec).expect("open");
            prop_assert_eq!(opened, text);
        }

        /// AAD binding: ciphertext sealed for entity A never opens under a
        /// different entity B.
        #[test]
        fn aad_binds_entity_type(
            text in ".{1,64}",
            entity_a in "[A-Z_]{1,12}",
            entity_b in "[A-Z_]{1,12}",
        ) {
            prop_assume!(entity_a != entity_b);
            let enc = config_with(&[("key", json!(KEY_B64))]);
            let dec = {
                let mut map = HashMap::new();
                map.insert("key".to_string(), json!(KEY_B64));
                OperatorConfig::with_params("decrypt", map).expect("config")
            };
            let sealed = Encrypt.operate(&text, &entity_a, &enc).expect("seal");
            prop_assert!(Decrypt.operate(&sealed, &entity_b, &dec).is_err());
        }
    }
}
