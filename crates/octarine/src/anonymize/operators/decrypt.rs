//! Decrypt operator — opens a span sealed by [`Encrypt`](super::Encrypt).
//!
//! `Decrypt` is the reversing (`Deanonymize`) counterpart to `Encrypt`. Given
//! the same key, algorithm, and entity type, it verifies the authentication tag
//! and returns the original plaintext. Tampering, a wrong key, or a mismatched
//! entity type fail the tag check — plaintext is never returned on
//! authentication failure.
//!
//! # The cryptography is single-sourced
//!
//! All opening is performed by the Layer 1 keyed-AEAD primitive
//! (`primitives::crypto::encryption::open`), which reads the version and
//! algorithm from the wire header and verifies the tag before returning. This
//! operator only parses parameters and delegates.

use octarine_problem::{Problem, Result};

use super::super::operator::Operator;
use super::super::{OperatorConfig, OperatorType};
use super::keyed_config;
use crate::primitives::crypto::encryption::open;

/// Opens AEAD ciphertext produced by [`Encrypt`](super::Encrypt).
///
/// Accepts the same key/algorithm/AAD parameters as `Encrypt` (the `algo` field
/// is not required for opening — the wire format records it — but is accepted
/// for symmetry and validated if present). See [`Encrypt`](super::Encrypt) for
/// the full parameter reference.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
///
/// use octarine::anonymize::{Decrypt, Encrypt, Operator, OperatorConfig};
/// use serde_json::json;
///
/// let key_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// let mut params = HashMap::new();
/// params.insert("key".to_string(), json!(key_b64));
/// let enc_config = OperatorConfig::with_params("encrypt", params.clone())?;
/// let dec_config = OperatorConfig::with_params("decrypt", params)?;
///
/// let sealed = Encrypt.operate("123-45-6789", "US_SSN", &enc_config)?;
/// assert_eq!(Decrypt.operate(&sealed, "US_SSN", &dec_config)?, "123-45-6789");
///
/// // Opening under a different entity type fails the tag check.
/// assert!(Decrypt.operate(&sealed, "EMAIL", &dec_config).is_err());
/// # Ok::<(), octarine_problem::Problem>(())
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Decrypt;

impl Operator for Decrypt {
    fn operate(&self, text: &str, entity_type: &str, config: &OperatorConfig) -> Result<String> {
        let key = keyed_config::resolve_key(config)?;
        // Validate algo if supplied (symmetry with Encrypt); the wire format is
        // authoritative for the actual algorithm used.
        keyed_config::resolve_algo(config)?;
        let aad = keyed_config::build_aad(entity_type, config);

        let plaintext = open(&key, text, &aad).map_err(Problem::from)?;
        String::from_utf8(plaintext).map_err(|e| {
            Problem::Validation(format!(
                "decrypt operator: plaintext is not valid UTF-8: {e}"
            ))
        })
    }

    /// Validates the key and algorithm parameters before any work is attempted.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Validation`] if no valid key material is configured,
    /// if both `key` and `password` are supplied, or if `algo` names an
    /// unsupported algorithm.
    fn validate(&self, config: &OperatorConfig) -> Result<()> {
        keyed_config::resolve_key(config)?;
        keyed_config::resolve_algo(config)?;
        Ok(())
    }

    fn operator_name(&self) -> &'static str {
        "decrypt"
    }

    fn operator_type(&self) -> OperatorType {
        OperatorType::Deanonymize
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::super::Encrypt;
    use super::*;
    use std::collections::HashMap;

    use base64::Engine;
    use serde_json::json;

    /// 32 zero bytes, base64url-no-pad.
    const KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn config_with(name: &str, params: &[(&str, serde_json::Value)]) -> OperatorConfig {
        let mut map = HashMap::new();
        for (k, v) in params {
            map.insert((*k).to_string(), v.clone());
        }
        OperatorConfig::with_params(name, map).expect("config")
    }

    #[test]
    fn round_trip_recovers_plaintext() {
        let enc = config_with("encrypt", &[("key", json!(KEY_B64))]);
        let dec = config_with("decrypt", &[("key", json!(KEY_B64))]);
        let sealed = Encrypt.operate("héllo wörld", "TEXT", &enc).expect("seal");
        let opened = Decrypt.operate(&sealed, "TEXT", &dec).expect("open");
        assert_eq!(opened, "héllo wörld");
    }

    #[test]
    fn round_trip_aes256gcm() {
        let params = [("key", json!(KEY_B64)), ("algo", json!("aes256gcm"))];
        let enc = config_with("encrypt", &params);
        let dec = config_with("decrypt", &params);
        let sealed = Encrypt.operate("secret", "EMAIL", &enc).expect("seal");
        assert_eq!(
            Decrypt.operate(&sealed, "EMAIL", &dec).expect("open"),
            "secret"
        );
    }

    #[test]
    fn wrong_entity_type_fails() {
        let enc = config_with("encrypt", &[("key", json!(KEY_B64))]);
        let dec = config_with("decrypt", &[("key", json!(KEY_B64))]);
        let sealed = Encrypt.operate("secret", "EMAIL", &enc).expect("seal");
        assert!(Decrypt.operate(&sealed, "PHONE", &dec).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let enc = config_with("encrypt", &[("key", json!(KEY_B64))]);
        // A different 32-byte key (all 0x01 → "AQEB...").
        let other_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
        let dec = config_with("decrypt", &[("key", json!(other_key))]);
        let sealed = Encrypt.operate("secret", "EMAIL", &enc).expect("seal");
        assert!(Decrypt.operate(&sealed, "EMAIL", &dec).is_err());
    }

    #[test]
    fn operator_type_is_deanonymize() {
        assert_eq!(Decrypt.operator_type(), OperatorType::Deanonymize);
    }
}
