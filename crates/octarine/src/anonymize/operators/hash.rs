//! Hash operator — replaces a span with a salted cryptographic digest.
//!
//! `Hash` is the one-way (irreversible) anonymization operator. It supports five
//! algorithms and an explicit salt-determinism contract, wiring octarine's
//! existing crypto primitives rather than reimplementing any digest.
//!
//! # Octarine vs Presidio
//!
//! Presidio's hash operator offers **two** algorithms (SHA-256, SHA-512) and,
//! when no salt is supplied, generates a 32-byte random salt that is *discarded
//! after use* — so identical inputs hash differently every call and the result
//! is silently **non-joinable** across documents (audit §F.4 #494). Octarine
//! fixes both:
//!
//! - **Five algorithms**: `sha256`, `sha512`, `blake3`, `hmac` (HMAC-SHA3-256),
//!   and `argon2`. BLAKE3 and Argon2 have no Presidio equivalent.
//! - **Explicit salt contract** instead of a silent footgun:
//!   - **Stable** (`salt` param, ≥ 16 bytes) — deterministic, joinable output.
//!   - **KdfDerived** (`kdf_ikm` [+ `kdf_info`]) — salt derived via HKDF-SHA3-256
//!     from caller key material, also deterministic.
//!   - **PerCallRandom** — the default *only* for keyless algorithms when no
//!     salt is configured. Output is non-joinable, and an [`observe::warn`] is
//!     emitted disclosing exactly that. Presidio never tells you.
//! - **Always tagged**: every digest is prefixed with `algorithm_tag:` (e.g.
//!   `sha256:…`, `argon2:…`) so callers know which algorithm produced it.
//! - **Argon2 is gated**: only permitted for secret-bearing entity types
//!   (`PiiType::is_secret()`), bridging the credential redactor surface.
//!
//! # The digests are single-sourced
//!
//! All hashing is delegated to Layer 1 primitives
//! ([`primitives::crypto::hash`](crate::primitives::crypto::hash),
//! [`hmac_sha3_256_hex`](crate::primitives::crypto::auth::hmac_sha3_256_hex),
//! and the Argon2 KDF). This operator only parses parameters and assembles the
//! salted input — so "hash an SSN" has exactly one implementation, the same one
//! the PII redactor converges on (epic #604).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use octarine_problem::{Problem, Result};
use zeroize::Zeroizing;

use super::super::operator::Operator;
use super::super::{OperatorConfig, OperatorType};
use crate::observe;
use crate::observe::pii::PiiType;
use crate::primitives::crypto::auth::hmac_sha3_256_hex;
use crate::primitives::crypto::hash::{blake3_hex, sha256_hex, sha512_hex};
use crate::primitives::crypto::keys::{
    DomainSeparator, derive_key_from_password_sync, hkdf_sha3_256, random_salt_sized,
};

/// Algorithm selector (`sha256` default | `sha512` | `blake3` | `hmac` | `argon2`).
const PARAM_ALGO: &str = "algo";
/// Stable salt (UTF-8 string, ≥ 16 bytes). Presence selects deterministic output.
const PARAM_SALT: &str = "salt";
/// Base64 (`URL_SAFE_NO_PAD`) HMAC key. Required for `algo = "hmac"`.
const PARAM_HMAC_KEY: &str = "hmac_key";
/// Base64 (`URL_SAFE_NO_PAD`) input key material for KDF-derived salt.
const PARAM_KDF_IKM: &str = "kdf_ikm";
/// Optional domain-separation context for KDF-derived salt.
const PARAM_KDF_INFO: &str = "kdf_info";

/// Minimum length of a caller-supplied stable salt, in bytes (Presidio hardening).
const MIN_SALT_LEN: usize = 16;
/// Length of a generated per-call or KDF-derived salt, in bytes.
const DERIVED_SALT_LEN: usize = 16;
/// Length of a KDF-derived salt, in bytes.
const KDF_SALT_LEN: usize = 32;
/// Argon2 derived-key length, in bytes.
const ARGON2_KEY_LEN: usize = 32;
/// Default domain separator for KDF-derived salts.
const DEFAULT_KDF_INFO: &str = "octarine:anonymize:hash:salt";

/// The hashing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashAlgorithm {
    Sha256,
    Sha512,
    Blake3,
    /// HMAC-SHA3-256 (octarine's only HMAC construction; post-quantum margin).
    Hmac,
    /// Argon2id password hashing (gated to secret entity types).
    Argon2,
}

impl HashAlgorithm {
    /// The output tag prefix for this algorithm.
    fn tag(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
            Self::Blake3 => "blake3",
            Self::Hmac => "hmac-sha3-256",
            Self::Argon2 => "argon2",
        }
    }

    /// Keyless algorithms derive joinability from the salt alone, so an absent
    /// salt falls back to per-call random (with disclosure). HMAC is keyed and
    /// is excluded — its key is the stability anchor.
    fn is_keyless(self) -> bool {
        !matches!(self, Self::Hmac)
    }
}

/// How the salt is sourced for this invocation.
enum SaltSource {
    /// Caller-supplied fixed salt (deterministic, joinable).
    Stable(Vec<u8>),
    /// Salt derived via HKDF-SHA3-256 from caller key material (deterministic).
    KdfDerived {
        ikm: Zeroizing<Vec<u8>>,
        info: String,
    },
    /// Fresh random salt per call (non-joinable; keyless default).
    PerCallRandom,
}

/// The validated `hash` parameters, shared by `validate` and `operate`.
struct HashParams {
    algo: HashAlgorithm,
    salt: SaltSource,
    /// Present only for [`HashAlgorithm::Hmac`].
    hmac_key: Option<Zeroizing<Vec<u8>>>,
}

/// Replaces each span with a salted, one-way cryptographic digest.
///
/// Parameters (read from the [`OperatorConfig`]):
///
/// - `algo` (optional, default `"sha256"`): `"sha256"`, `"sha512"`, `"blake3"`,
///   `"hmac"` (HMAC-SHA3-256), or `"argon2"`.
/// - Salt source — at most one of:
///   - `salt`: a UTF-8 string of **≥ 16 bytes** → deterministic, joinable.
///   - `kdf_ikm`: base64 key material → salt derived via HKDF (deterministic);
///     `kdf_info` optionally sets the domain separator.
///   - neither → per-call random salt for keyless algorithms (non-joinable; a
///     warning is emitted). HMAC needs no salt — its `hmac_key` is the anchor.
/// - `hmac_key` (**required** for `algo = "hmac"`): base64 (`URL_SAFE_NO_PAD`).
/// - `argon2` is only permitted for entity types whose
///   [`PiiType::is_secret()`] is true (e.g. `PASSWORD`, `API_KEY`).
///
/// The output is always `algorithm_tag:hexdigest` (e.g. `sha256:9f86d0…`).
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
///
/// use octarine::anonymize::{Hash, Operator, OperatorConfig};
/// use serde_json::json;
///
/// // Deterministic hashing with a stable salt: the same input always maps to
/// // the same token, so anonymized datasets remain joinable.
/// let mut params = HashMap::new();
/// params.insert("algo".to_string(), json!("sha256"));
/// params.insert("salt".to_string(), json!("a-stable-salt-of-16+"));
/// let config = OperatorConfig::with_params("hash", params)?;
///
/// let a = Hash.operate("alice@example.com", "EMAIL_ADDRESS", &config)?;
/// let b = Hash.operate("alice@example.com", "EMAIL_ADDRESS", &config)?;
/// assert_eq!(a, b);
/// assert!(a.starts_with("sha256:"));
/// # Ok::<(), octarine_problem::Problem>(())
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Hash;

impl Hash {
    /// Parses and validates the operator parameters once, so
    /// [`validate`](Operator::validate) and [`operate`](Operator::operate) share
    /// a single source of truth.
    fn parse_params(config: &OperatorConfig) -> Result<HashParams> {
        let algo = Self::parse_algo(config)?;
        let salt = Self::parse_salt(config)?;

        // HMAC requires a key; the other algorithms must not be given one.
        let hmac_key = if algo == HashAlgorithm::Hmac {
            let encoded = config.param_str(PARAM_HMAC_KEY).ok_or_else(|| {
                Problem::Validation(
                    "hash operator: 'hmac_key' (base64) is required for algo 'hmac'".to_string(),
                )
            })?;
            let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded).map_err(|e| {
                Problem::Validation(format!(
                    "hash operator: 'hmac_key' is not valid base64: {e}"
                ))
            })?);
            if bytes.is_empty() {
                return Err(Problem::Validation(
                    "hash operator: 'hmac_key' must not be empty".to_string(),
                ));
            }
            Some(bytes)
        } else {
            None
        };

        Ok(HashParams {
            algo,
            salt,
            hmac_key,
        })
    }

    /// Resolve the algorithm, defaulting to SHA-256.
    fn parse_algo(config: &OperatorConfig) -> Result<HashAlgorithm> {
        match config.param_str(PARAM_ALGO) {
            None => Ok(HashAlgorithm::Sha256),
            Some(name) => match name.to_ascii_lowercase().as_str() {
                "sha256" | "sha-256" => Ok(HashAlgorithm::Sha256),
                "sha512" | "sha-512" => Ok(HashAlgorithm::Sha512),
                "blake3" => Ok(HashAlgorithm::Blake3),
                "hmac" | "hmac-sha3-256" => Ok(HashAlgorithm::Hmac),
                "argon2" | "argon2id" => Ok(HashAlgorithm::Argon2),
                other => Err(Problem::Validation(format!(
                    "hash operator: unsupported algo '{other}'; use 'sha256', 'sha512', \
                     'blake3', 'hmac', or 'argon2'"
                ))),
            },
        }
    }

    /// Resolve the salt source from config, enforcing the minimum stable-salt
    /// length and rejecting conflicting salt parameters.
    fn parse_salt(config: &OperatorConfig) -> Result<SaltSource> {
        let has_salt = config.params.contains_key(PARAM_SALT);
        let has_ikm = config.params.contains_key(PARAM_KDF_IKM);

        if has_salt && has_ikm {
            return Err(Problem::Validation(
                "hash operator: provide at most one of 'salt' or 'kdf_ikm', not both".to_string(),
            ));
        }

        if has_salt {
            let salt = config.param_str(PARAM_SALT).ok_or_else(|| {
                Problem::Validation("hash operator: 'salt' must be a string".to_string())
            })?;
            if salt.len() < MIN_SALT_LEN {
                return Err(Problem::Validation(format!(
                    "hash operator: 'salt' must be at least {MIN_SALT_LEN} bytes, got {}",
                    salt.len()
                )));
            }
            return Ok(SaltSource::Stable(salt.as_bytes().to_vec()));
        }

        if has_ikm {
            let encoded = config.param_str(PARAM_KDF_IKM).ok_or_else(|| {
                Problem::Validation("hash operator: 'kdf_ikm' must be a base64 string".to_string())
            })?;
            let ikm = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded).map_err(|e| {
                Problem::Validation(format!("hash operator: 'kdf_ikm' is not valid base64: {e}"))
            })?);
            if ikm.is_empty() {
                return Err(Problem::Validation(
                    "hash operator: 'kdf_ikm' must not be empty".to_string(),
                ));
            }
            let info = config
                .param_str(PARAM_KDF_INFO)
                .unwrap_or(DEFAULT_KDF_INFO)
                .to_string();
            return Ok(SaltSource::KdfDerived { ikm, info });
        }

        Ok(SaltSource::PerCallRandom)
    }

    /// Materialize the salt bytes for this call, applying the keyless per-call
    /// random default (with disclosure) where appropriate.
    fn resolve_salt_bytes(params: &HashParams) -> Result<Vec<u8>> {
        match &params.salt {
            SaltSource::Stable(bytes) => Ok(bytes.clone()),
            SaltSource::KdfDerived { ikm, info } => {
                hkdf_sha3_256(ikm, None, DomainSeparator::new(info), KDF_SALT_LEN)
                    .map_err(Problem::from)
            }
            SaltSource::PerCallRandom => {
                if params.algo.is_keyless() {
                    observe::warn(
                        "anonymize.hash",
                        "no salt configured for a keyless hash algorithm; using a per-call \
                         random salt — output is NOT joinable across calls. Supply 'salt' \
                         (>=16 bytes) or 'kdf_ikm' for deterministic output.",
                    );
                    random_salt_sized(DERIVED_SALT_LEN).map_err(Problem::from)
                } else {
                    // HMAC: the key is the stability anchor; no salt needed.
                    Ok(Vec::new())
                }
            }
        }
    }

    /// Concatenate `salt || text` into a single buffer for digesting.
    fn salted(salt: &[u8], text: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(salt.len().saturating_add(text.len()));
        buf.extend_from_slice(salt);
        buf.extend_from_slice(text.as_bytes());
        buf
    }
}

impl Operator for Hash {
    fn operate(&self, text: &str, entity_type: &str, config: &OperatorConfig) -> Result<String> {
        let params = Self::parse_params(config)?;

        // Argon2 is gated to secret-bearing entity types. The classification
        // authority is PiiType::is_secret(); unknown labels are treated as
        // non-secret and rejected (conservative default).
        if params.algo == HashAlgorithm::Argon2 && !entity_is_secret(entity_type) {
            return Err(Problem::Validation(format!(
                "hash operator: 'argon2' is only permitted for secret entity types \
                 (e.g. PASSWORD, API_KEY, JWT), not '{entity_type}'"
            )));
        }

        let salt = Self::resolve_salt_bytes(&params)?;

        let digest = match params.algo {
            HashAlgorithm::Sha256 => sha256_hex(&Self::salted(&salt, text)),
            HashAlgorithm::Sha512 => sha512_hex(&Self::salted(&salt, text)),
            HashAlgorithm::Blake3 => blake3_hex(&Self::salted(&salt, text)),
            HashAlgorithm::Hmac => {
                // Key presence is guaranteed by parse_params for the HMAC algo.
                let key = params.hmac_key.as_ref().ok_or_else(|| {
                    Problem::Validation("hash operator: missing HMAC key".to_string())
                })?;
                hmac_sha3_256_hex(key, &Self::salted(&salt, text))
            }
            HashAlgorithm::Argon2 => {
                let derived = Zeroizing::new(
                    derive_key_from_password_sync(text, &salt, ARGON2_KEY_LEN)
                        .map_err(Problem::from)?,
                );
                hex::encode(&*derived)
            }
        };

        Ok(format!("{}:{digest}", params.algo.tag()))
    }

    /// Validates the algorithm, salt source, and key material before any output
    /// is built.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Validation`] if `algo` is unknown, if both `salt` and
    /// `kdf_ikm` are supplied, if a stable `salt` is shorter than 16 bytes, if
    /// `kdf_ikm`/`hmac_key` are not valid base64, or if `hmac_key` is missing
    /// for `algo = "hmac"`. The Argon2 entity-type gate is enforced per span in
    /// [`operate`](Operator::operate), where the entity type is available.
    fn validate(&self, config: &OperatorConfig) -> Result<()> {
        Self::parse_params(config).map(|_| ())
    }

    fn operator_name(&self) -> &'static str {
        "hash"
    }

    fn operator_type(&self) -> OperatorType {
        OperatorType::Anonymize
    }
}

/// Resolve a recognizer entity label (e.g. `"PASSWORD"`) to its [`PiiType`] for
/// the secret-bearing labels relevant to the Argon2 gate.
///
/// Operators receive only the string label, never a `PiiType`. This is a
/// deliberately conservative bridge: it covers the credential and token labels a
/// caller would plausibly hash with Argon2, and returns `None` for anything
/// else. Classification stays single-sourced in [`PiiType::is_secret()`] —
/// routing through it means a mismapped non-secret label is still rejected.
fn resolve_secret_pii_type(entity_type: &str) -> Option<PiiType> {
    Some(match entity_type.to_ascii_uppercase().as_str() {
        // Credential domain
        "PASSWORD" => PiiType::Password,
        "PIN" => PiiType::Pin,
        "PASSPHRASE" => PiiType::Passphrase,
        "SECURITY_ANSWER" => PiiType::SecurityAnswer,
        // Token domain (secret-bearing)
        "API_KEY" | "APIKEY" => PiiType::ApiKey,
        "JWT" => PiiType::Jwt,
        "SESSION_ID" | "SESSION" => PiiType::SessionId,
        "OAUTH_TOKEN" => PiiType::OAuthToken,
        "SSH_KEY" => PiiType::SshKey,
        "BEARER_TOKEN" => PiiType::BearerToken,
        "CONNECTION_STRING" => PiiType::ConnectionString,
        "URL_WITH_CREDENTIALS" => PiiType::UrlWithCredentials,
        _ => return None,
    })
}

/// Whether `entity_type` names a secret-bearing entity (Argon2 gate).
fn entity_is_secret(entity_type: &str) -> bool {
    resolve_secret_pii_type(entity_type).is_some_and(|t| t.is_secret())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]

    use std::collections::HashMap;

    use proptest::prelude::*;
    use serde_json::{Value, json};

    use super::*;

    /// A 16-byte stable salt (meets the minimum length).
    const STABLE_SALT: &str = "0123456789abcdef";
    /// 32 key bytes (all `0x07`), base64url-no-pad — an HMAC test key.
    const HMAC_KEY_B64: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
    /// 32 key bytes (all `0x01`), base64url-no-pad — KDF input key material.
    const KDF_IKM_B64: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    /// 32 key bytes (all `0x09`), base64url-no-pad — alternate KDF input.
    const KDF_IKM_ALT_B64: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk";

    fn config_with(params: &[(&str, Value)]) -> OperatorConfig {
        let mut map = HashMap::new();
        for (k, v) in params {
            map.insert((*k).to_string(), v.clone());
        }
        OperatorConfig::with_params("hash", map).expect("config")
    }

    #[test]
    fn defaults_to_sha256_tag() {
        let config = config_with(&[("salt", json!(STABLE_SALT))]);
        let out = Hash
            .operate("secret", "EMAIL_ADDRESS", &config)
            .expect("hash");
        assert!(out.starts_with("sha256:"), "got {out}");
    }

    #[test]
    fn each_algorithm_produces_its_tag() {
        let cases = [
            ("sha256", "sha256:"),
            ("sha512", "sha512:"),
            ("blake3", "blake3:"),
        ];
        for (algo, prefix) in cases {
            let config = config_with(&[("algo", json!(algo)), ("salt", json!(STABLE_SALT))]);
            let out = Hash
                .operate("data", "EMAIL_ADDRESS", &config)
                .expect("hash");
            assert!(out.starts_with(prefix), "algo {algo} => {out}");
        }

        // HMAC is keyed.
        let hmac = config_with(&[("algo", json!("hmac")), ("hmac_key", json!(HMAC_KEY_B64))]);
        let out = Hash.operate("data", "EMAIL_ADDRESS", &hmac).expect("hmac");
        assert!(out.starts_with("hmac-sha3-256:"), "got {out}");

        // Argon2 requires a secret entity type.
        let argon2 = config_with(&[("algo", json!("argon2")), ("salt", json!(STABLE_SALT))]);
        let out = Hash
            .operate("hunter2", "PASSWORD", &argon2)
            .expect("argon2");
        assert!(out.starts_with("argon2:"), "got {out}");
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let config = config_with(&[("algo", json!("md5")), ("salt", json!(STABLE_SALT))]);
        assert!(Hash.validate(&config).is_err());
        assert!(Hash.operate("x", "EMAIL_ADDRESS", &config).is_err());
    }

    #[test]
    fn rejects_short_stable_salt() {
        let config = config_with(&[("salt", json!("tooshort"))]);
        assert!(Hash.validate(&config).is_err());
    }

    #[test]
    fn rejects_both_salt_and_kdf_ikm() {
        let config = config_with(&[
            ("salt", json!(STABLE_SALT)),
            ("kdf_ikm", json!(KDF_IKM_B64)),
        ]);
        assert!(Hash.validate(&config).is_err());
    }

    #[test]
    fn hmac_requires_key() {
        let config = config_with(&[("algo", json!("hmac"))]);
        assert!(Hash.validate(&config).is_err());
        assert!(Hash.operate("x", "EMAIL_ADDRESS", &config).is_err());
    }

    #[test]
    fn hmac_rejects_bad_base64_key() {
        let config = config_with(&[("algo", json!("hmac")), ("hmac_key", json!("not base64!!"))]);
        assert!(Hash.validate(&config).is_err());
    }

    #[test]
    fn stable_salt_is_deterministic() {
        let config = config_with(&[("salt", json!(STABLE_SALT))]);
        let a = Hash.operate("alice", "EMAIL_ADDRESS", &config).expect("a");
        let b = Hash.operate("alice", "EMAIL_ADDRESS", &config).expect("b");
        assert_eq!(a, b, "stable salt must be joinable");
    }

    #[test]
    fn per_call_random_differs_each_call() {
        // No salt configured for a keyless algorithm => per-call random.
        let config = config_with(&[("algo", json!("sha256"))]);
        let a = Hash.operate("alice", "EMAIL_ADDRESS", &config).expect("a");
        let b = Hash.operate("alice", "EMAIL_ADDRESS", &config).expect("b");
        assert_ne!(a, b, "per-call random salt must differ each call");
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn kdf_derived_salt_is_deterministic() {
        let config = config_with(&[
            ("algo", json!("sha512")),
            ("kdf_ikm", json!(KDF_IKM_ALT_B64)),
        ]);
        let a = Hash.operate("bob", "EMAIL_ADDRESS", &config).expect("a");
        let b = Hash.operate("bob", "EMAIL_ADDRESS", &config).expect("b");
        assert_eq!(a, b, "KDF-derived salt must be deterministic");
        assert!(a.starts_with("sha512:"));
    }

    #[test]
    fn argon2_rejected_for_non_secret_entity() {
        let config = config_with(&[("algo", json!("argon2")), ("salt", json!(STABLE_SALT))]);
        // US_SSN is sensitive but not a secret per PiiType::is_secret().
        assert!(Hash.operate("123-45-6789", "US_SSN", &config).is_err());
    }

    #[test]
    fn argon2_allowed_for_secret_entity() {
        let config = config_with(&[("algo", json!("argon2")), ("salt", json!(STABLE_SALT))]);
        for label in ["PASSWORD", "API_KEY", "JWT", "PIN"] {
            assert!(
                Hash.operate("s3cr3t", label, &config).is_ok(),
                "argon2 should be allowed for {label}"
            );
        }
    }

    #[test]
    fn entity_secret_resolution_uses_pii_type_authority() {
        assert!(entity_is_secret("PASSWORD"));
        assert!(entity_is_secret("password")); // case-insensitive
        assert!(!entity_is_secret("EMAIL_ADDRESS"));
        assert!(!entity_is_secret("UNKNOWN_LABEL"));
    }

    #[test]
    fn hmac_is_deterministic_without_salt() {
        // HMAC is keyed: a stable key yields joinable output even with no salt.
        let config = config_with(&[("algo", json!("hmac")), ("hmac_key", json!(HMAC_KEY_B64))]);
        let a = Hash.operate("carol", "EMAIL_ADDRESS", &config).expect("a");
        let b = Hash.operate("carol", "EMAIL_ADDRESS", &config).expect("b");
        assert_eq!(a, b, "stable HMAC key must be joinable");
    }

    #[test]
    fn reports_operator_identity() {
        assert_eq!(Hash.operator_name(), "hash");
        assert_eq!(Hash.operator_type(), OperatorType::Anonymize);
    }

    proptest! {
        /// A stable salt makes any keyless algorithm deterministic over
        /// arbitrary UTF-8 input.
        #[test]
        fn stable_salt_joinable_for_all_keyless(
            text in ".*",
            algo in prop::sample::select(vec!["sha256", "sha512", "blake3"]),
        ) {
            let config = config_with(&[("algo", json!(algo)), ("salt", json!(STABLE_SALT))]);
            let a = Hash.operate(&text, "EMAIL_ADDRESS", &config).expect("a");
            let b = Hash.operate(&text, "EMAIL_ADDRESS", &config).expect("b");
            prop_assert_eq!(a, b);
        }

        /// Output is always `algorithm_tag:` prefixed.
        #[test]
        fn output_always_tagged(text in ".{0,64}") {
            let config = config_with(&[("salt", json!(STABLE_SALT))]);
            let out = Hash.operate(&text, "EMAIL_ADDRESS", &config).expect("hash");
            prop_assert!(out.starts_with("sha256:"));
        }
    }
}
