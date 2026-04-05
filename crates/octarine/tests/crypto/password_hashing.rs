#![allow(clippy::panic, clippy::expect_used)]

use octarine::crypto::keys::password;
use octarine::crypto::keys::{PasswordCharset, PasswordStrength};

// =========================================================================
// Hash + Verify (sync)
// =========================================================================

/// hash_sync → verify_sync with correct password succeeds.
#[test]
fn test_hash_verify_sync_correct() {
    let hash = password::hash_sync("correct-horse-battery-staple").expect("hash");
    let valid = password::verify_sync("correct-horse-battery-staple", &hash).expect("verify");
    assert!(valid, "Correct password should verify");
}

/// hash_sync → verify_sync with wrong password fails.
#[test]
fn test_hash_verify_sync_wrong_password() {
    let hash = password::hash_sync("correct-password").expect("hash");
    let valid = password::verify_sync("wrong-password", &hash).expect("verify");
    assert!(!valid, "Wrong password should not verify");
}

/// Same password produces different hashes (salting).
#[test]
fn test_hash_produces_unique_outputs() {
    let h1 = password::hash_sync("same-password").expect("hash 1");
    let h2 = password::hash_sync("same-password").expect("hash 2");
    assert_ne!(h1, h2, "Different salts should produce different hashes");

    // But both should verify
    assert!(password::verify_sync("same-password", &h1).expect("verify 1"));
    assert!(password::verify_sync("same-password", &h2).expect("verify 2"));
}

// =========================================================================
// Hash + Verify (async)
// =========================================================================

/// Async hash → verify round-trip.
#[tokio::test]
async fn test_hash_verify_async() {
    let hash = password::hash("async-password-test").await.expect("hash");
    let valid = password::verify("async-password-test", &hash)
        .await
        .expect("verify");
    assert!(valid, "Async verification should succeed");
}

// =========================================================================
// Key derivation from password
// =========================================================================

/// derive_key_from_password_sync produces consistent output for same inputs.
#[test]
fn test_derive_key_consistency() {
    let salt = b"consistent-salt-value";
    let k1 =
        password::derive_key_from_password_sync("my-password", salt, 32).expect("derive key 1");
    let k2 =
        password::derive_key_from_password_sync("my-password", salt, 32).expect("derive key 2");

    assert_eq!(k1, k2, "Same password + salt should produce same key");
    assert_eq!(k1.len(), 32, "Key should be 32 bytes");
}

/// Different passwords produce different derived keys.
#[test]
fn test_derive_key_different_passwords() {
    let salt = b"same-salt";
    let k1 = password::derive_key_from_password_sync("password-a", salt, 32).expect("derive 1");
    let k2 = password::derive_key_from_password_sync("password-b", salt, 32).expect("derive 2");

    assert_ne!(k1, k2, "Different passwords should produce different keys");
}

// =========================================================================
// Password generation and strength
// =========================================================================

/// generate produces password of requested length.
#[test]
fn test_generate_password() {
    let pw = password::generate(24, PasswordCharset::AlphanumericSymbols).expect("generate");
    assert_eq!(pw.len(), 24, "Generated password should be 24 characters");
}

/// estimate_strength returns reasonable levels.
#[test]
fn test_strength_estimation() {
    let weak = password::estimate_strength("abc");

    // Weak password should not be Strong
    assert_ne!(weak, PasswordStrength::Strong);

    // Strong password should not be VeryWeak
    let strong = password::estimate_strength("Tr0ub4dor&3-correct-horse!");
    assert_ne!(strong, PasswordStrength::VeryWeak);
}
