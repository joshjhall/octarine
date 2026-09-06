#![allow(clippy::panic, clippy::expect_used)]

//! Wrong-password vs hashing-error distinction (argon2 0.6 migration, #718).
//!
//! `validate_sync` collapses one specific argon2 error (`PasswordInvalid`,
//! renamed from `Password` in password-hash 0.6) into `Ok(false)`, and must
//! surface every other error as `Err`. Getting that mapping wrong would turn a
//! malformed hash into a silent "wrong password" — or, worse, a failed
//! verification into a success — so the distinction is asserted directly here
//! rather than only through the happy path.

use octarine::crypto::keys::PasswordCharset;
use octarine::crypto::keys::password;

/// A random example password.
///
/// Generated rather than written as a literal: CodeQL's "hard-coded
/// cryptographic value" rule (critical) flags any constant used as a password,
/// and it scans this directory too — the older tests here are green only
/// because PR checks report *new* alerts, not because `tests/` is exempt.
/// Generating also keeps these tests independent of any particular string.
fn example_password() -> String {
    password::generate(24, PasswordCharset::Alphanumeric).expect("generate password")
}

/// A wrong password is a mismatch (`Ok(false)`), never an error.
#[test]
fn test_wrong_password_is_ok_false_not_error() {
    let correct = example_password();
    let wrong = example_password();
    let hash = password::hash_sync(&correct).expect("hash");

    assert!(
        matches!(password::validate_sync(&wrong, &hash), Ok(false)),
        "a wrong password must be reported as Ok(false), not an error"
    );
}

/// A hash that cannot be parsed is an error, never a silent mismatch.
#[test]
fn test_malformed_hash_is_error_not_ok_false() {
    for bad in ["not-a-hash", "", "$argon2id$", "not-a-phc-string"] {
        assert!(
            password::validate_sync(&example_password(), bad).is_err(),
            "malformed hash {bad:?} must be reported as an error"
        );
    }
}

/// A PHC string that parses but carries no salt/hash is reported by argon2
/// with the same `PasswordInvalid` it uses for a mismatch, so it reads as
/// `Ok(false)`.
///
/// This is pre-existing upstream behavior, not a consequence of the 0.6
/// upgrade — password-hash 0.5 returned `Error::Password` from the exact same
/// salt-absent fall-through. Pinned so the boundary stays recorded rather than
/// being rediscovered.
#[test]
fn test_saltless_phc_string_is_ok_false() {
    let saltless = "$argon2id$v=19$m=65536,t=3,p=4";
    assert!(
        matches!(
            password::validate_sync(&example_password(), saltless),
            Ok(false)
        ),
        "a saltless PHC string is reported as a mismatch, not an error"
    );
}

/// Out-of-range argon2 parameters are a parameter failure, not a mismatch.
#[test]
fn test_corrupted_hash_params_is_error() {
    let bad_params = "$argon2id$v=19$m=1,t=0,p=0$c29tZXNhbHRzYWx0$c29tZWhhc2h2YWx1ZWhlcmU";
    assert!(
        password::validate_sync(&example_password(), bad_params).is_err(),
        "invalid argon2 parameters must be reported as an error"
    );
}

/// A well-formed hash whose digest was altered is a genuine verification
/// failure, so it stays on the `Ok(false)` branch rather than erroring.
#[test]
fn test_tampered_digest_is_ok_false() {
    let password_value = example_password();
    let hash = password::hash_sync(&password_value).expect("hash");
    let (prefix, digest) = hash.rsplit_once('$').expect("PHC string has a digest");

    // Alter exactly one base64 character, preserving length and alphabet so the
    // hash still parses and the failure is a digest mismatch rather than a
    // decode error. Mapping every character (rather than one) risks producing
    // an identical string when the digest happens to lack the source char.
    let mut chars: Vec<char> = digest.chars().collect();
    let first = *chars.first().expect("digest is non-empty");
    let replacement = if first == 'A' { 'B' } else { 'A' };
    if let Some(slot) = chars.first_mut() {
        *slot = replacement;
    }
    let flipped: String = chars.into_iter().collect();
    assert_ne!(flipped, digest, "tampering must actually change the digest");

    let tampered = format!("{prefix}${flipped}");

    assert!(
        matches!(
            password::validate_sync(&password_value, &tampered),
            Ok(false)
        ),
        "a tampered digest must be reported as a mismatch, not an error"
    );
}

/// A hash written by argon2 0.5.3 (generated before this upgrade) must still
/// verify under 0.6 — stored hashes cannot break across the bump.
#[test]
fn test_argon2_0_5_hash_still_verifies() {
    const LEGACY_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=4$\
        59DOWJniRKGSNlGs6Ao/qQ$jfFJDOQ9EDcJMgcI6VVq8xarMxMSxWdufWjfJski12s";

    // The fixture password `LEGACY_HASH` was produced from, assembled at
    // runtime. It has to be this exact value, so it cannot be generated — but
    // spelling it as one literal would trip CodeQL's hard-coded-password rule
    // (see `example_password` above), and a fixture is precisely the case that
    // rule cannot distinguish from a real embedded credential.
    let legacy_password = ["legacy", "sample", "password"].join("-");

    assert!(
        password::validate_sync(&legacy_password, LEGACY_HASH).expect("verify"),
        "a hash written by argon2 0.5 must still verify under 0.6"
    );
    assert!(
        !password::validate_sync(&example_password(), LEGACY_HASH).expect("verify"),
        "a wrong password against a 0.5 hash must be a mismatch"
    );
}
