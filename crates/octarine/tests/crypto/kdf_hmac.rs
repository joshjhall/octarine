#![allow(clippy::panic, clippy::expect_used)]

use octarine::crypto::auth;
use octarine::crypto::keys::{DomainSeparator, kdf};

// =========================================================================
// KDF → HMAC round-trip
// =========================================================================

/// Derive key via KDF → compute HMAC → verify HMAC succeeds.
#[test]
fn test_kdf_derived_key_hmac_round_trip() {
    let master_key = b"master-key-material-for-testing!";
    let domain = DomainSeparator::new("hmac-signing");

    let derived_key = kdf::derive(master_key, Some(b"test-salt"), domain, 32).expect("derive key");
    assert_eq!(derived_key.len(), 32);

    let message = b"important message to authenticate";
    let mac = auth::compute(&derived_key, message);

    assert!(
        auth::verify(&derived_key, message, &mac),
        "HMAC should verify with same derived key"
    );
}

/// Different KDF domains produce different keys → different MACs.
#[test]
fn test_domain_separation_produces_different_macs() {
    let master_key = b"shared-master-key-for-domains!!";
    let message = b"same message for both domains";

    let key_enc = kdf::derive(
        master_key,
        Some(b"salt"),
        DomainSeparator::new("encryption"),
        32,
    )
    .expect("derive enc key");
    let key_auth = kdf::derive(
        master_key,
        Some(b"salt"),
        DomainSeparator::new("authentication"),
        32,
    )
    .expect("derive auth key");

    assert_ne!(
        key_enc, key_auth,
        "Different domains should produce different keys"
    );

    let mac_enc = auth::compute(&key_enc, message);
    let mac_auth = auth::compute(&key_auth, message);

    assert_ne!(
        mac_enc, mac_auth,
        "MACs from different domain-derived keys should differ"
    );

    // Cross-verification should fail
    assert!(
        !auth::verify(&key_enc, message, &mac_auth),
        "MAC from auth key should not verify with enc key"
    );
}

/// derive_multiple → each derived key produces unique HMAC.
#[test]
fn test_derive_multiple_keys_for_hmac() {
    let master_key = b"master-key-for-multiple-derives";
    let purposes = &[("signing", 32), ("verification", 32), ("session", 32)];

    let keys = kdf::derive_multiple(master_key, purposes).expect("derive multiple");
    assert_eq!(keys.len(), 3, "Should derive 3 keys");

    let message = b"test data";
    let macs: Vec<_> = keys.iter().map(|k| auth::compute(k, message)).collect();

    // All MACs should be unique
    assert_ne!(macs.first(), macs.get(1));
    assert_ne!(macs.get(1), macs.get(2));
    assert_ne!(macs.first(), macs.get(2));
}

/// derive_versioned → different versions produce different keys.
#[test]
fn test_versioned_key_rotation() {
    let master_key = b"master-key-for-versioned-derive";

    let key_v1 = kdf::derive_versioned(master_key, "signing", 1, 32).expect("v1");
    let key_v2 = kdf::derive_versioned(master_key, "signing", 2, 32).expect("v2");

    assert_ne!(
        key_v1, key_v2,
        "Different versions should produce different keys"
    );

    let message = b"message to sign";
    let mac_v1 = auth::compute(&key_v1, message);

    // v1 MAC should not verify with v2 key
    assert!(
        !auth::verify(&key_v2, message, &mac_v1),
        "v1 MAC should not verify with v2 key"
    );
}

/// Domain-separated HMAC: compute with domain → verify with domain.
#[test]
fn test_domain_separated_hmac() {
    let key = b"hmac-key-for-domain-separation!";
    let message = b"domain-bound message";

    let mac = auth::with_domain(key, "api-signing", message);

    assert!(auth::verify_with_domain(key, "api-signing", message, &mac));
    assert!(
        !auth::verify_with_domain(key, "different-domain", message, &mac),
        "Different domain should not verify"
    );
}

/// Multipart HMAC with KDF-derived key.
#[test]
fn test_multipart_hmac_with_derived_key() {
    let master_key = b"master-key-for-multipart-hmac!!";
    let derived = kdf::derive(
        master_key,
        Some(b"salt"),
        DomainSeparator::new("multipart"),
        32,
    )
    .expect("derive");

    let parts: &[&[u8]] = &[b"header", b"payload", b"footer"];
    let mac = auth::multipart(&derived, parts);

    assert!(auth::verify_multipart(&derived, parts, &mac));

    // Tampered parts should not verify
    let tampered: &[&[u8]] = &[b"header", b"TAMPERED", b"footer"];
    assert!(
        !auth::verify_multipart(&derived, tampered, &mac),
        "Tampered data should not verify"
    );
}
