#![allow(clippy::panic, clippy::expect_used)]

use octarine::crypto::encryption::{ephemeral, hybrid, persistent};

// =========================================================================
// Hybrid (post-quantum) encrypt/decrypt
// =========================================================================

/// Generate keypair → encrypt → decrypt → verify plaintext matches.
#[test]
fn test_hybrid_round_trip() {
    let keypair = hybrid::generate_keypair().expect("generate keypair");
    let plaintext = b"Hello, post-quantum world!";

    let encrypted = hybrid::encrypt(&keypair.public_key(), plaintext).expect("encrypt");
    let decrypted = hybrid::decrypt(&keypair, &encrypted).expect("decrypt");

    assert_eq!(decrypted, plaintext, "Decrypted data should match original");
}

/// Different keypair cannot decrypt data encrypted for another keypair.
#[test]
fn test_hybrid_cross_keypair_isolation() {
    let keypair1 = hybrid::generate_keypair().expect("keypair 1");
    let keypair2 = hybrid::generate_keypair().expect("keypair 2");

    let encrypted = hybrid::encrypt(&keypair1.public_key(), b"secret").expect("encrypt");

    let result = hybrid::decrypt(&keypair2, &encrypted);
    assert!(result.is_err(), "Wrong keypair should not decrypt");
}

/// Components round-trip: encrypt → to_components → from_components → decrypt.
#[test]
fn test_hybrid_components_round_trip() {
    let keypair = hybrid::generate_keypair().expect("generate keypair");
    let plaintext = b"Serializable encryption test";

    let encrypted = hybrid::encrypt(&keypair.public_key(), plaintext).expect("encrypt");
    let components = hybrid::to_components(&encrypted);
    let restored = hybrid::from_components(components).expect("from components");
    let decrypted = hybrid::decrypt(&keypair, &restored).expect("decrypt");

    assert_eq!(decrypted, plaintext);
}

// =========================================================================
// Ephemeral (forward secrecy) encrypt/decrypt
// =========================================================================

/// Ephemeral encrypt → decrypt round-trip.
#[test]
fn test_ephemeral_round_trip() {
    let plaintext = b"Forward secrecy data";

    let encrypted = ephemeral::encrypt(plaintext).expect("encrypt");
    let decrypted = ephemeral::decrypt(&encrypted).expect("decrypt");

    assert_eq!(decrypted, plaintext);
}

/// Each ephemeral encryption produces unique ciphertext.
#[test]
fn test_ephemeral_unique_ciphertext() {
    let plaintext = b"Same data, different keys";

    let _enc1 = ephemeral::encrypt(plaintext).expect("encrypt 1");
    let _enc2 = ephemeral::encrypt(plaintext).expect("encrypt 2");

    // EncryptedComponents is a tuple: (ciphertext, nonce, key)
    let comp1 = ephemeral::encrypt_to_components(plaintext).expect("components 1");
    let comp2 = ephemeral::encrypt_to_components(plaintext).expect("components 2");

    assert_ne!(comp1.0, comp2.0, "Ciphertext should differ");
}

// =========================================================================
// Persistent (post-quantum storage) with key rotation
// =========================================================================

/// Create storage → encrypt → decrypt → verify.
#[test]
fn test_persistent_round_trip() {
    let storage = persistent::create_storage().expect("create storage");
    let plaintext = b"Long-term secret data";

    let encrypted = persistent::encrypt(&storage, plaintext).expect("encrypt");
    let decrypted = persistent::decrypt(&storage, &encrypted).expect("decrypt");

    assert_eq!(decrypted, plaintext);
}

/// Key rotation: encrypt → rotate → re-encrypt → decrypt with new key.
#[test]
fn test_persistent_key_rotation() {
    let mut storage = persistent::create_storage().expect("create storage");
    let plaintext = b"Data that survives rotation";

    let encrypted_v0 = persistent::encrypt(&storage, plaintext).expect("encrypt v0");
    assert_eq!(encrypted_v0.key_version(), 0);

    // Rotate key
    let new_version = persistent::rotate_key(&mut storage).expect("rotate");
    assert_eq!(new_version, 1);

    // Re-encrypt under new key
    let encrypted_v1 = persistent::re_encrypt(&storage, &encrypted_v0).expect("re-encrypt");
    assert_eq!(encrypted_v1.key_version(), 1);

    // Decrypt with current storage
    let decrypted = persistent::decrypt(&storage, &encrypted_v1).expect("decrypt v1");
    assert_eq!(decrypted, plaintext);
}
