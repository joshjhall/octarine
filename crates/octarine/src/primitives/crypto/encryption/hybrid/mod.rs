//! Hybrid Ephemeral Encryption (ML-KEM + X25519)
//!
//! Post-quantum safe key exchange combining ML-KEM 1024 (FIPS 203) with
//! X25519 (RFC 7748) for defense in depth. This hybrid approach provides
//! security even if one algorithm is broken.
//!
//! ## Security Model
//!
//! - **Post-Quantum Security**: ML-KEM 1024 provides NIST Level 5 security
//!   against quantum computer attacks
//! - **Classical Security**: X25519 provides 128-bit security against
//!   classical attacks
//! - **Hybrid Key Derivation**: Combined shared secrets prevent single-point
//!   failure if either algorithm is compromised
//! - **Forward Secrecy**: Each encryption uses fresh ephemeral keys
//! - **Authenticated Encryption**: ChaCha20-Poly1305 AEAD
//!
//! ## Cryptographic Flow
//!
//! ```text
//! Sender → Recipient:
//!   1. Generate ephemeral X25519 keypair (ek_x, dk_x)
//!   2. Compute X25519 shared secret: ss_x = X25519(dk_x, recipient_pk_x)
//!   3. Encapsulate with ML-KEM: (kem_ct, ss_kem) = Encapsulate(recipient_pk_kem)
//!   4. Combine secrets: ss = SHA3-256(ss_x || ss_kem || "hybrid-v1")
//!   5. Derive key: key = HKDF-SHA3-256(ss, "chacha20poly1305")
//!   6. Encrypt: ciphertext = ChaCha20-Poly1305(plaintext, key)
//!   7. Send: (ek_x, kem_ct, nonce, ciphertext)
//!
//! Recipient:
//!   1. Compute X25519 shared secret: ss_x = X25519(dk_x, sender_ek_x)
//!   2. Decapsulate ML-KEM: ss_kem = Decapsulate(dk_kem, kem_ct)
//!   3. Combine and derive key (same as sender)
//!   4. Decrypt: plaintext = ChaCha20-Poly1305.decrypt(ciphertext, key)
//! ```
//!
//! ## Use Cases
//!
//! - Encrypted messages between parties
//! - Secure key exchange for long-term keys
//! - Post-quantum safe session establishment
//! - Secure file transfer
//!
//! ## Example
//!
//! ```ignore
//! use crate::primitives::crypto::hybrid::{HybridKeyPair, HybridEncryption};
//!
//! // Recipient generates keypair
//! let recipient_keys = HybridKeyPair::generate()?;
//! let recipient_public = recipient_keys.public_key();
//!
//! // Sender encrypts to recipient
//! let secret = b"post-quantum-safe-message";
//! let encrypted = HybridEncryption::encrypt_to(secret, &recipient_public)?;
//!
//! // Recipient decrypts
//! let decrypted = encrypted.decrypt_with(&recipient_keys)?;
//! assert_eq!(decrypted.as_slice(), secret);
//! ```
//!
//! ## See Also
//!
//! - [`EphemeralEncryption`](super::EphemeralEncryption) - Classical ephemeral encryption
//!   when post-quantum security is not required
//! - [`PersistentEncryption`](super::PersistentEncryption) - Post-quantum encryption for
//!   storage (uses ML-KEM without X25519 hybrid)
//! - [`hkdf_sha3_256`](super::hkdf_sha3_256) - Key derivation used internally for
//!   hybrid key combination

// Allow dead_code: These are Layer 1 primitives that will be used by Layer 2/3 modules
#![allow(dead_code)]

mod encryption;
mod keypair;
mod public_key;

pub use encryption::{HybridEncryptedComponents, HybridEncryption};
pub use keypair::HybridKeyPair;
pub use public_key::HybridPublicKey;

use crate::primitives::crypto::{CryptoError, keys::fill_random};

/// ChaCha20-Poly1305 key size (256 bits)
pub(super) const KEY_SIZE: usize = 32;

/// ChaCha20-Poly1305 nonce size (96 bits)
pub(super) const NONCE_SIZE: usize = 12;

/// X25519 public key size (256 bits)
pub(super) const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// ML-KEM 1024 encapsulation key size (FIPS 203)
pub(super) const ML_KEM_ENCAP_KEY_SIZE: usize = 1568;

/// ML-KEM 1024 ciphertext size
pub(super) const ML_KEM_CIPHERTEXT_SIZE: usize = 1568;

/// Domain separator for hybrid key derivation
pub(super) const HYBRID_DOMAIN: &[u8] = b"hybrid-v1";

/// Domain separator for ChaCha20-Poly1305 key derivation
pub(super) const CHACHA_DOMAIN: &[u8] = b"chacha20poly1305";
