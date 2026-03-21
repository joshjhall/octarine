//! Crypto artifact identification primitives
//!
//! Pure detection functions for classifying cryptographic artifacts.
//! This is the CLASSIFICATION concern - answering "What type of key/cert is this?"
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Supported Artifacts
//!
//! - **Keys**: RSA, EC (P-256, P-384, Ed25519), Post-quantum (ML-KEM)
//! - **Formats**: PEM, DER, SSH, OpenSSH private key, PKCS#8
//! - **Certificates**: X.509 certificates
//! - **Algorithms**: RSA-PKCS1, RSA-PSS, ECDSA, EdDSA signatures
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::identifiers::crypto::CryptoIdentifierBuilder;
//!
//! let builder = CryptoIdentifierBuilder::new();
//!
//! // Quick format detection
//! if builder.is_pem_format(data) {
//!     println!("PEM-encoded data");
//! }
//!
//! // Key type detection
//! if builder.is_rsa_key(data) {
//!     println!("RSA key detected");
//! }
//!
//! // Comprehensive detection
//! let result = builder.detect(data);
//! match result.key_type {
//!     Some(KeyType::SshEd25519) => println!("SSH Ed25519 key"),
//!     Some(KeyType::Rsa2048) => println!("RSA 2048-bit key"),
//!     _ => println!("Unknown or no key type"),
//! }
//! ```
//!
//! # Three Orthogonal Concerns
//!
//! This module is part of the crypto input validation architecture:
//!
//! | Concern | Location | Question |
//! |---------|----------|----------|
//! | CLASSIFICATION | `identifiers/crypto` (this module) | "What type is it?" |
//! | FORMAT | `data/crypto` | "Can I parse it?" |
//! | THREATS | `security/crypto` | "Is it dangerous?" |
//!
//! # Module Structure
//!
//! ```text
//! crypto/
//! ├── mod.rs          # This file - module definition
//! ├── types.rs        # KeyType, KeyFormat, SignatureAlgorithm, etc.
//! ├── detection.rs    # is_*, detect_* functions
//! └── builder.rs      # CryptoIdentifierBuilder
//! ```

mod builder;
mod detection;
mod patterns;
mod types;

// Re-export builder (primary API)
pub use builder::CryptoIdentifierBuilder;

// Re-export types for public API (needed for function signatures)
pub use types::{CertificateType, CryptoDetectionResult, KeyFormat, KeyType, SignatureAlgorithm};

// Detection functions are accessed via CryptoIdentifierBuilder, not directly exported
// This follows the same pattern as primitives/identifiers/network/
