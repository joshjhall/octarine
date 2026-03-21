// Allow dead code - this module is incrementally built and some functions
// aren't used by the public API yet
#![allow(dead_code)]

//! Crypto data format parsing primitives
//!
//! Pure parsing functions for cryptographic data formats.
//! This is the FORMAT concern - answering "How should this be structured?"
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe dependencies
//! - No logging or side effects
//! - Returns parsed data structures
//!
//! # Supported Formats
//!
//! - **PEM**: Privacy-Enhanced Mail (Base64 with headers)
//! - **DER**: Distinguished Encoding Rules (binary ASN.1)
//! - **SSH**: OpenSSH public key format
//! - **X.509**: Certificate parsing
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::data::crypto::CryptoDataBuilder;
//!
//! let builder = CryptoDataBuilder::new();
//!
//! // Parse PEM data
//! let pem = builder.parse_pem(pem_string)?;
//! println!("PEM label: {}", pem.label);
//!
//! // Parse SSH public key
//! let ssh_key = builder.parse_ssh_public_key(ssh_string)?;
//! println!("Key type: {:?}", ssh_key.key_type);
//!
//! // Parse X.509 certificate
//! let cert = builder.parse_certificate_pem(cert_string)?;
//! println!("Subject: {}", cert.subject);
//! println!("Expires: {}", cert.not_after);
//! ```
//!
//! # Three Orthogonal Concerns
//!
//! This module is part of the crypto input validation architecture:
//!
//! | Concern | Location | Question |
//! |---------|----------|----------|
//! | CLASSIFICATION | `identifiers/crypto` | "What type is it?" |
//! | FORMAT | `data/crypto` (this module) | "Can I parse it?" |
//! | THREATS | `security/crypto` | "Is it dangerous?" |
//!
//! # Module Structure
//!
//! ```text
//! crypto/
//! ├── mod.rs          # This file - module definition
//! ├── types.rs        # ParsedPem, ParsedCertificate, etc.
//! ├── builder.rs      # CryptoDataBuilder
//! ├── pem.rs          # PEM parsing
//! ├── ssh.rs          # SSH key parsing
//! └── x509.rs         # X.509 certificate parsing
//! ```

mod builder;
mod pem;
mod ssh;
mod types;
mod x509;

// Re-export builder
pub use builder::CryptoDataBuilder;

// Re-export types (ParsedPem is exported for CryptoDataBuilder::parse_pem() consumers)
#[allow(unused_imports)]
pub use types::{ParsedCertificate, ParsedPem, ParsedPublicKey, ParsedSshPublicKey};

// Parsing functions are accessed via CryptoDataBuilder, not directly re-exported
