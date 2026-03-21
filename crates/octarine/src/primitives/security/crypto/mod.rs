//! Crypto security primitives - THREATS concern
//!
//! Pure functions for detecting security threats in cryptographic data.
//! This is the THREATS concern - answering "Is this dangerous?"
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe dependencies
//! - No logging or side effects
//! - Returns threat data structures
//!
//! # Threat Categories
//!
//! | Category | Examples |
//! |----------|----------|
//! | Key Threats | Weak key size, deprecated algorithms |
//! | Certificate Threats | Expired, self-signed, weak signature |
//! | Algorithm Threats | MD5, SHA-1, broken ciphers |
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::security::crypto::{CryptoSecurityBuilder, CryptoPolicy};
//!
//! // Create a builder with standard policy
//! let builder = CryptoSecurityBuilder::new();
//!
//! // Or use strict policy for high-security environments
//! let strict = CryptoSecurityBuilder::strict();
//!
//! // Check if a key type is weak
//! if builder.is_weak_key(&key_type) {
//!     // Handle weak key
//! }
//!
//! // Validate an algorithm
//! builder.validate_signature_algorithm(&algo)?;
//!
//! // Audit a certificate
//! let result = builder.audit_certificate(&cert);
//! if !result.passed() {
//!     for threat in result.blocking_threats() {
//!         println!("Blocking: {}", threat.description());
//!     }
//! }
//! ```
//!
//! # Three Orthogonal Concerns
//!
//! This module is part of the crypto input validation architecture:
//!
//! | Concern | Location | Question |
//! |---------|----------|----------|
//! | CLASSIFICATION | `identifiers/crypto` | "What type is it?" |
//! | FORMAT | `data/crypto` | "Can I parse it?" |
//! | THREATS | `security/crypto` (this module) | "Is it dangerous?" |
//!
//! # Security Policies
//!
//! The module provides pre-configured policies:
//!
//! | Policy | RSA Min | EC Min | SHA-1 | Self-Signed | Use Case |
//! |--------|---------|--------|-------|-------------|----------|
//! | `standard()` | 2048 | 256 | No | No | Normal operations |
//! | `strict()` | 3072 | 384 | No | No | High security |
//! | `legacy()` | 1024 | 224 | Yes | Yes | Legacy systems |
//! | `development()` | 1024 | 192 | Yes | Yes | Testing only |

mod builder;
mod detection;
mod types;
mod validation;

// Re-export builder (primary API)
pub use builder::CryptoSecurityBuilder;

// Re-export types (needed for function signatures and return values)
pub use types::{CryptoAuditResult, CryptoPolicy, CryptoThreat};

// Detection and validation functions are accessed via CryptoSecurityBuilder, not directly exported
// This follows the same pattern as primitives/security/network/
