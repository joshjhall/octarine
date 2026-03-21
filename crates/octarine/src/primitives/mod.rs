//! Primitives Module
//!
//! Foundation utilities with ZERO rust-core dependencies.
//! Used by both observe and feature modules (security, runtime).
//!
//! ## Architecture Layer
//!
//! This is **Layer 1** of the three-layer architecture:
//! - **Layer 1 (primitives)**: Pure utilities, no internal dependencies
//! - **Layer 2 (observe)**: Uses primitives only
//! - **Layer 3 (security, runtime)**: Uses primitives + observe
//!
//! ## Visibility Rules
//!
//! - **Module visibility**: `pub(crate)` - accessible only within octarine
//! - **Item visibility**: `pub` - accessible through parent module
//! - **NOT exported** from lib.rs - internal use only
//!
//! ## Type Access Pattern
//!
//! Types are accessed via their domain paths:
//!
//! ```rust,ignore
//! // Foundational types at primitives level
//! use crate::primitives::{Problem, Result};
//!
//! // Identifiers (CLASSIFICATION) - now at primitives level
//! use crate::primitives::identifiers::{IdentifierType, PersonalIdentifierBuilder};
//!
//! // Data (FORMAT) - normalization and formatting
//! use crate::primitives::data::paths::{PathBuilder, CharacteristicBuilder};
//!
//! // Security (THREATS) - danger detection
//! use crate::primitives::security::network::{NetworkSecurityBuilder, PortRange};
//! ```
//!
//! ## Module Organization (Three Orthogonal Concerns)
//!
//! The primitives layer is organized around three orthogonal concerns:
//!
//! - `data/` - FORMAT: "How should this be structured?"
//!   - `paths/` - Path normalization, canonicalization
//!   - `text/` - Text normalization, encoding
//!   - `tokens/` - Redaction token definitions
//!
//! - `security/` - THREATS: "Is this dangerous?"
//!   - `paths/` - Traversal, injection detection
//!   - `network/` - SSRF, encoding attacks
//!
//! - `identifiers/` - CLASSIFICATION: "What is it? Is it PII?"
//!   - `network/` - IP, MAC, UUID detection
//!   - `personal/` - SSN, email, phone
//!   - `financial/` - Credit cards, bank accounts
//!   - ...and more domains
//!
//! Also:
//! - `types/` - Core foundational types (Problem, Result, PortRange)
//! - `collections/` - Thread-safe data structures (RingBuffer, LruCache)
//! - `io/` - I/O primitives (file operations)
//! - `crypto/` - Cryptographic primitives
//! - `runtime/` - Pure async primitives

// Module organization (all private - implementation details)
pub(crate) mod collections;
pub(crate) mod types;

pub(crate) mod crypto;
pub(crate) mod data;
pub(crate) mod identifiers;
pub(crate) mod io;
pub(crate) mod runtime;
pub(crate) mod security;

#[cfg(feature = "auth")]
pub(crate) mod auth;

// ============================================================================
// Re-exports at primitives level
// ============================================================================

// Foundational types - these are truly universal and stay at primitives level
pub use types::{Problem, Result};

// Shared types from primitives/types/ - also re-exported from domain modules
#[allow(unused_imports)]
pub(crate) use types::PortRange;

// Redaction token - used across modules
#[allow(unused_imports)]
pub(crate) use data::RedactionTokenCore;

// ============================================================================
// Domain-specific types should be accessed via domain paths:
//
// Identifiers (CLASSIFICATION - "What is it?"):
//   use crate::primitives::identifiers::{IdentifierBuilder, PersonalIdentifierBuilder, ...};
//
// Data (FORMAT - "How to normalize?"):
//   use crate::primitives::data::paths::{PathBuilder, CharacteristicBuilder, ...};
//   use crate::primitives::data::text::{TextBuilder, TextConfig, ...};
//
// Security (THREATS - "Is it dangerous?"):
//   use crate::primitives::security::network::{NetworkSecurityBuilder, HostType, ...};
//   use crate::primitives::security::paths::{SecurityBuilder, ...};
// ============================================================================
