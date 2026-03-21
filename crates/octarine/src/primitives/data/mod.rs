//! Data primitives module - FORMAT concerns
//!
//! Pure data-related utilities for paths, text, and network formatting with ZERO
//! dependencies beyond the common utilities.
//!
//! ## Architecture
//!
//! This is part of **Layer 1 (primitives)** - used by both observe and security modules.
//! This module answers: "How should this data be FORMATTED/NORMALIZED?"
//!
//! For other concerns, see:
//! - `primitives::identifiers` - CLASSIFICATION: "What is it? Is it PII?"
//! - `primitives::security` - THREATS: "Is this dangerous?"
//!
//! ## Module Structure
//!
//! - `network` - URL/hostname normalization
//! - `paths` - Path normalization, canonicalization
//! - `text` - Text normalization, encoding
//! - `tokens` - Redaction token definitions
//!
//! ## Design Principles
//!
//! 1. **No Logging**: Pure functions, no trace/debug calls
//! 2. **No Side Effects**: Only normalization and formatting
//! 3. **Returns Data**: Normalized/formatted output
//! 4. **Reusable**: Used by observe/pii and security modules

pub(crate) mod formats;
pub(crate) mod network;
pub(crate) mod paths;
pub(crate) mod text;
pub(crate) mod tokens;

// Crypto format parsing (feature-gated)
#[cfg(feature = "crypto-validation")]
pub(crate) mod crypto;

// ============================================================================
// Domain Access Paths
// ============================================================================
//
// Types and builders should be accessed via their domain paths:
//
// Network:
//   crate::primitives::data::network::{normalize_url_path, NormalizeUrlPathOptions, ...}
//
// Paths:
//   crate::primitives::data::paths::{PathBuilder, CharacteristicBuilder, ...}
//
// Text:
//   crate::primitives::data::text::{TextBuilder, TextConfig, ...}
//
// Tokens:
//   crate::primitives::data::tokens::{RedactionToken, ...}
//
// Identifiers (now at primitives level, not data):
//   crate::primitives::identifiers::{IdentifierBuilder, PersonalIdentifierBuilder, ...}
//
// Security (at primitives level, not data):
//   crate::primitives::security::network::{NetworkSecurityBuilder, HostType, ...}
//   crate::primitives::security::paths::{SecurityBuilder, ...}
// ============================================================================

// Re-export RedactionTokenCore for crate-internal use
pub(crate) use tokens::RedactionTokenCore;
