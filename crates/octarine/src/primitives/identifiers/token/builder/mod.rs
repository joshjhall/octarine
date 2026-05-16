//! Token identifier builder (Layer 1 primitives)
//!
//! Split from the original 876-LOC `builder.rs` into per-section submodules
//! that mirror the original file's `// =====` section dividers. Each
//! submodule contains a single `impl TokenIdentifierBuilder` block. The
//! struct itself and `new()` constructor stay in this `mod.rs`.
//!
//! Mirrors the Layer 3 split landed in #335 (`identifiers/builder/token/`).

// Re-export types from the sibling `detection` module (matches the previous
// `pub use detection::{ApiKeyProvider, JwtAlgorithm}` flat-builder re-export).
// `super::detection` is `crate::primitives::identifiers::token::detection`,
// distinct from the local `mod detection` declared below.
pub use super::detection::{ApiKeyProvider, JwtAlgorithm};

mod conversion;
mod detection;
mod redaction_api_key;
mod redaction_jwt;
mod redaction_provider;
mod redaction_session;
mod redaction_ssh_fp;
mod redaction_ssh_key;
mod redaction_text;
mod test_patterns;
mod validation;

/// Builder for token identifier operations
///
/// Provides a unified interface for detection, validation, and sanitization
/// of authentication and authorization tokens.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokenIdentifierBuilder;

impl TokenIdentifierBuilder {
    /// Create a new token identifier builder
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = TokenIdentifierBuilder::new();
        // Use a real JWT token (from jwt.io)
        assert!(builder.is_jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
    }

    #[test]
    fn test_builder_api_key_detection() {
        let builder = TokenIdentifierBuilder::new();
        assert!(builder.is_api_key(&format!("sk_live_{}", "EXAMPLE000000000KEY01abcdef")));
        assert!(builder.is_stripe_key(&format!("sk_live_{}", "EXAMPLE000000000KEY01abcdef")));
    }

    #[test]
    fn test_builder_masking() {
        let builder = TokenIdentifierBuilder::new();
        let masked = builder.mask_api_key(&format!("sk_live_{}", "EXAMPLE000000000KEY01abcdef"));
        assert_eq!(masked, "sk_live_EXAM***");
    }
}
