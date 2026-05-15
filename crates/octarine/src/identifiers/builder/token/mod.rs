//! Token identifier builder with observability
//!
//! Wraps `primitives::identifiers::TokenIdentifierBuilder` with observe instrumentation.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.
//!
//! # Module Structure
//!
//! `TokenBuilder`'s methods are split across per-section submodules that
//! mirror the original file's `// =====` section dividers. Each submodule
//! contains a single `impl TokenBuilder` block. The struct itself and the
//! three constructors stay in this `mod.rs`.

use std::borrow::Cow;

use crate::observe::Problem;
use crate::primitives::identifiers::{
    ApiKeyProvider, ApiKeyRedactionStrategy, IdentifierType, JwtAlgorithm, JwtMetadata,
    JwtRedactionStrategy, SessionIdRedactionStrategy, SshFingerprintRedactionStrategy,
    SshKeyRedactionStrategy, TokenIdentifierBuilder, TokenTextPolicy, TokenType,
};

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

/// Token identifier builder with observability
#[derive(Debug, Clone, Copy, Default)]
pub struct TokenBuilder {
    inner: TokenIdentifierBuilder,
    emit_events: bool,
}

impl TokenBuilder {
    /// Create a new TokenBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: TokenIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: TokenIdentifierBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = TokenBuilder::new();
        assert!(builder.emit_events);

        let silent = TokenBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = TokenBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_jwt_detection() {
        let builder = TokenBuilder::silent();
        assert!(builder.is_jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
    }
}
