//! Session ID generation with 128+ bits of entropy
//!
//! Implements ASVS V3.1.1: Session tokens must have at least 128 bits of entropy.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use std::fmt;

/// Session identifier with at least 128 bits of entropy
///
/// Generated using cryptographically secure random bytes and encoded
/// as URL-safe base64 for transport in cookies/headers.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// Default session ID length in bytes (256 bits = 32 bytes)
    const DEFAULT_BYTES: usize = 32;

    /// Minimum session ID length in bytes (128 bits = 16 bytes)
    const MIN_BYTES: usize = 16;

    /// Generate a new session ID with 256 bits of entropy
    ///
    /// Uses the system's cryptographically secure random number generator.
    #[must_use]
    pub fn generate() -> Self {
        Self::generate_with_length(Self::DEFAULT_BYTES)
    }

    /// Generate a session ID with custom length in bytes
    ///
    /// # Panics
    ///
    /// Panics if `length` is less than 16 bytes (128 bits).
    #[must_use]
    pub fn generate_with_length(length: usize) -> Self {
        assert!(
            length >= Self::MIN_BYTES,
            "Session ID must be at least {} bytes for 128 bits of entropy",
            Self::MIN_BYTES
        );

        let mut bytes = vec![0u8; length];
        rand::rng().fill_bytes(&mut bytes);
        Self(URL_SAFE_NO_PAD.encode(&bytes))
    }

    /// Create a session ID from an existing string value
    ///
    /// Use this when loading session IDs from storage.
    #[must_use]
    pub fn from_string(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Get the session ID as a string slice
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Check if the session ID appears valid (non-empty, reasonable length)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        // Base64 of 16 bytes = ~22 chars, 32 bytes = ~43 chars
        !self.0.is_empty() && self.0.len() >= 21
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only show first 8 chars for security
        if self.0.len() > 8 {
            write!(f, "SessionId({}...)", &self.0[..8])
        } else {
            write!(f, "SessionId({})", &self.0)
        }
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only show first 8 chars for security in logs
        if self.0.len() > 8 {
            write!(f, "{}...", &self.0[..8])
        } else {
            write!(f, "{}", &self.0)
        }
    }
}

impl AsRef<str> for SessionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<SessionId> for String {
    fn from(id: SessionId) -> Self {
        id.0
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_generate_session_id() {
        let id = SessionId::generate();
        assert!(id.is_valid());
        // 32 bytes = 43 base64 chars (without padding)
        assert_eq!(id.as_str().len(), 43);
    }

    #[test]
    fn test_generate_minimum_length() {
        let id = SessionId::generate_with_length(16);
        assert!(id.is_valid());
        // 16 bytes = 22 base64 chars (without padding)
        assert_eq!(id.as_str().len(), 22);
    }

    #[test]
    #[should_panic(expected = "at least 16 bytes")]
    fn test_generate_too_short() {
        let _ = SessionId::generate_with_length(15);
    }

    #[test]
    fn test_uniqueness() {
        let mut ids = HashSet::new();
        for _ in 0..1000 {
            let id = SessionId::generate();
            assert!(
                ids.insert(id.as_str().to_string()),
                "Duplicate session ID generated"
            );
        }
    }

    #[test]
    fn test_debug_truncates() {
        let id = SessionId::generate();
        let debug = format!("{:?}", id);
        assert!(debug.contains("..."));
        assert!(!debug.contains(id.as_str()));
    }

    #[test]
    fn test_display_truncates() {
        let id = SessionId::generate();
        let display = id.to_string();
        assert!(display.contains("..."));
        assert!(!display.contains(id.as_str()));
    }

    #[test]
    fn test_from_string() {
        let id = SessionId::from_string("test-session-id-12345678901234567890");
        assert_eq!(id.as_str(), "test-session-id-12345678901234567890");
    }
}
