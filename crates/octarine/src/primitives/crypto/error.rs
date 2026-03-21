//! Cryptographic Error Types
//!
//! Error types for cryptographic operations in the primitives layer.
//! These are pure error types with NO observe dependencies.
//!
//! # Security Warning
//!
//! Error messages are logged and displayed to users. **NEVER** include sensitive
//! data in error messages:
//!
//! - Key material or cryptographic values
//! - Plaintext or decrypted data
//! - Passwords or secret tokens
//! - Internal state that could aid cryptanalysis
//!
//! ## Examples
//!
//! ```ignore
//! // WRONG - leaks key material
//! CryptoError::encryption(format!("Failed with key {:x?}", key_bytes));
//!
//! // WRONG - leaks plaintext length (timing side-channel)
//! CryptoError::encryption(format!("Failed to encrypt {} bytes", data.len()));
//!
//! // CORRECT - generic, safe to log
//! CryptoError::encryption("AEAD encryption failed");
//!
//! // CORRECT - describes operation, not data
//! CryptoError::invalid_key("key length must be 32 bytes");
//! ```

// Allow dead_code: These are Layer 1 primitives that will be used by Layer 2/3 modules
#![allow(dead_code)]

use thiserror::Error;

/// Error type for cryptographic operations
///
/// This enum represents all possible failures in cryptographic primitives.
/// It is designed to be informative for debugging while not leaking
/// sensitive information about the underlying cryptographic state.
///
/// # Security Notes
///
/// - Error messages do NOT include key material or plaintext
/// - Timing information is not leaked through error variants
/// - All variants are safe to log
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CryptoError {
    /// Failed to generate random bytes for keys or nonces
    #[error("Random generation failed: {0}")]
    RandomGeneration(String),

    /// Encryption operation failed
    #[error("Encryption failed: {0}")]
    Encryption(String),

    /// Decryption operation failed (authentication or other error)
    #[error("Decryption failed: {0}")]
    Decryption(String),

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    /// Invalid key length or format
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Invalid nonce length or format
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    /// Buffer operation failed (allocation, resize, etc.)
    #[error("Buffer operation failed: {0}")]
    BufferOperation(String),

    /// MAC verification failed (authentication failure)
    #[error("MAC verification failed: {0}")]
    MacVerification(String),

    /// Platform security feature unavailable
    #[error("Platform security unavailable: {0}")]
    PlatformSecurityUnavailable(String),
}

impl CryptoError {
    // ========================================================================
    // Constructor Methods
    // ========================================================================
    //
    // SECURITY: All constructors accept a message string. The message MUST NOT
    // contain key material, plaintext, or other sensitive cryptographic values.
    // See module documentation for examples of safe vs unsafe error messages.
    // ========================================================================

    /// Create a random generation error
    ///
    /// # Security
    /// Message should describe the failure, not the random values involved.
    #[inline]
    pub fn random_generation(msg: impl Into<String>) -> Self {
        Self::RandomGeneration(msg.into())
    }

    /// Create an encryption error
    ///
    /// # Security
    /// Message should NOT include plaintext, key material, or exact data sizes.
    #[inline]
    pub fn encryption(msg: impl Into<String>) -> Self {
        Self::Encryption(msg.into())
    }

    /// Create a decryption error
    ///
    /// # Security
    /// Message should NOT reveal why decryption failed (prevents oracle attacks).
    /// Use generic messages like "authentication failed" or "invalid ciphertext".
    #[inline]
    pub fn decryption(msg: impl Into<String>) -> Self {
        Self::Decryption(msg.into())
    }

    /// Create a key derivation error
    ///
    /// # Security
    /// Message should NOT include the input key material or derived keys.
    #[inline]
    pub fn key_derivation(msg: impl Into<String>) -> Self {
        Self::KeyDerivation(msg.into())
    }

    /// Create an invalid key error
    ///
    /// # Security
    /// Safe to include expected vs actual lengths, but NOT the key bytes.
    #[inline]
    pub fn invalid_key(msg: impl Into<String>) -> Self {
        Self::InvalidKey(msg.into())
    }

    /// Create an invalid nonce error
    ///
    /// # Security
    /// Safe to include expected vs actual lengths, but NOT the nonce bytes.
    #[inline]
    pub fn invalid_nonce(msg: impl Into<String>) -> Self {
        Self::InvalidNonce(msg.into())
    }

    /// Create a buffer operation error
    ///
    /// # Security
    /// Message should describe the operation failure, not buffer contents.
    #[inline]
    pub fn buffer_operation(msg: impl Into<String>) -> Self {
        Self::BufferOperation(msg.into())
    }

    /// Create a MAC verification error
    ///
    /// # Security
    /// Message should be generic. NEVER include expected or actual MAC values
    /// as this enables forgery attacks.
    #[inline]
    pub fn mac_verification(msg: impl Into<String>) -> Self {
        Self::MacVerification(msg.into())
    }

    /// Create a platform security unavailable error
    ///
    /// # Security
    /// Safe to include platform/OS details, but not cryptographic state.
    #[inline]
    pub fn platform_security_unavailable(msg: impl Into<String>) -> Self {
        Self::PlatformSecurityUnavailable(msg.into())
    }

    /// Check if this is a decryption error (common for authentication failures)
    #[inline]
    pub fn is_decryption_error(&self) -> bool {
        matches!(self, Self::Decryption(_))
    }

    /// Check if this is a MAC verification error
    #[inline]
    pub fn is_mac_error(&self) -> bool {
        matches!(self, Self::MacVerification(_))
    }

    /// Check if this is a platform-related error
    #[inline]
    pub fn is_platform_error(&self) -> bool {
        matches!(self, Self::PlatformSecurityUnavailable(_))
    }
}

// ============================================================================
// Problem Conversion
// ============================================================================

impl From<CryptoError> for crate::primitives::types::Problem {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::RandomGeneration(msg) => Self::OperationFailed(format!("crypto: {msg}")),
            CryptoError::Encryption(msg) => Self::OperationFailed(format!("encryption: {msg}")),
            CryptoError::Decryption(msg) => Self::OperationFailed(format!("decryption: {msg}")),
            CryptoError::KeyDerivation(msg) => {
                Self::OperationFailed(format!("key derivation: {msg}"))
            }
            CryptoError::InvalidKey(msg) => Self::Validation(format!("invalid key: {msg}")),
            CryptoError::InvalidNonce(msg) => Self::Validation(format!("invalid nonce: {msg}")),
            CryptoError::BufferOperation(msg) => Self::OperationFailed(format!("buffer: {msg}")),
            CryptoError::MacVerification(msg) => {
                Self::OperationFailed(format!("MAC verification: {msg}"))
            }
            CryptoError::PlatformSecurityUnavailable(msg) => {
                Self::OperationFailed(format!("platform security: {msg}"))
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = CryptoError::encryption("test failure");
        assert_eq!(err.to_string(), "Encryption failed: test failure");

        let err = CryptoError::decryption("auth failed");
        assert_eq!(err.to_string(), "Decryption failed: auth failed");

        let err = CryptoError::random_generation("entropy exhausted");
        assert_eq!(
            err.to_string(),
            "Random generation failed: entropy exhausted"
        );
    }

    #[test]
    fn test_error_equality() {
        let err1 = CryptoError::encryption("test");
        let err2 = CryptoError::encryption("test");
        let err3 = CryptoError::encryption("other");

        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_error_classification() {
        assert!(CryptoError::decryption("test").is_decryption_error());
        assert!(!CryptoError::encryption("test").is_decryption_error());

        assert!(CryptoError::platform_security_unavailable("test").is_platform_error());
        assert!(!CryptoError::encryption("test").is_platform_error());
    }

    #[test]
    fn test_error_constructors() {
        // Test all constructor methods
        let _ = CryptoError::random_generation("test");
        let _ = CryptoError::encryption("test");
        let _ = CryptoError::decryption("test");
        let _ = CryptoError::key_derivation("test");
        let _ = CryptoError::invalid_key("test");
        let _ = CryptoError::invalid_nonce("test");
        let _ = CryptoError::buffer_operation("test");
        let _ = CryptoError::mac_verification("test");
        let _ = CryptoError::platform_security_unavailable("test");
    }

    #[test]
    fn test_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(CryptoError::encryption("test"));
        assert!(err.to_string().contains("Encryption failed"));
    }

    #[test]
    fn test_error_clone() {
        let err1 = CryptoError::encryption("test");
        let err2 = err1.clone();
        assert_eq!(err1, err2);
    }
}
