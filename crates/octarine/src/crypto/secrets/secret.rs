//! Public Secret Wrapper Types
//!
//! This module provides the public API for secret handling with automatic
//! zeroization on drop.
//!
//! # Architecture
//!
//! These are **Layer 3** public types that wrap the internal `*Core` primitives.
//! The primitives provide the implementation, while these types provide the
//! stable public API.

use std::fmt;
use zeroize::Zeroize;

use crate::primitives::crypto::secrets::{ExposeSecretCore, SecretCore};

// ============================================================================
// ExposeSecret Trait (Public API)
// ============================================================================

/// Trait for types that can expose their secret inner value.
///
/// This provides a standardized way to access the underlying secret value
/// while maintaining type safety and making secret access explicit.
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::secrets::{Secret, ExposeSecret};
///
/// let secret = Secret::new("my-secret".to_string());
/// let value = secret.expose_secret();
/// ```
pub trait ExposeSecret<T> {
    /// Expose the inner secret value.
    ///
    /// # Security Note
    ///
    /// Use this method sparingly. Each call should be audited to ensure
    /// the exposed value is handled securely.
    fn expose_secret(&self) -> &T;
}

// ============================================================================
// Secret<T> Wrapper (Public API)
// ============================================================================

/// A wrapper that holds sensitive data and zeroizes it on drop.
///
/// `Secret<T>` provides:
/// - Automatic memory zeroization when dropped (via `zeroize` crate)
/// - Safe Debug/Display that never reveals the value (shows `[REDACTED]`)
/// - Explicit access via `expose_secret()` to make secret usage visible in code
///
/// # Security Properties
///
/// - **Zeroization**: The inner value is zeroed in memory when the Secret is dropped
/// - **Debug Safety**: Debug and Display implementations never reveal the value
/// - **Explicit Access**: You must call `expose_secret()` to access the value
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::secrets::{Secret, SecretString, ExposeSecret};
///
/// // Create a secret string
/// let password: SecretString = Secret::new("hunter2".to_string());
///
/// // Debug is safe - never shows the value
/// println!("{:?}", password);  // Secret([REDACTED])
///
/// // Explicit access when needed
/// let raw = password.expose_secret();
/// ```
///
/// # Type Aliases
///
/// For convenience, type aliases are provided:
/// - [`SecretString`] = `Secret<String>`
/// - [`SecretBytes`] = `Secret<Vec<u8>>`
pub struct Secret<T: Zeroize> {
    inner: SecretCore<T>,
}

impl<T: Zeroize> Secret<T> {
    /// Create a new secret wrapper.
    ///
    /// The value will be zeroized when the Secret is dropped.
    #[inline]
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            inner: SecretCore::new(value),
        }
    }

    /// Take ownership of the inner value, consuming the Secret.
    ///
    /// # Warning
    ///
    /// After calling this, YOU are responsible for zeroizing the returned value.
    /// The Secret wrapper will not zeroize it since ownership is transferred.
    #[inline]
    pub fn into_inner(self) -> T
    where
        T: Default,
    {
        self.inner.into_inner()
    }
}

impl<T: Zeroize> ExposeSecret<T> for Secret<T> {
    #[inline]
    fn expose_secret(&self) -> &T {
        self.inner.expose_secret()
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl<T: Zeroize> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize + Default> Default for Secret<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

// ============================================================================
// Type Aliases
// ============================================================================

/// A secret string with automatic zeroization.
///
/// This is a type alias for `Secret<String>`, providing a convenient
/// way to handle sensitive string data like passwords, API keys, and tokens.
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::secrets::{SecretString, ExposeSecret};
///
/// let password: SecretString = Secret::new("hunter2".to_string());
/// println!("{:?}", password);  // Secret([REDACTED])
/// ```
pub type SecretString = Secret<String>;

/// Secret bytes with automatic zeroization.
///
/// This is a type alias for `Secret<Vec<u8>>`, providing a convenient
/// way to handle sensitive binary data like encryption keys and certificates.
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::secrets::{SecretBytes, ExposeSecret};
///
/// let key: SecretBytes = Secret::new(vec![0u8; 32]);
/// println!("{:?}", key);  // Secret([REDACTED])
/// ```
pub type SecretBytes = Secret<Vec<u8>>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_expose() {
        let secret = Secret::new("my-secret".to_string());
        assert_eq!(secret.expose_secret(), "my-secret");
    }

    #[test]
    fn test_into_inner() {
        let secret = Secret::new("take-me".to_string());
        let value = secret.into_inner();
        assert_eq!(value, "take-me");
    }

    #[test]
    fn test_debug_redacted() {
        let secret = Secret::new("super-secret".to_string());
        let debug = format!("{:?}", secret);

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn test_display_redacted() {
        let secret = Secret::new("hidden".to_string());
        let display = format!("{}", secret);

        assert_eq!(display, "[REDACTED]");
        assert!(!display.contains("hidden"));
    }

    #[test]
    fn test_from_trait() {
        let secret: Secret<String> = "from-value".to_string().into();
        assert_eq!(secret.expose_secret(), "from-value");
    }

    #[test]
    fn test_default() {
        let secret: Secret<String> = Secret::default();
        assert!(secret.expose_secret().is_empty());
    }

    #[test]
    fn test_clone() {
        let original = Secret::new("clone-me".to_string());
        let cloned = original.clone();

        assert_eq!(original.expose_secret(), cloned.expose_secret());
    }

    #[test]
    fn test_secret_bytes() {
        let bytes: SecretBytes = Secret::new(vec![1, 2, 3, 4]);
        assert_eq!(bytes.expose_secret().len(), 4);
    }

    #[test]
    fn test_secret_string() {
        let string: SecretString = Secret::new("test".to_string());
        assert_eq!(string.expose_secret(), "test");
    }

    #[test]
    fn test_expose_secret_trait() {
        fn use_secret<T: ExposeSecret<String>>(s: &T) -> usize {
            s.expose_secret().len()
        }

        let secret = Secret::new("test-value".to_string());
        assert_eq!(use_secret(&secret), 10);
    }

    #[test]
    fn test_nested_in_struct() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Credentials {
            username: String,
            password: Secret<String>,
        }

        let creds = Credentials {
            username: "alice".to_string(),
            password: Secret::new("hunter2".to_string()),
        };

        let debug = format!("{:?}", creds);

        assert!(debug.contains("alice"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("hunter2"));
    }
}
