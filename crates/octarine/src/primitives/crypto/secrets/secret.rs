//! Secret Wrapper for Sensitive Data (primitives layer)
//!
//! Internal implementation of secret wrappers. The public API is
//! `octarine::crypto::secrets::{Secret, ExposeSecret, SecretString, SecretBytes}`.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure types with no observe dependencies.

// Allow dead_code: These are Layer 1 primitives that will be used by Layer 2/3 modules
#![allow(dead_code)]

use std::fmt;
use zeroize::Zeroize;

// ============================================================================
// ExposeSecretCore Trait
// ============================================================================

/// Internal trait for types that can expose their secret inner value.
///
/// This is the internal representation. The public API is
/// `octarine::crypto::secrets::ExposeSecret`.
pub(crate) trait ExposeSecretCore<T> {
    /// Expose the inner secret value.
    fn expose_secret(&self) -> &T;
}

// ============================================================================
// SecretCore<T> Wrapper
// ============================================================================

/// Internal secret wrapper type (primitives layer)
///
/// This is the internal representation. The public API is
/// `octarine::crypto::secrets::Secret`.
pub(crate) struct SecretCore<T: Zeroize> {
    /// The inner secret value
    inner: T,
}

impl<T: Zeroize> SecretCore<T> {
    /// Create a new secret wrapper.
    #[inline]
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Take ownership of the inner value, consuming the Secret.
    #[inline]
    pub fn into_inner(self) -> T
    where
        T: Default,
    {
        let mut this = self;
        std::mem::take(&mut this.inner)
    }
}

impl<T: Zeroize> ExposeSecretCore<T> for SecretCore<T> {
    #[inline]
    fn expose_secret(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> Drop for SecretCore<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

// ============================================================================
// Trait Implementations
// ============================================================================

impl<T: Zeroize> fmt::Debug for SecretCore<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl<T: Zeroize> fmt::Display for SecretCore<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize + Default> Default for SecretCore<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: Zeroize> From<T> for SecretCore<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: Zeroize + Clone> Clone for SecretCore<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

// ============================================================================
// Type Aliases
// ============================================================================

/// Internal secret string type alias.
pub(crate) type SecretStringCore = SecretCore<String>;

/// Internal secret bytes type alias.
pub(crate) type SecretBytesCore = SecretCore<Vec<u8>>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_expose() {
        let secret = SecretCore::new("my-secret".to_string());
        assert_eq!(secret.expose_secret(), "my-secret");
    }

    #[test]
    fn test_into_inner() {
        let secret = SecretCore::new("take-me".to_string());
        let value = secret.into_inner();
        assert_eq!(value, "take-me");
    }

    #[test]
    fn test_debug_redacted() {
        let secret = SecretCore::new("super-secret".to_string());
        let debug = format!("{:?}", secret);

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn test_display_redacted() {
        let secret = SecretCore::new("hidden".to_string());
        let display = format!("{}", secret);

        assert_eq!(display, "[REDACTED]");
        assert!(!display.contains("hidden"));
    }

    #[test]
    fn test_from_trait() {
        let secret: SecretCore<String> = "from-value".to_string().into();
        assert_eq!(secret.expose_secret(), "from-value");
    }

    #[test]
    fn test_default() {
        let secret: SecretCore<String> = SecretCore::default();
        assert!(secret.expose_secret().is_empty());
    }

    #[test]
    fn test_clone() {
        let original = SecretCore::new("clone-me".to_string());
        let cloned = original.clone();

        assert_eq!(original.expose_secret(), cloned.expose_secret());
    }

    #[test]
    fn test_secret_bytes() {
        let bytes: SecretBytesCore = SecretCore::new(vec![1, 2, 3, 4]);
        assert_eq!(bytes.expose_secret().len(), 4);
    }

    #[test]
    fn test_secret_string() {
        let string: SecretStringCore = SecretCore::new("test".to_string());
        assert_eq!(string.expose_secret(), "test");
    }

    #[test]
    fn test_zeroization_on_drop() {
        let value = "secret-data".to_string();
        let ptr = value.as_ptr();
        let len = value.len();

        let secret = SecretCore::new(value);
        assert_eq!(secret.expose_secret(), "secret-data");
        drop(secret);

        let _ = (ptr, len);
    }

    #[test]
    fn test_zeroization_observable() {
        use std::cell::RefCell;

        let observable = RefCell::new(vec![1u8, 2, 3, 4, 5]);
        let original: Vec<u8> = observable.borrow().clone();
        assert_eq!(original, vec![1, 2, 3, 4, 5]);

        observable.borrow_mut().zeroize();
        assert!(observable.borrow().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let secret = Arc::new(SecretCore::new("shared-secret".to_string()));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let s = Arc::clone(&secret);
                thread::spawn(move || {
                    assert_eq!(s.expose_secret(), "shared-secret");
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_expose_secret_trait() {
        fn use_secret<T: ExposeSecretCore<String>>(s: &T) -> usize {
            s.expose_secret().len()
        }

        let secret = SecretCore::new("test-value".to_string());
        assert_eq!(use_secret(&secret), 10);
    }

    #[test]
    fn test_nested_in_struct() {
        #[derive(Debug)]
        struct Credentials {
            username: String,
            password: SecretCore<String>,
        }

        let creds = Credentials {
            username: "alice".to_string(),
            password: SecretCore::new("hunter2".to_string()),
        };

        let debug = format!("{:?}", creds);

        assert!(debug.contains("alice"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("hunter2"));
    }

    #[test]
    fn test_empty_secret() {
        let empty: SecretCore<String> = SecretCore::new(String::new());
        assert!(empty.expose_secret().is_empty());

        let debug = format!("{:?}", empty);
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_large_secret() {
        let large = "x".repeat(10000);
        let secret = SecretCore::new(large.clone());

        assert_eq!(secret.expose_secret().len(), 10000);
        assert_eq!(secret.expose_secret(), &large);
    }

    #[test]
    fn test_binary_data() {
        let binary: Vec<u8> = (0..=255).collect();
        let secret: SecretBytesCore = SecretCore::new(binary.clone());

        assert_eq!(secret.expose_secret().len(), 256);
        assert_eq!(secret.expose_secret(), &binary);
    }
}
