//! Secret builder for secure value wrappers (primitives layer).

use super::super::secrets::{SecretBytesCore, SecretCore, SecretStringCore};

/// Internal builder for secret wrapper operations (primitives layer)
#[derive(Debug, Clone, Default)]
pub struct SecretBuilder {
    _private: (),
}

impl SecretBuilder {
    /// Create a new SecretBuilder
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Create a secret string wrapper
    #[must_use]
    pub fn string(&self, value: String) -> SecretStringCore {
        SecretCore::new(value)
    }

    /// Create a secret bytes wrapper
    #[must_use]
    pub fn bytes(&self, value: Vec<u8>) -> SecretBytesCore {
        SecretCore::new(value)
    }

    /// Create a generic secret wrapper
    #[must_use]
    pub fn wrap<T: zeroize::Zeroize>(&self, value: T) -> SecretCore<T> {
        SecretCore::new(value)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::super::super::secrets::ExposeSecretCore;
    use super::super::CryptoBuilder;

    #[test]
    fn test_secret_string() {
        let crypto = CryptoBuilder::new();
        let secret = crypto.secret().string("password123".to_string());

        assert_eq!(secret.expose_secret(), "password123");

        let debug = format!("{:?}", secret);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("password123"));
    }

    #[test]
    fn test_secret_bytes() {
        let crypto = CryptoBuilder::new();
        let secret = crypto.secret().bytes(vec![1, 2, 3, 4, 5]);

        assert_eq!(secret.expose_secret(), &vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_secret_wrap() {
        let crypto = CryptoBuilder::new();
        let secret = crypto.secret().wrap(vec![0u8; 32]);

        assert_eq!(secret.expose_secret().len(), 32);
    }
}
