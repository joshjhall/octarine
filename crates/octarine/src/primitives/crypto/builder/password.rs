//! Password builder for hashing and key derivation.

use crate::primitives::crypto::CryptoError;
use crate::primitives::crypto::keys::{
    PasswordCharset, PasswordProfile, PasswordStrength, derive_key_from_password_sync,
    derive_key_from_password_with_profile_sync, derive_multiple_keys_from_password_sync,
    estimate_password_strength, generate_password, hash_password_sync,
    hash_password_with_profile_sync, verify_password_sync,
};

/// Builder for password operations
///
/// Provides methods for secure password hashing and password-based key
/// derivation using Argon2id (RFC 9106, winner of Password Hashing Competition).
///
/// # When to Use
///
/// - **Argon2id (this builder)**: For low-entropy input like user passwords
/// - **HKDF (kdf module)**: For high-entropy input like random keys
///
/// # Security Features
///
/// - Memory-hard: Resists GPU/ASIC attacks
/// - Argon2id variant: Hybrid of side-channel and GPU resistance
/// - Configurable security profiles
/// - OWASP recommended
#[derive(Debug, Clone, Default)]
pub struct PasswordBuilder {
    _private: (),
}

impl PasswordBuilder {
    /// Create a new PasswordBuilder
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Hash a password for secure storage
    ///
    /// Returns a PHC-format string that can be stored in a database.
    /// Uses the Interactive profile (64 MiB, 3 iterations).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let crypto = CryptoBuilder::new();
    /// let hash = crypto.password().hash("user_password")?;
    /// // Store hash in database
    /// ```
    pub fn hash(&self, password: &str) -> Result<String, CryptoError> {
        hash_password_sync(password)
    }

    /// Hash a password with a specific security profile
    ///
    /// Use higher profiles for more sensitive passwords.
    pub fn hash_with_profile(
        &self,
        password: &str,
        profile: PasswordProfile,
    ) -> Result<String, CryptoError> {
        hash_password_with_profile_sync(password, profile)
    }

    /// Verify a password against a stored hash
    ///
    /// Performs constant-time comparison to prevent timing attacks.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let crypto = CryptoBuilder::new();
    /// let hash = crypto.password().hash("secret")?;
    /// assert!(crypto.password().verify("secret", &hash)?);
    /// assert!(!crypto.password().verify("wrong", &hash)?);
    /// ```
    pub fn verify(&self, password: &str, hash: &str) -> Result<bool, CryptoError> {
        verify_password_sync(password, hash)
    }

    /// Derive an encryption key from a password
    ///
    /// Use unique salts for each key derivation.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to derive from
    /// * `salt` - Unique salt (at least 16 bytes recommended)
    /// * `key_len` - Desired key length in bytes (typically 32)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let crypto = CryptoBuilder::new();
    /// let key = crypto.password().derive_key("master", b"unique-salt", 32)?;
    /// ```
    pub fn derive_key(
        &self,
        password: &str,
        salt: &[u8],
        key_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        derive_key_from_password_sync(password, salt, key_len)
    }

    /// Derive an encryption key with a specific security profile
    pub fn derive_key_with_profile(
        &self,
        password: &str,
        salt: &[u8],
        key_len: usize,
        profile: PasswordProfile,
    ) -> Result<Vec<u8>, CryptoError> {
        derive_key_from_password_with_profile_sync(password, salt, key_len, profile)
    }

    /// Derive multiple keys from a single password
    ///
    /// Each domain produces a unique key, useful for deriving separate
    /// encryption, authentication, and signing keys.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let crypto = CryptoBuilder::new();
    /// let keys = crypto.password().derive_multiple(
    ///     "master",
    ///     b"salt",
    ///     &["encryption", "auth", "signing"],
    ///     32,
    /// )?;
    /// ```
    pub fn derive_multiple(
        &self,
        password: &str,
        salt: &[u8],
        domains: &[&str],
        key_len: usize,
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        derive_multiple_keys_from_password_sync(password, salt, domains, key_len)
    }

    /// Estimate password strength
    ///
    /// Returns a strength level based on character classes and length.
    #[must_use]
    pub fn strength(&self, password: &str) -> PasswordStrength {
        estimate_password_strength(password)
    }

    /// Generate a secure random password
    ///
    /// # Arguments
    ///
    /// * `length` - Desired length (minimum 8)
    /// * `charset` - Character set to use
    pub fn generate(&self, length: usize, charset: PasswordCharset) -> Result<String, CryptoError> {
        generate_password(length, charset)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::super::CryptoBuilder;
    use super::PasswordCharset;

    #[test]
    fn test_password_hash_and_verify() {
        let crypto = CryptoBuilder::new();
        let hash = crypto
            .password()
            .hash("test_password")
            .expect("Failed to hash");

        assert!(hash.starts_with("$argon2id$"));
        assert!(
            crypto
                .password()
                .verify("test_password", &hash)
                .expect("Verify failed")
        );
        assert!(
            !crypto
                .password()
                .verify("wrong", &hash)
                .expect("Verify failed")
        );
    }

    #[test]
    fn test_password_derive_key() {
        let crypto = CryptoBuilder::new();
        let key = crypto
            .password()
            .derive_key("master_password", b"unique-salt-1234", 32)
            .expect("Failed to derive");

        assert_eq!(key.len(), 32);

        // Same input produces same output
        let key2 = crypto
            .password()
            .derive_key("master_password", b"unique-salt-1234", 32)
            .expect("Failed to derive");
        assert_eq!(key, key2);
    }

    #[test]
    fn test_password_derive_multiple() {
        let crypto = CryptoBuilder::new();
        let keys = crypto
            .password()
            .derive_multiple("master", b"salt-1234567890", &["enc", "auth", "sign"], 32)
            .expect("Failed to derive");

        assert_eq!(keys.len(), 3);
        // Each key should be unique
        assert_ne!(
            keys.first().expect("should have at least 1 key"),
            keys.get(1).expect("should have at least 2 keys")
        );
        assert_ne!(
            keys.get(1).expect("should have at least 2 keys"),
            keys.get(2).expect("should have at least 3 keys")
        );
    }

    #[test]
    fn test_password_strength() {
        let crypto = CryptoBuilder::new();
        assert!(!crypto.password().strength("weak").is_acceptable());
        assert!(crypto.password().strength("Password123!").is_acceptable());
    }

    #[test]
    fn test_password_generate() {
        let crypto = CryptoBuilder::new();
        let password = crypto
            .password()
            .generate(16, PasswordCharset::Alphanumeric)
            .expect("Failed to generate");

        assert_eq!(password.len(), 16);
        assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
