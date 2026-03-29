//! Password-Based Key Derivation
//!
//! Secure password hashing and key derivation using Argon2id (RFC 9106).
//! This module provides memory-hard password processing suitable for
//! low-entropy input like user passwords.
//!
//! ## Async-First Design
//!
//! Password operations are intentionally slow (~100ms+) to resist brute-force
//! attacks. This module provides async-first APIs that offload CPU-intensive
//! work to a blocking thread pool:
//!
//! - Primary API is async (`hash_password()`, `verify_password()`, etc.)
//! - Sync variants available with `*_sync()` suffix
//!
//! ## Why Argon2id?
//!
//! - **Winner of the Password Hashing Competition (PHC)**
//! - **Memory-hard**: Resists GPU/ASIC attacks by requiring significant RAM
//! - **Argon2id variant**: Hybrid of Argon2i (side-channel resistant) and
//!   Argon2d (GPU resistant) - best of both worlds
//! - **OWASP recommended**: Current best practice for password hashing
//!
//! ## Security Parameters
//!
//! | Profile | Memory | Iterations | Parallelism | Use Case |
//! |---------|--------|------------|-------------|----------|
//! | Interactive | 64 MiB | 3 | 4 | Login/real-time |
//! | Moderate | 256 MiB | 4 | 4 | Background processing |
//! | Sensitive | 1 GiB | 6 | 4 | High-value secrets |
//!
//! ## Example (Async)
//!
//! ```ignore
//! use crate::primitives::crypto::keys::password::{hash_password, verify_password};
//!
//! // Hash a password for storage (runs on blocking thread pool)
//! let hash = hash_password("user_password").await?;
//! assert!(verify_password("user_password", &hash).await?);
//! ```
//!
//! ## Example (Sync)
//!
//! ```ignore
//! use crate::primitives::crypto::keys::password::{hash_password_sync, verify_password_sync};
//!
//! // Hash synchronously (blocks current thread)
//! let hash = hash_password_sync("user_password")?;
//! assert!(verify_password_sync("user_password", &hash)?);
//! ```
//!
//! ## IMPORTANT: HKDF vs Argon2
//!
//! - Use **HKDF** (from `kdf.rs`) when input is already high-entropy (random keys)
//! - Use **Argon2** (this module) when input is low-entropy (user passwords)
//!
//! Using HKDF on passwords is a security vulnerability!
//!
//! ## See Also
//!
//! - [`hkdf_sha3_256`](super::hkdf_sha3_256) - Key derivation for high-entropy input
//! - [`random_bytes`](super::random_bytes) - Generate cryptographic random data
//! - [`SecretString`](super::SecretString) - Zeroizing wrapper for password storage

// Allow dead_code: These are Layer 1 primitives that will be used by Layer 2/3 modules
#![allow(dead_code)]

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use tokio::task::JoinError;
use zeroize::Zeroize;

use crate::primitives::crypto::CryptoError;
use crate::primitives::runtime::r#async::async_utils::spawn_blocking;

// ============================================================================
// Error Type
// ============================================================================

/// Error type for async password operations
#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    /// Underlying crypto operation failed
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// Blocking task was cancelled or panicked
    #[error("blocking task failed: {0}")]
    TaskFailed(#[from] JoinError),
}

impl From<PasswordError> for crate::primitives::types::Problem {
    fn from(err: PasswordError) -> Self {
        match err {
            PasswordError::Crypto(e) => e.into(),
            PasswordError::TaskFailed(e) => Self::Runtime(format!("password task failed: {e}")),
        }
    }
}

// ============================================================================
// Configuration Profiles
// ============================================================================

/// Security profile for password hashing.
///
/// Higher security profiles use more memory and CPU time, providing
/// better resistance to brute-force attacks at the cost of latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PasswordProfile {
    /// Fast hashing for interactive use (login, real-time).
    ///
    /// Parameters: 64 MiB memory, 3 iterations, parallelism 4
    /// Approximate time: 100-300ms on modern hardware
    #[default]
    Interactive,

    /// Balanced security for background processing.
    ///
    /// Parameters: 256 MiB memory, 4 iterations, parallelism 4
    /// Approximate time: 500ms-1s on modern hardware
    Moderate,

    /// Maximum security for high-value secrets.
    ///
    /// Parameters: 1 GiB memory, 6 iterations, parallelism 4
    /// Approximate time: 2-5s on modern hardware
    Sensitive,

    /// Custom parameters for specific requirements.
    Custom {
        /// Memory cost in KiB (e.g., 65536 = 64 MiB)
        memory_kib: u32,
        /// Number of iterations (time cost)
        iterations: u32,
        /// Degree of parallelism
        parallelism: u32,
    },
}

impl PasswordProfile {
    /// Get the Argon2 parameters for this profile.
    fn params(&self) -> Result<Params, CryptoError> {
        let (m_cost, t_cost, p_cost) = match self {
            Self::Interactive => (64 * 1024, 3, 4), // 64 MiB
            Self::Moderate => (256 * 1024, 4, 4),   // 256 MiB
            Self::Sensitive => (1024 * 1024, 6, 4), // 1 GiB
            Self::Custom {
                memory_kib,
                iterations,
                parallelism,
            } => (*memory_kib, *iterations, *parallelism),
        };

        Params::new(m_cost, t_cost, p_cost, Some(32))
            .map_err(|e| CryptoError::key_derivation(format!("Invalid Argon2 parameters: {e}")))
    }

    /// Get the memory usage in human-readable format.
    pub fn memory_usage(&self) -> &'static str {
        match self {
            Self::Interactive => "64 MiB",
            Self::Moderate => "256 MiB",
            Self::Sensitive => "1 GiB",
            Self::Custom { .. } => "custom",
        }
    }
}

// ============================================================================
// Async Password Hashing (Primary API)
// ============================================================================

/// Hash a password for secure storage (async).
///
/// Runs on a blocking thread pool to avoid blocking the async runtime.
/// Returns a PHC-format string containing the algorithm, parameters,
/// salt, and hash.
///
/// # Example
///
/// ```ignore
/// let hash = hash_password("user_password").await?;
/// // Store `hash` in database
/// ```
pub async fn hash_password(password: &str) -> Result<String, PasswordError> {
    hash_password_with_profile(password, PasswordProfile::Interactive).await
}

/// Hash a password with a specific security profile (async).
///
/// Runs on a blocking thread pool.
pub async fn hash_password_with_profile(
    password: &str,
    profile: PasswordProfile,
) -> Result<String, PasswordError> {
    let password = password.to_owned();
    let result =
        spawn_blocking(move || hash_password_with_profile_sync(&password, profile)).await?;
    Ok(result?)
}

/// Verify a password against a stored hash (async).
///
/// Runs on a blocking thread pool. Performs constant-time comparison.
///
/// # Example
///
/// ```ignore
/// if verify_password("user_input", &stored_hash).await? {
///     // Login successful
/// }
/// ```
pub async fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
    let password = password.to_owned();
    let hash = hash.to_owned();
    let result = spawn_blocking(move || verify_password_sync(&password, &hash)).await?;
    Ok(result?)
}

// ============================================================================
// Sync Password Hashing
// ============================================================================

/// Hash a password for secure storage (sync).
///
/// **Warning**: Blocks the current thread. In async contexts, use `hash_password()`.
///
/// Returns a PHC-format string like:
/// `$argon2id$v=19$m=65536,t=3,p=4$...salt...$...hash...`
pub fn hash_password_sync(password: &str) -> Result<String, CryptoError> {
    hash_password_with_profile_sync(password, PasswordProfile::Interactive)
}

/// Hash a password with a specific security profile (sync).
///
/// **Warning**: Blocks the current thread.
pub fn hash_password_with_profile_sync(
    password: &str,
    profile: PasswordProfile,
) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let params = profile.params()?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::key_derivation(format!("Password hashing failed: {e}")))?;

    Ok(hash.to_string())
}

/// Verify a password against a stored hash (sync).
///
/// **Warning**: Blocks the current thread. In async contexts, use `verify_password()`.
///
/// Performs constant-time comparison to prevent timing attacks.
pub fn verify_password_sync(password: &str, hash: &str) -> Result<bool, CryptoError> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| CryptoError::key_derivation(format!("Invalid hash format: {e}")))?;

    // Extract params from the hash to use the same parameters
    let params = Params::try_from(&parsed_hash)
        .map_err(|e| CryptoError::key_derivation(format!("Invalid hash parameters: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(CryptoError::key_derivation(format!(
            "Password verification failed: {e}"
        ))),
    }
}

// ============================================================================
// Async Key Derivation (Primary API)
// ============================================================================

/// Derive an encryption key from a password (async).
///
/// Runs on a blocking thread pool. The salt should be unique per key.
///
/// # Example
///
/// ```ignore
/// let key = derive_key_from_password("master_password", &salt, 32).await?;
/// ```
pub async fn derive_key_from_password(
    password: &str,
    salt: &[u8],
    key_len: usize,
) -> Result<Vec<u8>, PasswordError> {
    derive_key_from_password_with_profile(password, salt, key_len, PasswordProfile::Interactive)
        .await
}

/// Derive an encryption key with a specific security profile (async).
///
/// Runs on a blocking thread pool.
pub async fn derive_key_from_password_with_profile(
    password: &str,
    salt: &[u8],
    key_len: usize,
    profile: PasswordProfile,
) -> Result<Vec<u8>, PasswordError> {
    let password = password.to_owned();
    let salt = salt.to_vec();
    let result = spawn_blocking(move || {
        derive_key_from_password_with_profile_sync(&password, &salt, key_len, profile)
    })
    .await?;
    Ok(result?)
}

/// Derive multiple keys from a single password (async).
///
/// Runs on a blocking thread pool. Each key is derived with a unique
/// domain separator.
pub async fn derive_multiple_keys_from_password(
    password: &str,
    salt: &[u8],
    domains: &[&str],
    key_len: usize,
) -> Result<Vec<Vec<u8>>, PasswordError> {
    derive_multiple_keys_with_profile(
        password,
        salt,
        domains,
        key_len,
        PasswordProfile::Interactive,
    )
    .await
}

/// Derive multiple keys with a specific security profile (async).
///
/// Runs on a blocking thread pool.
pub async fn derive_multiple_keys_with_profile(
    password: &str,
    salt: &[u8],
    domains: &[&str],
    key_len: usize,
    profile: PasswordProfile,
) -> Result<Vec<Vec<u8>>, PasswordError> {
    let password = password.to_owned();
    let salt = salt.to_vec();
    let domains: Vec<String> = domains.iter().map(|s| (*s).to_owned()).collect();
    let result = spawn_blocking(move || {
        let domain_refs: Vec<&str> = domains.iter().map(String::as_str).collect();
        derive_multiple_keys_with_profile_sync(&password, &salt, &domain_refs, key_len, profile)
    })
    .await?;
    Ok(result?)
}

// ============================================================================
// Sync Key Derivation
// ============================================================================

/// Derive an encryption key from a password (sync).
///
/// **Warning**: Blocks the current thread. In async contexts, use `derive_key_from_password()`.
///
/// # Arguments
///
/// * `password` - The password to derive from
/// * `salt` - A unique salt (at least 16 bytes recommended)
/// * `key_len` - Desired key length in bytes (typically 32 for 256-bit)
pub fn derive_key_from_password_sync(
    password: &str,
    salt: &[u8],
    key_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    derive_key_from_password_with_profile_sync(
        password,
        salt,
        key_len,
        PasswordProfile::Interactive,
    )
}

/// Derive an encryption key with a specific security profile (sync).
///
/// **Warning**: Blocks the current thread.
pub fn derive_key_from_password_with_profile_sync(
    password: &str,
    salt: &[u8],
    key_len: usize,
    profile: PasswordProfile,
) -> Result<Vec<u8>, CryptoError> {
    if salt.len() < 8 {
        return Err(CryptoError::key_derivation("Salt must be at least 8 bytes"));
    }

    if key_len == 0 || key_len > 1024 {
        return Err(CryptoError::key_derivation(
            "Key length must be 1-1024 bytes",
        ));
    }

    // Create params with the desired output length
    let base_params = profile.params()?;
    let params = Params::new(
        base_params.m_cost(),
        base_params.t_cost(),
        base_params.p_cost(),
        Some(key_len),
    )
    .map_err(|e| CryptoError::key_derivation(format!("Invalid parameters: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = vec![0u8; key_len];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| CryptoError::key_derivation(format!("Key derivation failed: {e}")))?;

    Ok(output)
}

/// Derive multiple keys from a single password (sync).
///
/// **Warning**: Blocks the current thread.
pub fn derive_multiple_keys_from_password_sync(
    password: &str,
    salt: &[u8],
    domains: &[&str],
    key_len: usize,
) -> Result<Vec<Vec<u8>>, CryptoError> {
    derive_multiple_keys_with_profile_sync(
        password,
        salt,
        domains,
        key_len,
        PasswordProfile::Interactive,
    )
}

/// Derive multiple keys with a specific security profile (sync).
///
/// **Warning**: Blocks the current thread.
pub fn derive_multiple_keys_with_profile_sync(
    password: &str,
    salt: &[u8],
    domains: &[&str],
    key_len: usize,
    profile: PasswordProfile,
) -> Result<Vec<Vec<u8>>, CryptoError> {
    let mut keys = Vec::with_capacity(domains.len());

    for domain in domains {
        // Create domain-specific salt
        let mut domain_salt = salt.to_vec();
        domain_salt.extend_from_slice(domain.as_bytes());

        let key =
            derive_key_from_password_with_profile_sync(password, &domain_salt, key_len, profile)?;
        keys.push(key);
    }

    Ok(keys)
}

// ============================================================================
// Password Strength Estimation
// ============================================================================

/// Minimum acceptable password entropy bits.
pub const MIN_PASSWORD_ENTROPY: u32 = 40;

/// Recommended password entropy bits.
pub const RECOMMENDED_PASSWORD_ENTROPY: u32 = 60;

/// Password strength level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PasswordStrength {
    /// Very weak - easily guessable
    VeryWeak,
    /// Weak - vulnerable to targeted attacks
    Weak,
    /// Fair - acceptable for low-value accounts
    Fair,
    /// Strong - good for most purposes
    Strong,
    /// Very strong - suitable for high-security use
    VeryStrong,
}

impl PasswordStrength {
    /// Check if the strength meets minimum requirements.
    pub fn is_acceptable(&self) -> bool {
        *self >= Self::Fair
    }

    /// Check if the strength is recommended for sensitive use.
    pub fn is_recommended(&self) -> bool {
        *self >= Self::Strong
    }
}

/// Estimate password strength.
///
/// This provides a rough estimate based on character classes and length.
/// For production use, consider a more sophisticated library like `zxcvbn`.
///
/// # Arguments
///
/// * `password` - The password to evaluate
///
/// # Returns
///
/// A `PasswordStrength` enum value.
pub fn estimate_password_strength(password: &str) -> PasswordStrength {
    let entropy = estimate_entropy(password);

    match entropy {
        0..=25 => PasswordStrength::VeryWeak,
        26..=40 => PasswordStrength::Weak,
        41..=60 => PasswordStrength::Fair,
        61..=80 => PasswordStrength::Strong,
        _ => PasswordStrength::VeryStrong,
    }
}

/// Estimate password entropy in bits.
///
/// Uses character class analysis to estimate entropy.
fn estimate_entropy(password: &str) -> u32 {
    if password.is_empty() {
        return 0;
    }

    let len = password.len() as u32;
    let mut charset_size: u32 = 0;

    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());

    if has_lower {
        charset_size = charset_size.saturating_add(26);
    }
    if has_upper {
        charset_size = charset_size.saturating_add(26);
    }
    if has_digit {
        charset_size = charset_size.saturating_add(10);
    }
    if has_special {
        charset_size = charset_size.saturating_add(32);
    }

    if charset_size == 0 {
        charset_size = 26; // Fallback for unicode-only
    }

    // Entropy = log2(charset_size^length) = length * log2(charset_size)
    // We approximate log2 to avoid floating point
    let log2_charset = 32u32.saturating_sub(charset_size.leading_zeros());
    len.saturating_mul(log2_charset)
}

// ============================================================================
// Secure Password Generation
// ============================================================================

/// Character set for password generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordCharset {
    /// Alphanumeric only (a-z, A-Z, 0-9)
    Alphanumeric,
    /// Alphanumeric plus common symbols
    AlphanumericSymbols,
    /// All printable ASCII
    Full,
}

impl PasswordCharset {
    fn chars(&self) -> &'static [u8] {
        match self {
            Self::Alphanumeric => {
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            }
            Self::AlphanumericSymbols => {
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
            }
            Self::Full => {
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
            }
        }
    }
}

/// Generate a secure random password.
///
/// # Arguments
///
/// * `length` - Desired password length (minimum 8)
/// * `charset` - Character set to use
///
/// # Returns
///
/// A randomly generated password string.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::password::{generate_password, PasswordCharset};
///
/// let password = generate_password(16, PasswordCharset::AlphanumericSymbols)?;
/// ```
pub fn generate_password(length: usize, charset: PasswordCharset) -> Result<String, CryptoError> {
    use super::fill_random;

    if length < 8 {
        return Err(CryptoError::key_derivation(
            "Password length must be at least 8",
        ));
    }

    if length > 256 {
        return Err(CryptoError::key_derivation(
            "Password length must be at most 256",
        ));
    }

    let chars = charset.chars();
    let chars_len = chars.len();

    // Use rejection sampling to avoid modulo bias
    let mut password = Vec::with_capacity(length);

    // Pre-compute the rejection threshold to avoid modulo bias
    // We reject values >= (256 - (256 % chars_len)) to ensure uniform distribution
    let remainder = 256_usize
        .checked_rem(chars_len)
        .ok_or_else(|| CryptoError::key_derivation("Invalid charset length"))?;
    let threshold = 256_usize
        .checked_sub(remainder)
        .ok_or_else(|| CryptoError::key_derivation("Arithmetic overflow"))?;

    while password.len() < length {
        let mut byte = [0u8; 1];
        fill_random(&mut byte)?;

        // Rejection sampling: only accept values that don't cause modulo bias
        let idx = byte[0] as usize;
        if idx < threshold {
            let char_idx = idx
                .checked_rem(chars_len)
                .ok_or_else(|| CryptoError::key_derivation("Invalid charset length"))?;
            // Safe: char_idx is always < chars_len due to modulo
            let ch = chars
                .get(char_idx)
                .ok_or_else(|| CryptoError::key_derivation("Index out of bounds"))?;
            password.push(*ch);
        }
    }

    String::from_utf8(password)
        .map_err(|e| CryptoError::key_derivation(format!("Invalid password bytes: {e}")))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // ========================================================================
    // Sync Tests
    // ========================================================================

    #[test]
    fn test_hash_and_verify() {
        let hash = hash_password_sync("test_password").expect("Failed to hash");
        assert!(hash.starts_with("$argon2id$"));

        assert!(verify_password_sync("test_password", &hash).expect("Verify failed"));
        assert!(!verify_password_sync("wrong_password", &hash).expect("Verify failed"));
    }

    #[test]
    fn test_hash_with_profiles() {
        // Test that different profiles work
        let hash_interactive =
            hash_password_with_profile_sync("test", PasswordProfile::Interactive).expect("Failed");
        let hash_moderate =
            hash_password_with_profile_sync("test", PasswordProfile::Moderate).expect("Failed");

        // Both should verify correctly
        assert!(verify_password_sync("test", &hash_interactive).expect("Verify failed"));
        assert!(verify_password_sync("test", &hash_moderate).expect("Verify failed"));

        // Different parameters produce different hashes
        assert_ne!(hash_interactive, hash_moderate);
    }

    #[test]
    fn test_derive_key_from_password() {
        let salt = b"unique-salt-1234";
        let key = derive_key_from_password_sync("password", salt, 32).expect("Failed to derive");

        assert_eq!(key.len(), 32);

        // Same input produces same output
        let key2 = derive_key_from_password_sync("password", salt, 32).expect("Failed to derive");
        assert_eq!(key, key2);

        // Different password produces different key
        let key3 = derive_key_from_password_sync("different", salt, 32).expect("Failed to derive");
        assert_ne!(key, key3);

        // Different salt produces different key
        let key4 = derive_key_from_password_sync("password", b"different-salt!!", 32)
            .expect("Failed to derive");
        assert_ne!(key, key4);
    }

    #[test]
    fn test_derive_key_from_password_lengths() {
        let salt = b"test-salt-12345";

        let key16 = derive_key_from_password_sync("pass", salt, 16).expect("Failed");
        let key32 = derive_key_from_password_sync("pass", salt, 32).expect("Failed");
        let key64 = derive_key_from_password_sync("pass", salt, 64).expect("Failed");

        assert_eq!(key16.len(), 16);
        assert_eq!(key32.len(), 32);
        assert_eq!(key64.len(), 64);
    }

    #[test]
    fn test_derive_key_from_password_validation() {
        // Salt too short
        let result = derive_key_from_password_sync("pass", b"short", 32);
        assert!(result.is_err());

        // Key length zero
        let result = derive_key_from_password_sync("pass", b"valid-salt-here", 0);
        assert!(result.is_err());

        // Key length too long
        let result = derive_key_from_password_sync("pass", b"valid-salt-here", 2048);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_multiple_keys() {
        let salt = b"base-salt-value";
        let domains = ["encryption", "authentication", "signing"];

        let keys =
            derive_multiple_keys_from_password_sync("master", salt, &domains, 32).expect("Failed");

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
        assert_ne!(
            keys.first().expect("should have at least 1 key"),
            keys.get(2).expect("should have at least 3 keys")
        );

        // Each key should be 32 bytes
        for key in &keys {
            assert_eq!(key.len(), 32);
        }
    }

    #[test]
    fn test_password_strength() {
        assert_eq!(estimate_password_strength(""), PasswordStrength::VeryWeak);
        assert_eq!(
            estimate_password_strength("abc"),
            PasswordStrength::VeryWeak
        );
        assert_eq!(
            estimate_password_strength("password"),
            PasswordStrength::Weak
        );
        assert!(estimate_password_strength("Password123!").is_acceptable());
        assert!(estimate_password_strength("Str0ng!P@ssw0rd#2024").is_recommended());
    }

    #[test]
    fn test_password_generation() {
        let pass = generate_password(16, PasswordCharset::Alphanumeric).expect("Failed");
        assert_eq!(pass.len(), 16);
        assert!(pass.chars().all(|c| c.is_ascii_alphanumeric()));

        let pass2 = generate_password(20, PasswordCharset::AlphanumericSymbols).expect("Failed");
        assert_eq!(pass2.len(), 20);

        // Should generate different passwords each time
        let pass3 = generate_password(16, PasswordCharset::Alphanumeric).expect("Failed");
        assert_ne!(pass, pass3);
    }

    #[test]
    fn test_password_generation_validation() {
        // Too short
        let result = generate_password(4, PasswordCharset::Alphanumeric);
        assert!(result.is_err());

        // Too long
        let result = generate_password(500, PasswordCharset::Alphanumeric);
        assert!(result.is_err());
    }

    #[test]
    fn test_custom_profile() {
        let profile = PasswordProfile::Custom {
            memory_kib: 32 * 1024, // 32 MiB
            iterations: 2,
            parallelism: 2,
        };

        let hash = hash_password_with_profile_sync("test", profile).expect("Failed");
        assert!(verify_password_sync("test", &hash).expect("Verify failed"));
    }

    #[test]
    fn test_profile_memory_usage() {
        assert_eq!(PasswordProfile::Interactive.memory_usage(), "64 MiB");
        assert_eq!(PasswordProfile::Moderate.memory_usage(), "256 MiB");
        assert_eq!(PasswordProfile::Sensitive.memory_usage(), "1 GiB");
    }

    #[test]
    fn test_empty_password() {
        // Empty password should still work (though not recommended)
        let hash = hash_password_sync("").expect("Failed to hash");
        assert!(verify_password_sync("", &hash).expect("Verify failed"));
        assert!(!verify_password_sync("x", &hash).expect("Verify failed"));
    }

    #[test]
    fn test_unicode_password() {
        let password = "пароль密码🔐";
        let hash = hash_password_sync(password).expect("Failed to hash");
        assert!(verify_password_sync(password, &hash).expect("Verify failed"));
        assert!(!verify_password_sync("wrong", &hash).expect("Verify failed"));
    }

    // ========================================================================
    // Async Tests
    // ========================================================================

    #[tokio::test]
    async fn test_hash_and_verify_async() {
        let hash = hash_password("test_password")
            .await
            .expect("Failed to hash");
        assert!(hash.starts_with("$argon2id$"));

        assert!(
            verify_password("test_password", &hash)
                .await
                .expect("Verify failed")
        );
        assert!(
            !verify_password("wrong_password", &hash)
                .await
                .expect("Verify failed")
        );
    }

    #[tokio::test]
    async fn test_derive_key_async() {
        let salt = b"unique-salt-1234";
        let key = derive_key_from_password("password", salt, 32)
            .await
            .expect("Failed to derive");
        assert_eq!(key.len(), 32);
    }

    #[tokio::test]
    async fn test_derive_multiple_keys_async() {
        let salt = b"base-salt-value";
        let domains = ["encryption", "authentication"];

        let keys = derive_multiple_keys_from_password("master", salt, &domains, 32)
            .await
            .expect("Failed");

        assert_eq!(keys.len(), 2);
        assert_ne!(
            keys.first().expect("should have at least 1 key"),
            keys.get(1).expect("should have at least 2 keys")
        );
    }
}
