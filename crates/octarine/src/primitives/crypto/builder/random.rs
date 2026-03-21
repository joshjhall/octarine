//! Random builder for secure random generation.

use crate::primitives::crypto::CryptoError;
use crate::primitives::crypto::keys::{
    fill_random, random_base64, random_base64_url, random_bytes, random_bytes_vec, random_choice,
    random_hex, random_iv_16, random_key_128, random_key_256, random_nonce_12, random_nonce_24,
    random_salt, random_salt_sized, random_sample, random_u32, random_u32_bounded,
    random_u32_range, random_u64, random_u64_bounded, random_uuid_v4, shuffle,
};

/// Builder for secure random generation operations
///
/// Provides methods for generating cryptographically secure random data
/// from the operating system's CSPRNG.
///
/// # Security Features
///
/// - All randomness sourced from OS CSPRNG (getrandom)
/// - No weak PRNGs or seeded generators
/// - Rejection sampling to avoid modulo bias
/// - Type-safe interfaces
#[derive(Debug, Clone, Default)]
pub struct RandomBuilder {
    _private: (),
}

impl RandomBuilder {
    /// Create a new RandomBuilder
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Generate random bytes as a fixed-size array
    ///
    /// # Type Parameters
    ///
    /// * `N` - The number of bytes to generate
    ///
    /// # Example
    ///
    /// ```ignore
    /// let crypto = CryptoBuilder::new();
    /// let key: [u8; 32] = crypto.random().bytes()?;
    /// ```
    pub fn bytes<const N: usize>(&self) -> Result<[u8; N], CryptoError> {
        random_bytes()
    }

    /// Generate random bytes as a Vec
    pub fn bytes_vec(&self, len: usize) -> Result<Vec<u8>, CryptoError> {
        random_bytes_vec(len)
    }

    /// Fill a buffer with random bytes
    pub fn fill(&self, buffer: &mut [u8]) -> Result<(), CryptoError> {
        fill_random(buffer)
    }

    /// Generate a random 256-bit encryption key
    pub fn key_256(&self) -> Result<[u8; 32], CryptoError> {
        random_key_256()
    }

    /// Generate a random 128-bit encryption key
    pub fn key_128(&self) -> Result<[u8; 16], CryptoError> {
        random_key_128()
    }

    /// Generate a random 12-byte nonce (for ChaCha20-Poly1305/AES-GCM)
    pub fn nonce_12(&self) -> Result<[u8; 12], CryptoError> {
        random_nonce_12()
    }

    /// Generate a random 24-byte nonce (for XChaCha20-Poly1305)
    pub fn nonce_24(&self) -> Result<[u8; 24], CryptoError> {
        random_nonce_24()
    }

    /// Generate a random 16-byte IV (for AES-CBC)
    pub fn iv_16(&self) -> Result<[u8; 16], CryptoError> {
        random_iv_16()
    }

    /// Generate a random 16-byte salt
    pub fn salt(&self) -> Result<[u8; 16], CryptoError> {
        random_salt()
    }

    /// Generate a random salt with custom length
    pub fn salt_sized(&self, len: usize) -> Result<Vec<u8>, CryptoError> {
        random_salt_sized(len)
    }

    /// Generate a random u32
    pub fn u32(&self) -> Result<u32, CryptoError> {
        random_u32()
    }

    /// Generate a random u64
    pub fn u64(&self) -> Result<u64, CryptoError> {
        random_u64()
    }

    /// Generate a random u32 in range [0, bound)
    pub fn u32_bounded(&self, bound: u32) -> Result<u32, CryptoError> {
        random_u32_bounded(bound)
    }

    /// Generate a random u64 in range [0, bound)
    pub fn u64_bounded(&self, bound: u64) -> Result<u64, CryptoError> {
        random_u64_bounded(bound)
    }

    /// Generate a random u32 in range [min, max]
    pub fn u32_range(&self, min: u32, max: u32) -> Result<u32, CryptoError> {
        random_u32_range(min, max)
    }

    /// Generate a random UUID v4
    pub fn uuid_v4(&self) -> Result<String, CryptoError> {
        random_uuid_v4()
    }

    /// Generate a random hex string
    pub fn hex(&self, byte_len: usize) -> Result<String, CryptoError> {
        random_hex(byte_len)
    }

    /// Generate a random base64 string
    pub fn base64(&self, byte_len: usize) -> Result<String, CryptoError> {
        random_base64(byte_len)
    }

    /// Generate a random URL-safe base64 string
    pub fn base64_url(&self, byte_len: usize) -> Result<String, CryptoError> {
        random_base64_url(byte_len)
    }

    /// Securely shuffle a slice in-place
    pub fn shuffle<T>(&self, slice: &mut [T]) -> Result<(), CryptoError> {
        shuffle(slice)
    }

    /// Randomly select one element from a slice
    pub fn choice<'a, T>(&self, slice: &'a [T]) -> Result<&'a T, CryptoError> {
        random_choice(slice)
    }

    /// Randomly sample N elements without replacement
    pub fn sample<T: Clone>(&self, slice: &[T], n: usize) -> Result<Vec<T>, CryptoError> {
        random_sample(slice, n)
    }
}

// Note: RandomBuilder tests are included in the main mod.rs integration tests
// since they don't require specific builder test coverage beyond API verification.
