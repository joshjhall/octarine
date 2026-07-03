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

// ============================================================================
// Tests
// ============================================================================
//
// SECURITY-SENSITIVE: RandomBuilder is the public gateway to the OS CSPRNG.
// These tests exercise the *contracts* callers rely on — correct output
// length, correct alphabet, honoured bounds, and non-repetition across
// successive calls — rather than pinning any specific random value.
//
// Uniqueness note: for k independent draws from a space of size N, the
// probability that ALL are distinct is ~ 1 - C(k,2)/N. For the sizes used
// here (>= 96 bits of entropy, k <= 64) the collision probability is far
// below 1e-20, so a duplicate would signal a real entropy defect, not
// flakiness.

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use std::collections::HashSet;

    fn rb() -> RandomBuilder {
        RandomBuilder::new()
    }

    // ------------------------------------------------------------------
    // Fixed-size byte / key / nonce / IV / salt generators
    // ------------------------------------------------------------------

    #[test]
    fn test_fixed_length_contracts() {
        let b = rb();
        assert_eq!(b.bytes::<32>().expect("bytes").len(), 32);
        assert_eq!(b.key_256().expect("key256").len(), 32);
        assert_eq!(b.key_128().expect("key128").len(), 16);
        assert_eq!(b.nonce_12().expect("nonce12").len(), 12);
        assert_eq!(b.nonce_24().expect("nonce24").len(), 24);
        assert_eq!(b.iv_16().expect("iv16").len(), 16);
        assert_eq!(b.salt().expect("salt").len(), 16);
    }

    #[test]
    fn test_bytes_vec_and_salt_sized_length() {
        let b = rb();
        assert_eq!(b.bytes_vec(48).expect("vec").len(), 48);
        assert_eq!(b.salt_sized(24).expect("salt").len(), 24);
        // Zero-length salt is rejected by the entropy contract.
        assert!(b.salt_sized(0).is_err());
    }

    #[test]
    fn test_fill_overwrites_buffer() {
        let b = rb();
        let mut buffer = [0u8; 32];
        b.fill(&mut buffer).expect("fill");
        // An all-zero 32-byte fill has probability 2^-256; treat non-zero as
        // the entropy contract. (Not a value assertion — a liveness check.)
        assert!(buffer.iter().any(|&x| x != 0), "fill produced all zeros");
    }

    // ------------------------------------------------------------------
    // Uniqueness / entropy contract: successive calls must differ.
    // ------------------------------------------------------------------

    #[test]
    fn test_key_256_successive_calls_differ() {
        let b = rb();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for _ in 0..64 {
            let key = b.key_256().expect("key");
            assert!(seen.insert(key), "duplicate 256-bit key => entropy defect");
        }
    }

    #[test]
    fn test_nonce_12_successive_calls_differ() {
        let b = rb();
        let mut seen: HashSet<[u8; 12]> = HashSet::new();
        for _ in 0..64 {
            let n = b.nonce_12().expect("nonce");
            assert!(seen.insert(n), "duplicate 96-bit nonce => entropy defect");
        }
    }

    #[test]
    fn test_uuid_v4_unique_and_wellformed() {
        let b = rb();
        let mut seen = HashSet::new();
        for _ in 0..64 {
            let id = b.uuid_v4().expect("uuid");
            // RFC 4122 shape: 8-4-4-4-12, version nibble '4', variant in 8/9/a/b.
            assert_eq!(id.len(), 36);
            assert_eq!(
                id.as_bytes().get(14).copied(),
                Some(b'4'),
                "version nibble must be 4"
            );
            let variant = id.as_bytes().get(19).copied().map(char::from);
            assert!(
                matches!(variant, Some('8' | '9' | 'a' | 'b')),
                "variant nibble {variant:?} out of range"
            );
            assert!(seen.insert(id), "duplicate UUID => entropy defect");
        }
    }

    // ------------------------------------------------------------------
    // Encoded string generators: length + alphabet contracts.
    // ------------------------------------------------------------------

    #[test]
    fn test_hex_length_and_alphabet() {
        let b = rb();
        let hex = b.hex(16).expect("hex");
        // 16 bytes -> 32 hex chars, lowercase hex alphabet only.
        assert_eq!(hex.len(), 32);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        // Distinct successive outputs.
        assert_ne!(hex, b.hex(16).expect("hex2"));
    }

    #[test]
    fn test_base64_standard_length() {
        let b = rb();
        // 24 bytes -> 32 standard-base64 chars (no padding needed, 24 % 3 == 0).
        let s = b.base64(24).expect("b64");
        assert_eq!(s.len(), 32);
    }

    #[test]
    fn test_base64_url_is_url_safe() {
        let b = rb();
        let s = b.base64_url(32).expect("b64url");
        // URL-safe, no-pad alphabet: no '+', '/', or '=' characters.
        assert!(!s.contains('+'));
        assert!(!s.contains('/'));
        assert!(!s.contains('='));
        assert!(!s.is_empty());
    }

    // ------------------------------------------------------------------
    // Integer generators: bounds and rejection-sampling contracts.
    // ------------------------------------------------------------------

    #[test]
    fn test_u32_u64_produce_variation() {
        let b = rb();
        // Over many draws we expect more than one distinct value (a constant
        // generator would be a severe defect).
        let a: HashSet<u32> = (0..32).map(|_| b.u32().expect("u32")).collect();
        assert!(a.len() > 1, "u32 generator appears constant");
        let c: HashSet<u64> = (0..32).map(|_| b.u64().expect("u64")).collect();
        assert!(c.len() > 1, "u64 generator appears constant");
    }

    #[test]
    fn test_u32_bounded_respects_exclusive_upper() {
        let b = rb();
        for _ in 0..500 {
            let v = b.u32_bounded(10).expect("bounded");
            assert!(v < 10, "value {v} not in [0,10)");
        }
        // bound of 1 always yields 0; bound of 0 is an error.
        assert_eq!(b.u32_bounded(1).expect("one"), 0);
        assert!(b.u32_bounded(0).is_err());
    }

    #[test]
    fn test_u64_bounded_respects_exclusive_upper() {
        let b = rb();
        for _ in 0..500 {
            let v = b.u64_bounded(1000).expect("bounded");
            assert!(v < 1000, "value {v} not in [0,1000)");
        }
        assert!(b.u64_bounded(0).is_err());
    }

    #[test]
    fn test_u32_range_inclusive_bounds() {
        let b = rb();
        for _ in 0..500 {
            let v = b.u32_range(10, 20).expect("range");
            assert!((10..=20).contains(&v), "value {v} not in [10,20]");
        }
        // Degenerate single-value range.
        assert_eq!(b.u32_range(7, 7).expect("single"), 7);
        // Inverted range is rejected.
        assert!(b.u32_range(20, 10).is_err());
    }

    // ------------------------------------------------------------------
    // Selection helpers: shuffle / choice / sample.
    // ------------------------------------------------------------------

    #[test]
    fn test_shuffle_is_permutation() {
        let b = rb();
        let mut data: Vec<i32> = (0..64).collect();
        let original = data.clone();
        b.shuffle(&mut data).expect("shuffle");
        // Same multiset of elements...
        let mut sorted = data.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, original);
        // ...and (with overwhelming probability) a different order.
        assert_ne!(data, original, "shuffle left order unchanged");
    }

    #[test]
    fn test_choice_returns_member() {
        let b = rb();
        let items = [10, 20, 30, 40, 50];
        for _ in 0..100 {
            let pick = b.choice(&items).expect("choice");
            assert!(items.contains(pick));
        }
        // Empty slice is an error.
        let empty: [i32; 0] = [];
        assert!(b.choice(&empty).is_err());
    }

    #[test]
    fn test_sample_without_replacement() {
        let b = rb();
        let items: Vec<i32> = (1..=20).collect();
        let picked = b.sample(&items, 5).expect("sample");
        assert_eq!(picked.len(), 5);
        // No repeats, all drawn from the source.
        let unique: HashSet<_> = picked.iter().collect();
        assert_eq!(unique.len(), 5, "sample drew a duplicate");
        assert!(picked.iter().all(|x| items.contains(x)));
        // Oversized sample is rejected; zero sample is empty.
        assert!(b.sample(&items, 21).is_err());
        assert!(b.sample(&items, 0).expect("zero").is_empty());
    }

    #[test]
    fn test_default_and_clone_construct() {
        // Default + Clone impls are part of the public surface.
        let b = RandomBuilder::default();
        let _c = b.clone();
        assert_eq!(b.key_128().expect("k").len(), 16);
    }
}
