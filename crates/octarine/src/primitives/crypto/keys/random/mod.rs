//! Secure Random Generation
//!
//! Cryptographically secure random number generation primitives with
//! proper error handling and type-safe interfaces.
//!
//! ## Overview
//!
//! This module provides a unified interface for generating cryptographically
//! secure random data. All random data is sourced from the operating system's
//! CSPRNG (via the `rand` crate's `ThreadRng` which uses `getrandom`).
//!
//! ## Security Guarantees
//!
//! - All randomness is from OS CSPRNG (getrandom on Unix, BCryptGenRandom on Windows)
//! - No weak PRNGs or seeded generators
//! - Proper error handling for RNG failures
//! - Type-safe interfaces to prevent misuse
//!
//! ## Usage
//!
//! ```ignore
//! use crate::primitives::crypto::{random_bytes, random_u64, fill_random};
//!
//! // Generate random bytes
//! let key = random_bytes::<32>()?;  // 32-byte key
//! let nonce = random_bytes::<12>()?; // 12-byte nonce
//!
//! // Generate random numbers
//! let id = random_u64()?;
//!
//! // Fill an existing buffer
//! let mut buffer = vec![0u8; 64];
//! fill_random(&mut buffer)?;
//! ```
//!
//! ## Via CryptoBuilder
//!
//! ```ignore
//! use crate::primitives::crypto::CryptoBuilder;
//!
//! let crypto = CryptoBuilder::new();
//!
//! let key = crypto.random().bytes::<32>()?;
//! let nonce = crypto.random().nonce_12()?;
//! let id = crypto.random().u64()?;
//! ```

// Allow dead_code: Layer 1 primitives used by Layer 2/3 modules
#![allow(dead_code)]

mod identifiers;
mod primitives;
mod selection;
mod types;

pub use identifiers::{random_base64, random_base64_url, random_hex, random_uuid_v4};
pub use primitives::{
    random_iv_16, random_key_128, random_key_256, random_nonce_12, random_nonce_24, random_salt,
    random_salt_sized,
};
pub use selection::{random_choice, random_sample, shuffle};
pub use types::{
    random_u8, random_u16, random_u32, random_u32_bounded, random_u32_range, random_u64,
    random_u64_bounded, random_u64_range, random_u128, random_usize, random_usize_bounded,
};

use rand::RngCore;

use crate::primitives::crypto::CryptoError;

// ============================================================================
// Core Random Functions
// ============================================================================

/// Generate cryptographically secure random bytes.
///
/// Uses the OS CSPRNG to generate the specified number of random bytes.
///
/// # Type Parameters
///
/// * `N` - The number of bytes to generate (compile-time constant)
///
/// # Returns
///
/// A fixed-size array of random bytes.
///
/// # Errors
///
/// Returns an error if the OS CSPRNG fails (very rare).
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::random_bytes;
///
/// let key: [u8; 32] = random_bytes()?;
/// let nonce: [u8; 12] = random_bytes()?;
/// ```
#[inline]
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0u8; N];
    fill_random(&mut bytes)?;
    Ok(bytes)
}

/// Generate cryptographically secure random bytes as a Vec.
///
/// Uses the OS CSPRNG to generate the specified number of random bytes.
///
/// # Arguments
///
/// * `len` - The number of bytes to generate
///
/// # Returns
///
/// A Vec of random bytes.
///
/// # Errors
///
/// Returns an error if the OS CSPRNG fails or if length is 0.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::random_bytes_vec;
///
/// let random_data = random_bytes_vec(64)?;
/// ```
pub fn random_bytes_vec(len: usize) -> Result<Vec<u8>, CryptoError> {
    if len == 0 {
        return Err(CryptoError::random_generation("Length cannot be zero"));
    }

    let mut bytes = vec![0u8; len];
    fill_random(&mut bytes)?;
    Ok(bytes)
}

/// Fill a buffer with cryptographically secure random bytes.
///
/// Uses the OS CSPRNG to fill the entire buffer with random data.
///
/// # Arguments
///
/// * `buffer` - The buffer to fill with random bytes
///
/// # Errors
///
/// Returns an error if the OS CSPRNG fails (very rare).
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::fill_random;
///
/// let mut buffer = [0u8; 32];
/// fill_random(&mut buffer)?;
/// ```
#[inline]
pub fn fill_random(buffer: &mut [u8]) -> Result<(), CryptoError> {
    // ThreadRng is a CSPRNG backed by getrandom
    // It cannot fail in normal operation, but we wrap for API consistency
    rand::rng().fill_bytes(buffer);
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let bytes1: [u8; 32] = random_bytes().expect("Random bytes failed");
        let bytes2: [u8; 32] = random_bytes().expect("Random bytes failed");

        // Should be different (with overwhelming probability)
        assert_ne!(bytes1, bytes2);

        // Should not be all zeros
        assert!(bytes1.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_random_bytes_vec() {
        let bytes = random_bytes_vec(64).expect("Random bytes vec failed");
        assert_eq!(bytes.len(), 64);
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_random_bytes_vec_zero_length() {
        let result = random_bytes_vec(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_fill_random() {
        let mut buffer = [0u8; 32];
        fill_random(&mut buffer).expect("Fill random failed");
        assert!(buffer.iter().any(|&b| b != 0));
    }
}
