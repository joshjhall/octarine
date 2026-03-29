//! Typed random integer generation.

use super::{CryptoError, random_bytes};

// ============================================================================
// Typed Random Generation
// ============================================================================

/// Generate a random u8 value.
#[inline]
pub fn random_u8() -> Result<u8, CryptoError> {
    let bytes = random_bytes::<1>()?;
    Ok(bytes[0])
}

/// Generate a random u16 value.
#[inline]
pub fn random_u16() -> Result<u16, CryptoError> {
    let bytes = random_bytes::<2>()?;
    Ok(u16::from_le_bytes(bytes))
}

/// Generate a random u32 value.
#[inline]
pub fn random_u32() -> Result<u32, CryptoError> {
    let bytes = random_bytes::<4>()?;
    Ok(u32::from_le_bytes(bytes))
}

/// Generate a random u64 value.
#[inline]
pub fn random_u64() -> Result<u64, CryptoError> {
    let bytes = random_bytes::<8>()?;
    Ok(u64::from_le_bytes(bytes))
}

/// Generate a random u128 value.
#[inline]
pub fn random_u128() -> Result<u128, CryptoError> {
    let bytes = random_bytes::<16>()?;
    Ok(u128::from_le_bytes(bytes))
}

/// Generate a random usize value.
#[inline]
pub fn random_usize() -> Result<usize, CryptoError> {
    #[cfg(target_pointer_width = "64")]
    {
        random_u64().map(|v| v as usize)
    }
    #[cfg(target_pointer_width = "32")]
    {
        random_u32().map(|v| v as usize)
    }
}

// ============================================================================
// Bounded Random Generation
// ============================================================================

/// Generate a random u32 in the range [0, bound).
///
/// Uses rejection sampling to avoid modulo bias.
///
/// # Arguments
///
/// * `bound` - The exclusive upper bound (must be > 0)
///
/// # Errors
///
/// Returns an error if bound is 0 or if the OS CSPRNG fails.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::random_u32_bounded;
///
/// let dice_roll = random_u32_bounded(6)? + 1; // 1-6
/// ```
pub fn random_u32_bounded(bound: u32) -> Result<u32, CryptoError> {
    if bound == 0 {
        return Err(CryptoError::random_generation("Bound cannot be zero"));
    }

    // Special case: bound == 1 always returns 0
    if bound == 1 {
        return Ok(0);
    }

    // For rejection sampling to avoid modulo bias:
    // We need to reject values >= (u32::MAX - (u32::MAX % bound) + 1) when that doesn't overflow
    // This is equivalent to rejecting values where (value % bound) would have modulo bias
    //
    // Calculate: u32::MAX % bound gives us the "remainder" that causes bias
    // We want to reject values in the range [u32::MAX - remainder, u32::MAX]
    let remainder = u32::MAX
        .checked_rem(bound)
        .ok_or_else(|| CryptoError::random_generation("Bound cannot be zero"))?;

    // threshold = u32::MAX - remainder (this is the last "fair" value before bias starts)
    // We accept values in [0, threshold]
    let threshold = u32::MAX.wrapping_sub(remainder);

    loop {
        let value = random_u32()?;
        // Accept if value <= threshold (no modulo bias)
        if value <= threshold {
            // Safe because bound > 0 (checked above)
            return value
                .checked_rem(bound)
                .ok_or_else(|| CryptoError::random_generation("Division by zero"));
        }
    }
}

/// Generate a random u64 in the range [0, bound).
///
/// Uses rejection sampling to avoid modulo bias.
///
/// # Arguments
///
/// * `bound` - The exclusive upper bound (must be > 0)
///
/// # Errors
///
/// Returns an error if bound is 0 or if the OS CSPRNG fails.
pub fn random_u64_bounded(bound: u64) -> Result<u64, CryptoError> {
    if bound == 0 {
        return Err(CryptoError::random_generation("Bound cannot be zero"));
    }

    // Special case: bound == 1 always returns 0
    if bound == 1 {
        return Ok(0);
    }

    // Same algorithm as u32_bounded
    let remainder = u64::MAX
        .checked_rem(bound)
        .ok_or_else(|| CryptoError::random_generation("Bound cannot be zero"))?;

    let threshold = u64::MAX.wrapping_sub(remainder);

    loop {
        let value = random_u64()?;
        if value <= threshold {
            return value
                .checked_rem(bound)
                .ok_or_else(|| CryptoError::random_generation("Division by zero"));
        }
    }
}

/// Generate a random usize in the range [0, bound).
///
/// Uses rejection sampling to avoid modulo bias.
///
/// # Arguments
///
/// * `bound` - The exclusive upper bound (must be > 0)
///
/// # Errors
///
/// Returns an error if bound is 0 or if the OS CSPRNG fails.
#[inline]
pub fn random_usize_bounded(bound: usize) -> Result<usize, CryptoError> {
    #[cfg(target_pointer_width = "64")]
    {
        random_u64_bounded(bound as u64).map(|v| v as usize)
    }
    #[cfg(target_pointer_width = "32")]
    {
        random_u32_bounded(bound as u32).map(|v| v as usize)
    }
}

// ============================================================================
// Range Random Generation
// ============================================================================

/// Generate a random u32 in the range [min, max].
///
/// # Arguments
///
/// * `min` - The inclusive lower bound
/// * `max` - The inclusive upper bound (must be >= min)
///
/// # Errors
///
/// Returns an error if max < min or if the OS CSPRNG fails.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::random_u32_range;
///
/// let port = random_u32_range(49152, 65535)?; // Dynamic port range
/// ```
pub fn random_u32_range(min: u32, max: u32) -> Result<u32, CryptoError> {
    if max < min {
        return Err(CryptoError::random_generation(
            "max must be greater than or equal to min",
        ));
    }

    let range = max
        .checked_sub(min)
        .and_then(|r| r.checked_add(1))
        .ok_or_else(|| CryptoError::random_generation("Range overflow"))?;

    let offset = random_u32_bounded(range)?;
    offset
        .checked_add(min)
        .ok_or_else(|| CryptoError::random_generation("Overflow when adding min"))
}

/// Generate a random u64 in the range [min, max].
///
/// # Arguments
///
/// * `min` - The inclusive lower bound
/// * `max` - The inclusive upper bound (must be >= min)
///
/// # Errors
///
/// Returns an error if max < min or if the OS CSPRNG fails.
pub fn random_u64_range(min: u64, max: u64) -> Result<u64, CryptoError> {
    if max < min {
        return Err(CryptoError::random_generation(
            "max must be greater than or equal to min",
        ));
    }

    let range = max
        .checked_sub(min)
        .and_then(|r| r.checked_add(1))
        .ok_or_else(|| CryptoError::random_generation("Range overflow"))?;

    let offset = random_u64_bounded(range)?;
    offset
        .checked_add(min)
        .ok_or_else(|| CryptoError::random_generation("Overflow when adding min"))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_random_integers() {
        // Just verify they work
        let _ = random_u8().expect("u8");
        let _ = random_u16().expect("u16");
        let _ = random_u32().expect("u32");
        let _ = random_u64().expect("u64");
        let _ = random_u128().expect("u128");
        let _ = random_usize().expect("usize");
    }

    #[test]
    fn test_random_u32_bounded() {
        for _ in 0..100 {
            let value = random_u32_bounded(10).expect("Bounded random failed");
            assert!(value < 10);
        }
    }

    #[test]
    fn test_random_u32_bounded_zero() {
        let result = random_u32_bounded(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_random_u64_bounded() {
        for _ in 0..100 {
            let value = random_u64_bounded(1000).expect("Bounded random failed");
            assert!(value < 1000);
        }
    }

    #[test]
    fn test_random_u32_range() {
        for _ in 0..100 {
            let value = random_u32_range(10, 20).expect("Range random failed");
            assert!(value >= 10);
            assert!(value <= 20);
        }
    }

    #[test]
    fn test_random_u32_range_invalid() {
        let result = random_u32_range(20, 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_random_u64_range() {
        for _ in 0..100 {
            let value = random_u64_range(1000, 2000).expect("Range random failed");
            assert!(value >= 1000);
            assert!(value <= 2000);
        }
    }

    #[test]
    fn test_distribution_quality() {
        // Verify the bounded random has reasonable distribution
        let mut counts = [0u32; 10];
        let iterations = 10000;

        for _ in 0..iterations {
            let value = random_u32_bounded(10).expect("Bounded");
            *counts
                .get_mut(value as usize)
                .expect("value is always < 10 per bounded range") += 1;
        }

        // Each bucket should get roughly 10% (allow wide tolerance for random variation)
        let expected = iterations / 10;
        for count in counts {
            let diff = (count as i32 - expected as i32).unsigned_abs();
            // Allow up to 20% deviation (very generous for randomness tests)
            assert!(
                diff < expected / 5,
                "Distribution too uneven: count={count}, expected={expected}"
            );
        }
    }
}
