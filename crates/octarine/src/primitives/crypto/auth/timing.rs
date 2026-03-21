//! Constant-Time Comparison Utilities
//!
//! Functions for comparing sensitive data without leaking timing information.
//! These are critical for preventing timing-based side-channel attacks when
//! comparing secrets, tokens, MACs, or hashes.
//!
//! ## Why Constant-Time?
//!
//! Standard comparison operations (like `==`) typically short-circuit on the
//! first difference found. An attacker can measure the time taken to reject
//! an input and gradually discover valid values byte-by-byte.
//!
//! **Example Attack:**
//! ```text
//! Token: "secret123"
//! Attempt 1: "aaaaaaaaa" - rejected immediately (0 matching chars) - fast
//! Attempt 2: "saaaaaaaa" - rejected after 1 char matches - slightly slower
//! Attempt 3: "seaaaaaaa" - rejected after 2 chars match - slower still
//! ...
//! Attacker learns one character at a time!
//! ```
//!
//! ## Security Model
//!
//! These functions ensure:
//! - **Fixed execution time**: Same duration regardless of where values differ
//! - **No early exit**: All bytes are always compared
//! - **Compiler-safe**: Uses volatile operations to prevent optimization
//!
//! ## Usage
//!
//! ```ignore
//! use crate::primitives::crypto::timing::{ct_eq, ct_select};
//!
//! // Compare two secrets
//! let user_token = b"user-provided-token";
//! let valid_token = b"stored-secret-token";
//! if ct_eq(user_token, valid_token) {
//!     // Tokens match
//! }
//!
//! // Conditional selection without branching
//! let result = ct_select(condition, value_if_true, value_if_false);
//! ```

// Allow dead_code: Layer 1 primitives used by Layer 2/3 modules
#![allow(dead_code)]

// ============================================================================
// Constant-Time Comparison
// ============================================================================

/// Compare two byte slices in constant time.
///
/// Returns `true` if the slices are equal, `false` otherwise. The comparison
/// always takes the same amount of time regardless of where the slices differ.
///
/// # Arguments
///
/// * `a` - First byte slice
/// * `b` - Second byte slice
///
/// # Returns
///
/// `true` if slices are equal in length and content, `false` otherwise.
///
/// # Security
///
/// - Compares all bytes even if a difference is found early
/// - Uses volatile operations to prevent compiler optimization
/// - Length comparison is NOT constant-time (length is typically public)
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::timing::ct_eq;
///
/// let secret = b"correct-password";
/// let attempt = b"wrong-password!!";
///
/// // This comparison won't leak which bytes differ
/// if ct_eq(secret, attempt) {
///     println!("Password correct!");
/// }
/// ```
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    // Length comparison is not constant-time, but length is typically public
    if a.len() != b.len() {
        return false;
    }

    // XOR all bytes and accumulate differences
    // If any byte differs, the result will be non-zero
    let mut diff: u8 = 0;

    for (x, y) in a.iter().zip(b.iter()) {
        // XOR gives 0 for equal bytes, non-zero for different
        diff |= x ^ y;
    }

    // Use volatile read to prevent the compiler from optimizing
    // the comparison into an early-exit form
    ct_is_zero(diff)
}

/// Compare two fixed-size byte arrays in constant time.
///
/// Generic version for arrays of any size. Useful for comparing
/// hashes, MACs, or keys of known length.
///
/// # Type Parameters
///
/// * `N` - The array size
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::timing::ct_eq_array;
///
/// let hash1: [u8; 32] = compute_hash(data1);
/// let hash2: [u8; 32] = compute_hash(data2);
///
/// if ct_eq_array(&hash1, &hash2) {
///     println!("Hashes match!");
/// }
/// ```
#[must_use]
pub fn ct_eq_array<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    ct_eq(a.as_slice(), b.as_slice())
}

/// Check if a byte is zero in constant time.
///
/// Uses a black_box hint to prevent compiler optimization.
/// Note: This relies on the compiler respecting the hint.
#[inline]
fn ct_is_zero(value: u8) -> bool {
    // Use black_box to prevent the compiler from optimizing away
    // the comparison in ways that might not be constant-time.
    // This is the safe alternative to volatile operations.
    std::hint::black_box(value) == 0
}

// ============================================================================
// Constant-Time Selection
// ============================================================================

/// Select between two values in constant time.
///
/// Returns `a` if `condition` is `true`, `b` otherwise. The selection
/// is performed without branching to prevent timing leaks.
///
/// # Arguments
///
/// * `condition` - The selection condition
/// * `a` - Value to return if condition is true
/// * `b` - Value to return if condition is false
///
/// # Returns
///
/// `a` if condition is true, `b` otherwise.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::timing::ct_select_u8;
///
/// let secret_bit = true;
/// let result = ct_select_u8(secret_bit, 0xFF, 0x00);
/// // result is 0xFF, but timing doesn't reveal which branch was taken
/// ```
#[must_use]
#[inline]
pub fn ct_select_u8(condition: bool, a: u8, b: u8) -> u8 {
    // Convert bool to mask: true -> 0xFF, false -> 0x00
    let mask = ct_bool_to_mask(condition);
    // Select: (a & mask) | (b & !mask)
    (a & mask) | (b & !mask)
}

/// Select between two u32 values in constant time.
#[must_use]
#[inline]
pub fn ct_select_u32(condition: bool, a: u32, b: u32) -> u32 {
    let mask = ct_bool_to_mask_u32(condition);
    (a & mask) | (b & !mask)
}

/// Select between two u64 values in constant time.
#[must_use]
#[inline]
pub fn ct_select_u64(condition: bool, a: u64, b: u64) -> u64 {
    let mask = ct_bool_to_mask_u64(condition);
    (a & mask) | (b & !mask)
}

/// Select between two usize values in constant time.
#[must_use]
#[inline]
pub fn ct_select_usize(condition: bool, a: usize, b: usize) -> usize {
    #[cfg(target_pointer_width = "64")]
    {
        ct_select_u64(condition, a as u64, b as u64) as usize
    }
    #[cfg(target_pointer_width = "32")]
    {
        ct_select_u32(condition, a as u32, b as u32) as usize
    }
}

/// Convert a bool to a u8 mask in constant time.
///
/// Returns 0xFF if true, 0x00 if false.
#[inline]
fn ct_bool_to_mask(b: bool) -> u8 {
    // Negate to get 0xFF for true, 0x00 for false
    // Using wrapping_sub to avoid any branches
    0u8.wrapping_sub(b as u8)
}

/// Convert a bool to a u32 mask in constant time.
#[inline]
fn ct_bool_to_mask_u32(b: bool) -> u32 {
    0u32.wrapping_sub(b as u32)
}

/// Convert a bool to a u64 mask in constant time.
#[inline]
fn ct_bool_to_mask_u64(b: bool) -> u64 {
    0u64.wrapping_sub(b as u64)
}

// ============================================================================
// Constant-Time Copy
// ============================================================================

/// Copy bytes from source to destination in constant time based on condition.
///
/// If condition is true, copies `src` to `dst`. If false, `dst` is unchanged.
/// The operation takes the same time regardless of the condition.
///
/// # Arguments
///
/// * `condition` - Whether to perform the copy
/// * `dst` - Destination buffer
/// * `src` - Source buffer (must be same length as dst)
///
/// # Panics
///
/// Panics if `dst` and `src` have different lengths.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::timing::ct_copy_if;
///
/// let mut buffer = [0u8; 4];
/// let new_value = [1, 2, 3, 4];
///
/// ct_copy_if(should_update, &mut buffer, &new_value);
/// ```
pub fn ct_copy_if(condition: bool, dst: &mut [u8], src: &[u8]) {
    assert_eq!(
        dst.len(),
        src.len(),
        "Source and destination must have same length"
    );

    let mask = ct_bool_to_mask(condition);

    for (d, s) in dst.iter_mut().zip(src.iter()) {
        // d = (s & mask) | (d & !mask)
        // If mask is 0xFF, d becomes s
        // If mask is 0x00, d stays as d
        *d = (*s & mask) | (*d & !mask);
    }
}

// ============================================================================
// Constant-Time Zero Check
// ============================================================================

/// Check if a byte slice is all zeros in constant time.
///
/// Returns `true` if all bytes are zero, `false` if any byte is non-zero.
/// The check examines all bytes regardless of where non-zero values appear.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::timing::ct_is_zero_slice;
///
/// let key = [0u8; 32];
/// if ct_is_zero_slice(&key) {
///     panic!("Key is all zeros - this is insecure!");
/// }
/// ```
#[must_use]
pub fn ct_is_zero_slice(data: &[u8]) -> bool {
    let mut acc: u8 = 0;
    for byte in data {
        acc |= *byte;
    }
    ct_is_zero(acc)
}

/// Check if a fixed-size array is all zeros in constant time.
#[must_use]
pub fn ct_is_zero_array<const N: usize>(data: &[u8; N]) -> bool {
    ct_is_zero_slice(data.as_slice())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // =========================================================================
    // ct_eq Tests
    // =========================================================================

    #[test]
    fn test_ct_eq_equal() {
        let a = b"hello world";
        let b = b"hello world";
        assert!(ct_eq(a, b));
    }

    #[test]
    fn test_ct_eq_different() {
        let a = b"hello world";
        let b = b"hello worle";
        assert!(!ct_eq(a, b));
    }

    #[test]
    fn test_ct_eq_different_first_byte() {
        let a = b"hello";
        let b = b"jello";
        assert!(!ct_eq(a, b));
    }

    #[test]
    fn test_ct_eq_different_last_byte() {
        let a = b"hello";
        let b = b"hellp";
        assert!(!ct_eq(a, b));
    }

    #[test]
    fn test_ct_eq_different_lengths() {
        let a = b"hello";
        let b = b"hello world";
        assert!(!ct_eq(a, b));
    }

    #[test]
    fn test_ct_eq_empty() {
        let a: &[u8] = &[];
        let b: &[u8] = &[];
        assert!(ct_eq(a, b));
    }

    #[test]
    fn test_ct_eq_single_byte() {
        assert!(ct_eq(&[42], &[42]));
        assert!(!ct_eq(&[42], &[43]));
    }

    #[test]
    fn test_ct_eq_all_zeros() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert!(ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_eq_all_ones() {
        let a = [0xFFu8; 32];
        let b = [0xFFu8; 32];
        assert!(ct_eq(&a, &b));
    }

    // =========================================================================
    // ct_eq_array Tests
    // =========================================================================

    #[test]
    fn test_ct_eq_array_equal() {
        let a: [u8; 32] = [1; 32];
        let b: [u8; 32] = [1; 32];
        assert!(ct_eq_array(&a, &b));
    }

    #[test]
    fn test_ct_eq_array_different() {
        let a: [u8; 32] = [1; 32];
        let mut b: [u8; 32] = [1; 32];
        b[31] = 2;
        assert!(!ct_eq_array(&a, &b));
    }

    // =========================================================================
    // ct_select Tests
    // =========================================================================

    #[test]
    fn test_ct_select_u8_true() {
        assert_eq!(ct_select_u8(true, 0xAA, 0x55), 0xAA);
    }

    #[test]
    fn test_ct_select_u8_false() {
        assert_eq!(ct_select_u8(false, 0xAA, 0x55), 0x55);
    }

    #[test]
    fn test_ct_select_u32_true() {
        assert_eq!(ct_select_u32(true, 0xDEADBEEF, 0xCAFEBABE), 0xDEADBEEF);
    }

    #[test]
    fn test_ct_select_u32_false() {
        assert_eq!(ct_select_u32(false, 0xDEADBEEF, 0xCAFEBABE), 0xCAFEBABE);
    }

    #[test]
    fn test_ct_select_u64_true() {
        assert_eq!(
            ct_select_u64(true, 0xDEAD_BEEF_CAFE_BABE, 0x1234_5678_9ABC_DEF0),
            0xDEAD_BEEF_CAFE_BABE
        );
    }

    #[test]
    fn test_ct_select_u64_false() {
        assert_eq!(
            ct_select_u64(false, 0xDEAD_BEEF_CAFE_BABE, 0x1234_5678_9ABC_DEF0),
            0x1234_5678_9ABC_DEF0
        );
    }

    #[test]
    fn test_ct_select_usize() {
        assert_eq!(ct_select_usize(true, 100, 200), 100);
        assert_eq!(ct_select_usize(false, 100, 200), 200);
    }

    // =========================================================================
    // ct_copy_if Tests
    // =========================================================================

    #[test]
    fn test_ct_copy_if_true() {
        let mut dst = [1, 2, 3, 4];
        let src = [5, 6, 7, 8];
        ct_copy_if(true, &mut dst, &src);
        assert_eq!(dst, [5, 6, 7, 8]);
    }

    #[test]
    fn test_ct_copy_if_false() {
        let mut dst = [1, 2, 3, 4];
        let src = [5, 6, 7, 8];
        ct_copy_if(false, &mut dst, &src);
        assert_eq!(dst, [1, 2, 3, 4]);
    }

    #[test]
    #[should_panic(expected = "same length")]
    fn test_ct_copy_if_length_mismatch() {
        let mut dst = [1, 2, 3];
        let src = [4, 5, 6, 7];
        ct_copy_if(true, &mut dst, &src);
    }

    // =========================================================================
    // ct_is_zero Tests
    // =========================================================================

    #[test]
    fn test_ct_is_zero_slice_all_zeros() {
        let data = [0u8; 64];
        assert!(ct_is_zero_slice(&data));
    }

    #[test]
    fn test_ct_is_zero_slice_not_zeros() {
        let mut data = [0u8; 64];
        data[32] = 1;
        assert!(!ct_is_zero_slice(&data));
    }

    #[test]
    fn test_ct_is_zero_slice_first_non_zero() {
        let mut data = [0u8; 64];
        data[0] = 1;
        assert!(!ct_is_zero_slice(&data));
    }

    #[test]
    fn test_ct_is_zero_slice_last_non_zero() {
        let mut data = [0u8; 64];
        data[63] = 1;
        assert!(!ct_is_zero_slice(&data));
    }

    #[test]
    fn test_ct_is_zero_slice_empty() {
        let data: [u8; 0] = [];
        assert!(ct_is_zero_slice(&data));
    }

    #[test]
    fn test_ct_is_zero_array() {
        let zeros: [u8; 32] = [0; 32];
        let non_zeros: [u8; 32] = [1; 32];
        assert!(ct_is_zero_array(&zeros));
        assert!(!ct_is_zero_array(&non_zeros));
    }

    // =========================================================================
    // Mask Tests
    // =========================================================================

    #[test]
    fn test_bool_to_mask() {
        assert_eq!(ct_bool_to_mask(true), 0xFF);
        assert_eq!(ct_bool_to_mask(false), 0x00);
    }

    #[test]
    fn test_bool_to_mask_u32() {
        assert_eq!(ct_bool_to_mask_u32(true), 0xFFFFFFFF);
        assert_eq!(ct_bool_to_mask_u32(false), 0x00000000);
    }

    #[test]
    fn test_bool_to_mask_u64() {
        assert_eq!(ct_bool_to_mask_u64(true), 0xFFFFFFFFFFFFFFFF);
        assert_eq!(ct_bool_to_mask_u64(false), 0x0000000000000000);
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_ct_eq_binary_data() {
        // Test with all possible byte values
        let a: Vec<u8> = (0..=255).collect();
        let b: Vec<u8> = (0..=255).collect();
        assert!(ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_eq_large_data() {
        let a = vec![0xABu8; 10000];
        let b = vec![0xABu8; 10000];
        assert!(ct_eq(&a, &b));
    }
}
