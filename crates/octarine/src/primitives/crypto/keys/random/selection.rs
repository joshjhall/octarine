//! Secure shuffle and random selection.

use super::CryptoError;
use super::types::random_usize_bounded;

// ============================================================================
// Shuffle and Selection
// ============================================================================

/// Securely shuffle a slice in-place using Fisher-Yates algorithm.
///
/// Uses cryptographically secure random numbers for shuffling.
///
/// # Arguments
///
/// * `slice` - The slice to shuffle
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::shuffle;
///
/// let mut deck: Vec<u8> = (0..52).collect();
/// shuffle(&mut deck)?;
/// ```
pub fn shuffle<T>(slice: &mut [T]) -> Result<(), CryptoError> {
    let len = slice.len();
    if len <= 1 {
        return Ok(());
    }

    // Fisher-Yates shuffle
    for i in (1..len).rev() {
        let j = random_usize_bounded(i.saturating_add(1))?;
        slice.swap(i, j);
    }

    Ok(())
}

/// Securely select a random element from a slice.
///
/// # Arguments
///
/// * `slice` - The slice to select from
///
/// # Returns
///
/// A reference to a randomly selected element.
///
/// # Errors
///
/// Returns an error if the slice is empty.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::random_choice;
///
/// let colors = ["red", "green", "blue"];
/// let color = random_choice(&colors)?;
/// ```
pub fn random_choice<T>(slice: &[T]) -> Result<&T, CryptoError> {
    if slice.is_empty() {
        return Err(CryptoError::random_generation(
            "Cannot select from empty slice",
        ));
    }

    let idx = random_usize_bounded(slice.len())?;
    slice
        .get(idx)
        .ok_or_else(|| CryptoError::random_generation("Index out of bounds (unreachable)"))
}

/// Securely sample N elements from a slice without replacement.
///
/// Returns a new Vec containing N randomly selected elements.
///
/// # Arguments
///
/// * `slice` - The slice to sample from
/// * `n` - The number of elements to sample
///
/// # Errors
///
/// Returns an error if n > slice.len() or if the OS CSPRNG fails.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::random_sample;
///
/// let numbers: Vec<i32> = (1..=100).collect();
/// let winners = random_sample(&numbers, 3)?;
/// ```
pub fn random_sample<T: Clone>(slice: &[T], n: usize) -> Result<Vec<T>, CryptoError> {
    if n > slice.len() {
        return Err(CryptoError::random_generation(
            "Sample size cannot exceed slice length",
        ));
    }

    if n == 0 {
        return Ok(Vec::new());
    }

    // Create indices and shuffle
    let mut indices: Vec<usize> = (0..slice.len()).collect();
    shuffle(&mut indices)?;

    // Take first N
    Ok(indices
        .into_iter()
        .take(n)
        .filter_map(|i| slice.get(i).cloned())
        .collect())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_shuffle() {
        let mut numbers: Vec<i32> = (0..100).collect();
        let original = numbers.clone();

        shuffle(&mut numbers).expect("Shuffle");

        // Should be permuted (with overwhelming probability)
        assert_ne!(numbers, original);

        // Should contain same elements
        numbers.sort();
        assert_eq!(numbers, original);
    }

    #[test]
    fn test_shuffle_empty() {
        let mut empty: Vec<i32> = vec![];
        shuffle(&mut empty).expect("Shuffle empty");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_shuffle_single() {
        let mut single = vec![42];
        shuffle(&mut single).expect("Shuffle single");
        assert_eq!(single, vec![42]);
    }

    #[test]
    fn test_random_choice() {
        let items = [1, 2, 3, 4, 5];
        let choice = random_choice(&items).expect("Choice");
        assert!(items.contains(choice));
    }

    #[test]
    fn test_random_choice_empty() {
        let items: Vec<i32> = vec![];
        let result = random_choice(&items);
        assert!(result.is_err());
    }

    #[test]
    fn test_random_sample() {
        let items: Vec<i32> = (1..=10).collect();
        let sample = random_sample(&items, 5).expect("Sample");

        assert_eq!(sample.len(), 5);

        // All elements should be unique
        let unique: HashSet<_> = sample.iter().collect();
        assert_eq!(unique.len(), 5);

        // All elements should be from the original
        for item in &sample {
            assert!(items.contains(item));
        }
    }

    #[test]
    fn test_random_sample_too_large() {
        let items = vec![1, 2, 3];
        let result = random_sample(&items, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_random_sample_zero() {
        let items = vec![1, 2, 3];
        let sample = random_sample(&items, 0).expect("Sample zero");
        assert!(sample.is_empty());
    }
}
