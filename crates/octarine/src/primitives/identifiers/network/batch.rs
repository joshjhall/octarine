//! Batch processing operations for network identifiers
//!
//! Helper functions for processing multiple identifiers at once.
//! These are convenience functions with business logic, separated from
//! the pure builder pattern.

use super::super::types::IdentifierType;
use super::detection;
use std::collections::HashMap;

/// Validate a batch of values against an expected type
///
/// Returns a vector of (value, is_valid) tuples indicating whether
/// each value matches the expected identifier type.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::batch;
/// use octarine::primitives::identifiers::types::IdentifierType;
///
/// let values = vec![
///     "550e8400-e29b-41d4-a716-446655440000",
///     "not-a-uuid",
///     "123e4567-e89b-12d3-a456-426614174000",
/// ];
///
/// let results = batch::validate_batch_as(&values, IdentifierType::Uuid);
/// assert_eq!(results[0].1, true);  // First is UUID
/// assert_eq!(results[1].1, false); // Second is not
/// assert_eq!(results[2].1, true);  // Third is UUID
/// ```
#[must_use]
pub fn validate_batch_as<'a>(
    values: &'a [&str],
    expected_type: IdentifierType,
) -> Vec<(&'a str, bool)> {
    values
        .iter()
        .map(|&value| {
            let detected = detection::detect_network_identifier(value);
            (value, detected == Some(expected_type.clone()))
        })
        .collect()
}

/// Filter batch to only valid identifiers
///
/// Returns only the values that were successfully detected as valid identifiers.
/// Useful for cleaning datasets or extracting identifiers from mixed input.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::batch;
///
/// let mixed = vec![
///     "550e8400-e29b-41d4-a716-446655440000", // UUID
///     "invalid",
///     "192.168.1.1", // IP
///     "junk",
/// ];
///
/// let valid = batch::filter_valid_identifiers(&mixed);
/// assert_eq!(valid.len(), 2); // Only UUID and IP
/// ```
#[must_use]
pub fn filter_valid_identifiers<'a>(values: &'a [&str]) -> Vec<&'a str> {
    values
        .iter()
        .filter(|&&value| detection::detect_network_identifier(value).is_some())
        .copied()
        .collect()
}

/// Count identifiers by type in batch
///
/// Returns a count of how many of each identifier type were found.
/// Useful for analyzing datasets or reporting statistics.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::batch;
/// use octarine::primitives::identifiers::types::IdentifierType;
///
/// let values = vec![
///     "550e8400-e29b-41d4-a716-446655440000", // UUID
///     "192.168.1.1", // IP
///     "192.168.1.2", // IP
///     "not-valid",
/// ];
///
/// let counts = batch::count_by_type(&values);
/// assert_eq!(counts.get(&IdentifierType::Uuid), Some(&1));
/// assert_eq!(counts.get(&IdentifierType::IpAddress), Some(&2));
/// ```
#[must_use]
pub fn count_by_type(values: &[&str]) -> HashMap<IdentifierType, usize> {
    let mut counts = HashMap::new();
    for &value in values {
        if let Some(id_type) = detection::detect_network_identifier(value) {
            #[allow(clippy::arithmetic_side_effects)] // Safe: counting occurrences
            {
                *counts.entry(id_type).or_insert(0) += 1;
            }
        }
    }
    counts
}

/// Partition batch into valid and invalid identifiers
///
/// Returns two vectors: (valid_identifiers, invalid_values).
/// Useful for error handling or data cleanup.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::batch;
///
/// let mixed = vec!["192.168.1.1", "invalid", "10.0.0.1", "junk"];
///
/// let (valid, invalid) = batch::partition_identifiers(&mixed);
/// assert_eq!(valid.len(), 2);
/// assert_eq!(invalid.len(), 2);
/// ```
#[must_use]
pub fn partition_identifiers<'a>(values: &'a [&str]) -> (Vec<&'a str>, Vec<&'a str>) {
    let mut valid = Vec::new();
    let mut invalid = Vec::new();

    for &value in values {
        if detection::detect_network_identifier(value).is_some() {
            valid.push(value);
        } else {
            invalid.push(value);
        }
    }

    (valid, invalid)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_validate_batch_as() {
        let values = vec![
            "550e8400-e29b-41d4-a716-446655440000",
            "not-a-uuid",
            "123e4567-e89b-12d3-a456-426614174000",
        ];

        let results = validate_batch_as(&values, IdentifierType::Uuid);
        assert_eq!(results.len(), 3);
        assert!(results[0].1); // First is UUID
        assert!(!results[1].1); // Second is not
        assert!(results[2].1); // Third is UUID
    }

    #[test]
    fn test_filter_valid_identifiers() {
        let mixed = vec![
            "550e8400-e29b-41d4-a716-446655440000", // UUID
            "",                                     // Empty - not valid
            "192.168.1.1",                          // IP
            " ",                                    // Whitespace - not valid
        ];

        let valid = filter_valid_identifiers(&mixed);
        assert_eq!(valid.len(), 2);
        assert!(valid.contains(&"550e8400-e29b-41d4-a716-446655440000"));
        assert!(valid.contains(&"192.168.1.1"));
    }

    #[test]
    fn test_count_by_type() {
        let values = vec![
            "550e8400-e29b-41d4-a716-446655440000", // UUID
            "192.168.1.1",                          // IP
            "192.168.1.2",                          // IP
            "not-valid",
        ];

        let counts = count_by_type(&values);
        assert_eq!(counts.get(&IdentifierType::Uuid), Some(&1));
        assert_eq!(counts.get(&IdentifierType::IpAddress), Some(&2));
    }

    #[test]
    fn test_partition_identifiers() {
        let mixed = vec!["192.168.1.1", "", "10.0.0.1", " "];

        let (valid, invalid) = partition_identifiers(&mixed);
        assert_eq!(valid.len(), 2);
        assert_eq!(invalid.len(), 2);
        assert!(valid.contains(&"192.168.1.1"));
        assert!(valid.contains(&"10.0.0.1"));
        assert!(invalid.contains(&""));
        assert!(invalid.contains(&" "));
    }

    #[test]
    fn test_empty_batch() {
        let empty: Vec<&str> = vec![];

        let results = validate_batch_as(&empty, IdentifierType::Uuid);
        assert_eq!(results.len(), 0);

        let valid = filter_valid_identifiers(&empty);
        assert_eq!(valid.len(), 0);

        let counts = count_by_type(&empty);
        assert_eq!(counts.len(), 0);

        let (valid, invalid) = partition_identifiers(&empty);
        assert_eq!(valid.len(), 0);
        assert_eq!(invalid.len(), 0);
    }

    #[test]
    fn test_all_invalid() {
        let all_invalid = vec!["", " ", "  "];

        let valid = filter_valid_identifiers(&all_invalid);
        assert_eq!(valid.len(), 0);

        let counts = count_by_type(&all_invalid);
        assert_eq!(counts.len(), 0);

        let (valid, invalid) = partition_identifiers(&all_invalid);
        assert_eq!(valid.len(), 0);
        assert_eq!(invalid.len(), 3);
    }

    #[test]
    fn test_all_valid() {
        let all_valid = vec![
            "550e8400-e29b-41d4-a716-446655440000",
            "192.168.1.1",
            "00:1B:44:11:3A:B7",
        ];

        let valid = filter_valid_identifiers(&all_valid);
        assert_eq!(valid.len(), 3);

        let counts = count_by_type(&all_valid);
        assert_eq!(counts.len(), 3); // 3 different types

        let (valid, invalid) = partition_identifiers(&all_valid);
        assert_eq!(valid.len(), 3);
        assert_eq!(invalid.len(), 0);
    }
}
