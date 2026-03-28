use super::super::types::IdentifierMatch;
use super::types::CorrelationConfig;

/// Calculate the number of newlines between two byte positions in text.
///
/// Positions are order-independent — swaps internally if `pos_a > pos_b`.
/// Returns 0 if both positions are on the same line or if the text slice
/// between them contains no newlines.
#[must_use]
pub(crate) fn line_distance(text: &str, pos_a: usize, pos_b: usize) -> usize {
    let (start, end) = if pos_a <= pos_b {
        (pos_a, pos_b)
    } else {
        (pos_b, pos_a)
    };

    // Clamp to text length to avoid panics
    let clamped_start = start.min(text.len());
    let clamped_end = end.min(text.len());

    text.as_bytes()
        .get(clamped_start..clamped_end)
        .map_or(0, |slice| slice.iter().filter(|&&b| b == b'\n').count())
}

/// Calculate the character gap between two identifier matches.
///
/// Returns the number of characters between the end of the earlier match
/// and the start of the later match. Returns 0 for overlapping or adjacent
/// matches. Order-independent — determines which match comes first by position.
#[must_use]
pub(crate) fn char_distance(match_a: &IdentifierMatch, match_b: &IdentifierMatch) -> usize {
    let (earlier_end, later_start) = if match_a.start <= match_b.start {
        (match_a.end, match_b.start)
    } else {
        (match_b.end, match_a.start)
    };

    later_start.saturating_sub(earlier_end)
}

/// Check if two identifier matches are within the configured proximity window.
///
/// Both the line distance AND character distance must be within thresholds
/// for the matches to be considered proximate.
#[must_use]
pub(crate) fn is_within_proximity(
    text: &str,
    match_a: &IdentifierMatch,
    match_b: &IdentifierMatch,
    config: &CorrelationConfig,
) -> bool {
    let c_dist = char_distance(match_a, match_b);
    if c_dist > config.max_proximity_chars {
        return false;
    }

    let l_dist = line_distance(text, match_a.end, match_b.start);
    l_dist <= config.max_proximity_lines
}

/// A pair of identifier matches found within proximity.
#[derive(Debug, Clone)]
pub(crate) struct ProximatePair {
    /// Index of the first match in the input slice
    pub index_a: usize,
    /// Index of the second match in the input slice
    pub index_b: usize,
    /// Character distance between the two matches
    pub char_distance: usize,
}

/// Find all pairs of identifier matches that are within the configured proximity window.
///
/// Iterates all unique pairs `(i, j)` where `i < j`, checks proximity, and
/// returns qualifying pairs sorted by character distance (closest first).
///
/// Returns an empty vec if fewer than 2 matches are provided.
#[must_use]
pub(crate) fn find_proximate_pairs(
    text: &str,
    matches: &[IdentifierMatch],
    config: &CorrelationConfig,
) -> Vec<ProximatePair> {
    if matches.len() < 2 {
        return Vec::new();
    }

    let mut pairs = Vec::new();

    for i in 0..matches.len() {
        for j in (i.saturating_add(1))..matches.len() {
            // Safety: i and j are within bounds by loop construction
            let (Some(match_a), Some(match_b)) = (matches.get(i), matches.get(j)) else {
                continue;
            };

            if is_within_proximity(text, match_a, match_b, config) {
                pairs.push(ProximatePair {
                    index_a: i,
                    index_b: j,
                    char_distance: char_distance(match_a, match_b),
                });
            }
        }
    }

    // Sort by char_distance ascending (closest pairs first)
    pairs.sort_by_key(|p| p.char_distance);
    pairs
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]

    use super::*;
    use crate::primitives::identifiers::types::{DetectionConfidence, IdentifierType};

    fn make_match(start: usize, end: usize, text: &str) -> IdentifierMatch {
        IdentifierMatch::new(
            start,
            end,
            text.to_string(),
            IdentifierType::ApiKey,
            DetectionConfidence::Medium,
        )
    }

    // --- line_distance tests ---

    #[test]
    fn test_line_distance_same_line() {
        let text = "AKIA1234 secret_key_here";
        assert_eq!(line_distance(text, 0, 9), 0);
    }

    #[test]
    fn test_line_distance_one_line_apart() {
        let text = "AKIA1234\nsecret_key_here";
        assert_eq!(line_distance(text, 0, 9), 1);
    }

    #[test]
    fn test_line_distance_five_lines_apart() {
        let text = "key1\n\n\n\n\nkey2";
        assert_eq!(line_distance(text, 0, 9), 5);
    }

    #[test]
    fn test_line_distance_reversed_positions() {
        let text = "line1\nline2\nline3";
        assert_eq!(line_distance(text, 12, 0), 2);
    }

    #[test]
    fn test_line_distance_clamped_to_text_length() {
        let text = "short";
        assert_eq!(line_distance(text, 0, 1000), 0);
    }

    // --- char_distance tests ---

    #[test]
    fn test_char_distance_adjacent() {
        let a = make_match(0, 8, "AKIA1234");
        let b = make_match(8, 20, "secret_value");
        assert_eq!(char_distance(&a, &b), 0);
    }

    #[test]
    fn test_char_distance_with_gap() {
        let a = make_match(0, 8, "AKIA1234");
        let b = make_match(18, 30, "secret_value");
        assert_eq!(char_distance(&a, &b), 10);
    }

    #[test]
    fn test_char_distance_overlapping() {
        let a = make_match(0, 15, "overlapping_a");
        let b = make_match(10, 25, "overlapping_b");
        assert_eq!(char_distance(&a, &b), 0);
    }

    #[test]
    fn test_char_distance_reversed_order() {
        let a = make_match(18, 30, "secret_value");
        let b = make_match(0, 8, "AKIA1234");
        assert_eq!(char_distance(&a, &b), 10);
    }

    // --- is_within_proximity tests ---

    #[test]
    fn test_within_proximity_same_line() {
        let text = "AKIA1234 secret_key_here";
        let a = make_match(0, 8, "AKIA1234");
        let b = make_match(9, 24, "secret_key_here");
        let config = CorrelationConfig::default();
        assert!(is_within_proximity(text, &a, &b, &config));
    }

    #[test]
    fn test_within_proximity_at_line_threshold() {
        // 5 newlines = exactly at default threshold
        let text = "key1\n\n\n\n\nkey2";
        let a = make_match(0, 4, "key1");
        let b = make_match(9, 13, "key2");
        let config = CorrelationConfig::default();
        assert!(is_within_proximity(text, &a, &b, &config));
    }

    #[test]
    fn test_outside_proximity_too_many_lines() {
        // 6 newlines = beyond default threshold of 5
        let text = "key1\n\n\n\n\n\nkey2";
        let a = make_match(0, 4, "key1");
        let b = make_match(10, 14, "key2");
        let config = CorrelationConfig::default();
        assert!(!is_within_proximity(text, &a, &b, &config));
    }

    #[test]
    fn test_outside_proximity_too_many_chars() {
        // Create text with chars > 500 apart but on same line
        let padding = "x".repeat(501);
        let text = format!("key1{padding}key2");
        let a = make_match(0, 4, "key1");
        let b = make_match(505, 509, "key2");
        let config = CorrelationConfig::default();
        assert!(!is_within_proximity(&text, &a, &b, &config));
    }

    #[test]
    fn test_within_proximity_custom_config() {
        let text = "key1\n\n\n\n\n\n\n\n\n\nkey2"; // 10 newlines
        let a = make_match(0, 4, "key1");
        let b = make_match(14, 18, "key2");
        let config = CorrelationConfig {
            max_proximity_lines: 10,
            max_proximity_chars: 1000,
            ..CorrelationConfig::default()
        };
        assert!(is_within_proximity(text, &a, &b, &config));
    }

    // --- find_proximate_pairs tests ---

    #[test]
    fn test_find_pairs_empty_matches() {
        let pairs = find_proximate_pairs("text", &[], &CorrelationConfig::default());
        assert!(pairs.is_empty());
    }

    #[test]
    fn test_find_pairs_single_match() {
        let matches = vec![make_match(0, 4, "key1")];
        let pairs = find_proximate_pairs("key1", &matches, &CorrelationConfig::default());
        assert!(pairs.is_empty());
    }

    #[test]
    fn test_find_pairs_two_proximate() {
        let text = "AKIA1234 secret_here";
        let matches = vec![
            make_match(0, 8, "AKIA1234"),
            make_match(9, 20, "secret_here"),
        ];
        let pairs = find_proximate_pairs(text, &matches, &CorrelationConfig::default());
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs.first().expect("has pair").index_a, 0);
        assert_eq!(pairs.first().expect("has pair").index_b, 1);
        assert_eq!(pairs.first().expect("has pair").char_distance, 1);
    }

    #[test]
    fn test_find_pairs_two_distant() {
        let padding = "x".repeat(501);
        let text = format!("key1{padding}key2");
        let matches = vec![make_match(0, 4, "key1"), make_match(505, 509, "key2")];
        let pairs = find_proximate_pairs(&text, &matches, &CorrelationConfig::default());
        assert!(pairs.is_empty());
    }

    #[test]
    fn test_find_pairs_sorted_by_distance() {
        let text = "a  b      c";
        let matches = vec![
            make_match(0, 1, "a"),
            make_match(3, 4, "b"),
            make_match(10, 11, "c"),
        ];
        let pairs = find_proximate_pairs(text, &matches, &CorrelationConfig::default());
        assert_eq!(pairs.len(), 3); // (a,b), (a,c), (b,c) all within 500 chars
        // Should be sorted by char_distance: (a,b)=2, (b,c)=6, (a,c)=9
        assert_eq!(pairs.first().expect("has pair").char_distance, 2);
    }

    #[test]
    fn test_find_pairs_multiple_some_proximate() {
        // Three matches: first two close, third far away
        let padding = "x".repeat(501);
        let text = format!("key1 key2{padding}key3");
        let matches = vec![
            make_match(0, 4, "key1"),
            make_match(5, 9, "key2"),
            make_match(510, 514, "key3"),
        ];
        let pairs = find_proximate_pairs(&text, &matches, &CorrelationConfig::default());
        assert_eq!(pairs.len(), 1); // Only (key1, key2)
        assert_eq!(pairs.first().expect("has pair").index_a, 0);
        assert_eq!(pairs.first().expect("has pair").index_b, 1);
    }
}
