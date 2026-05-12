//! Shared helpers for government identifier detection
//!
//! Pure helper functions used by per-country detection submodules.
//!
//! - `MAX_INPUT_LENGTH` / `MAX_IDENTIFIER_LENGTH` — ReDoS-protection limits
//! - `get_full_match` — encapsulates the regex capture-group-0 unwrap
//! - `deduplicate_matches` — keep longest/highest-confidence overlapping match
//! - `exceeds_safe_length` — input-length gate for regex scanning

use super::super::super::types::IdentifierMatch;

/// Maximum input length for ReDoS protection
///
/// Inputs longer than this are rejected to prevent regex denial of service.
pub(super) const MAX_INPUT_LENGTH: usize = 10_000;

/// Maximum single identifier length
///
/// Individual identifiers (SSN, Driver License, etc.) shouldn't exceed this.
pub(super) const MAX_IDENTIFIER_LENGTH: usize = 100;

/// Extract the full match from a regex capture.
///
/// # Safety
/// Capture group 0 always exists per regex spec - it's the full match.
/// This function encapsulates the expect() call with proper justification.
#[allow(clippy::expect_used)]
pub(super) fn get_full_match<'a>(capture: &'a regex::Captures<'a>) -> regex::Match<'a> {
    capture
        .get(0)
        .expect("BUG: capture group 0 always exists per regex spec")
}

/// Deduplicate overlapping matches (keep longest/highest confidence)
///
/// When multiple patterns match the same text position, keep only the best match:
/// - Prefer longer matches (more specific)
/// - Prefer higher confidence
/// - Prefer earlier position as tiebreaker
pub(super) fn deduplicate_matches(mut matches: Vec<IdentifierMatch>) -> Vec<IdentifierMatch> {
    if matches.is_empty() {
        return matches;
    }

    // Sort by start position, then by length (descending), then by confidence
    matches.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| b.len().cmp(&a.len())) // Longer first
            .then_with(|| b.confidence.cmp(&a.confidence)) // Higher confidence first
    });

    let mut deduped = Vec::new();
    let mut last_end = 0;

    for m in matches {
        // If this match doesn't overlap with the previous one, keep it
        if m.start >= last_end {
            last_end = m.end;
            deduped.push(m);
        }
        // Otherwise, it overlaps and we skip it (we already kept the better match)
    }

    deduped
}

/// Check if input exceeds safe length for regex processing
///
/// Used for ReDoS protection in text scanning functions.
#[inline]
pub(super) fn exceeds_safe_length(input: &str, max_len: usize) -> bool {
    input.len() > max_len
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::super::super::super::types::IdentifierType;
    use super::*;

    #[test]
    fn test_deduplicate_matches() {
        let matches = vec![
            IdentifierMatch::high_confidence(0, 10, "test1".into(), IdentifierType::Ssn),
            IdentifierMatch::high_confidence(0, 15, "test1long".into(), IdentifierType::Ssn),
            IdentifierMatch::high_confidence(20, 30, "test2".into(), IdentifierType::Ssn),
        ];

        let deduped = deduplicate_matches(matches);
        assert_eq!(deduped.len(), 2);
        let first = deduped.first().expect("Should have first match");
        let second = deduped.get(1).expect("Should have second match");
        assert_eq!(first.matched_text, "test1long");
        assert_eq!(second.matched_text, "test2");
    }
}
