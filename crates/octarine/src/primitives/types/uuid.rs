//! UUID predicates - shared primitives for UUID structure checks
//!
//! Pure checks for the RFC 4122 UUID string layout. Like [`super::dates`], these
//! are dependency-free helper functions that live in `primitives/types/` because
//! more than one Layer 1 sub-module needs them.
//!
//! # Why here
//!
//! `primitives::data::network` normalizes URL path segments and must recognize a
//! segment that *is* a UUID. `primitives::identifiers::network` owns UUID
//! detection. Having `data` call into `identifiers` closes a Layer 1 cycle (see
//! issue #753) and blocks either sub-module from being extracted to its own
//! crate, so the predicates are defined once here and depended on by both
//! directions of the flow.
//!
//! # Two predicates
//!
//! [`is_uuid_shape`] is **anchored** — the whole input must be a UUID.
//! [`is_uuid_present`] finds one **delimited by word boundaries** inside a longer
//! value, matching what `identifiers::network::detection::is_uuid` does with its
//! `\b…\b` regexes. The two are kept side by side so a caller states which
//! question it is asking, and so the behavior of existing callers is preserved
//! exactly when they move off the detection module.
//!
//! # Structure
//!
//! `xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx` (8-4-4-4-12 hex), where `M` is the
//! version nibble (1-5) and `N` is the variant nibble (8, 9, a, or b). The nil
//! UUID (`00000000-...`) fails both, matching the version/variant rules the
//! identifier patterns already encode.

#![allow(clippy::expect_used)]
// SAFETY: the one regex in this module is a hardcoded, compile-time-known-valid
// pattern, exercised by the unit tests below.

use once_cell::sync::Lazy;
use regex::Regex;

/// A single Unicode word character, as the regex crate's `\b` defines one.
///
/// [`is_uuid_present`] must agree with `identifiers::network::detection::is_uuid`
/// about where a word boundary falls, and that function's `\b` uses the regex
/// crate's Unicode `\w` — alphabetic, marks, decimal numbers, connector
/// punctuation, and join controls. `char::is_alphanumeric()` covers only part of
/// that (a combining accent or a ZWJ would wrongly read as a boundary), so the
/// classification is delegated to the same engine rather than approximated.
static WORD_CHAR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\w$").expect("BUG: Invalid regex pattern"));

/// Expected total length of a hyphenated UUID string.
const UUID_LEN: usize = 36;

/// Byte offsets that must hold a `-` separator.
const SEPARATOR_POSITIONS: [usize; 4] = [8, 13, 18, 23];

/// Byte offset of the version nibble (must be `1`-`5`).
const VERSION_POSITION: usize = 14;

/// Byte offset of the variant nibble (must be `8`, `9`, `a`, or `b`).
const VARIANT_POSITION: usize = 19;

/// Longest input [`is_uuid_present`] will scan.
///
/// Mirrors `MAX_IDENTIFIER_LENGTH` in
/// `identifiers::network::detection::common`, which `is_uuid` applies before
/// running its regexes. Keeping the bound here means the two predicates agree on
/// oversized input as well as on content, and caps the scan's work.
const MAX_SCAN_LENGTH: usize = 1_000;

/// Check whether the entire value has UUID shape (versions 1-5).
///
/// Returns `true` only when the whole string is a hyphenated 8-4-4-4-12 hex
/// UUID with a valid version and variant nibble. Any leading or trailing
/// character (whitespace included) makes this `false`; trim before calling if
/// that is not what you want.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::types::is_uuid_shape;
///
/// assert!(is_uuid_shape("550e8400-e29b-41d4-a716-446655440000"));
/// assert!(!is_uuid_shape("id-550e8400-e29b-41d4-a716-446655440000"));
/// assert!(!is_uuid_shape("00000000-0000-0000-0000-000000000000")); // nil
/// ```
#[must_use]
pub(crate) fn is_uuid_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != UUID_LEN {
        return false;
    }

    for (index, byte) in bytes.iter().enumerate() {
        let expected_separator = SEPARATOR_POSITIONS.contains(&index);
        if expected_separator {
            if *byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }

    let version_ok = matches!(bytes.get(VERSION_POSITION), Some(b'1'..=b'5'));
    let variant_ok = matches!(
        bytes.get(VARIANT_POSITION),
        Some(b'8' | b'9' | b'a' | b'b' | b'A' | b'B')
    );

    version_ok && variant_ok
}

/// Check whether a UUID appears anywhere in the value, at a word boundary.
///
/// This is the substring counterpart to [`is_uuid_shape`], and mirrors the
/// `\b…\b` regex matching of `identifiers::network::detection::is_uuid`: the
/// candidate must be bounded on each side by a non-word character or the end of
/// the input, so `report-{uuid}.pdf` matches (the `-` and `.` are boundaries)
/// while a UUID glued to extra hex digits does not. "Word character" follows the
/// regex crate's Unicode-aware `\b` — any alphanumeric plus `_`, not only ASCII
/// — so a UUID glued to a non-ASCII letter is likewise not a match.
///
/// Callers normalizing a value for a low-cardinality label want this; callers
/// asking "is this entire value a UUID?" want [`is_uuid_shape`].
///
/// Input is trimmed, and anything longer than [`MAX_SCAN_LENGTH`] returns
/// `false` without scanning — both matching `is_uuid`'s own preconditions.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::types::is_uuid_present;
///
/// assert!(is_uuid_present("report-550e8400-e29b-41d4-a716-446655440000.pdf"));
/// assert!(!is_uuid_present("no identifier here"));
/// ```
#[must_use]
pub(crate) fn is_uuid_present(value: &str) -> bool {
    // Trim then length-cap, exactly as `is_uuid` does before running its regexes,
    // so the two agree on padded and on oversized input.
    let value = value.trim();
    let bytes = value.as_bytes();
    if bytes.len() < UUID_LEN || bytes.len() > MAX_SCAN_LENGTH {
        return false;
    }

    // `\b` in the reference regexes is Unicode-aware, and its `\w` class is
    // wider than "alphanumeric plus `_`": it also covers marks (a combining
    // accent), connector punctuation, and join controls. Rather than approximate
    // that classification and drift from it, test it with the same regex engine
    // that defines it (see WORD_CHAR).
    let is_word = |character: char| {
        let mut buffer = [0u8; 4];
        WORD_CHAR.is_match(character.encode_utf8(&mut buffer))
    };

    // saturating_sub: `arithmetic_side_effects` is denied, and the length check
    // above already guarantees this cannot underflow.
    let last_start = bytes.len().saturating_sub(UUID_LEN);
    for start in 0..=last_start {
        let end = start.saturating_add(UUID_LEN);

        // `get` returns None when an index splits a multibyte character; such a
        // window cannot hold an all-ASCII UUID anyway.
        let Some(candidate) = value.get(start..end) else {
            continue;
        };
        if !is_uuid_shape(candidate) {
            continue;
        }

        // Both edges must be boundaries. The ends of the input count as
        // boundaries, so a missing neighbour is a pass.
        let preceded_by_word = value
            .get(..start)
            .and_then(|before| before.chars().next_back())
            .is_some_and(is_word);
        let followed_by_word = value
            .get(end..)
            .and_then(|after| after.chars().next())
            .is_some_and(is_word);
        if !preceded_by_word && !followed_by_word {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]

    use super::*;

    #[test]
    fn test_accepts_all_versions() {
        assert!(is_uuid_shape("550e8400-e29b-11d4-a716-446655440000")); // v1
        assert!(is_uuid_shape("550e8400-e29b-21d4-a716-446655440000")); // v2
        assert!(is_uuid_shape("550e8400-e29b-31d4-a716-446655440000")); // v3
        assert!(is_uuid_shape("550e8400-e29b-41d4-a716-446655440000")); // v4
        assert!(is_uuid_shape("550e8400-e29b-51d4-a716-446655440000")); // v5
    }

    #[test]
    fn test_accepts_all_variant_nibbles() {
        for variant in ['8', '9', 'a', 'b', 'A', 'B'] {
            let value = format!("550e8400-e29b-41d4-{variant}716-446655440000");
            assert!(
                is_uuid_shape(&value),
                "variant {variant} should be accepted"
            );
        }
    }

    #[test]
    fn test_uppercase_accepted() {
        assert!(is_uuid_shape("550E8400-E29B-41D4-A716-446655440000"));
    }

    #[test]
    fn test_rejects_out_of_range_version() {
        // Version 0 and 6 bracket the accepted 1-5 range.
        assert!(!is_uuid_shape("550e8400-e29b-01d4-a716-446655440000"));
        assert!(!is_uuid_shape("550e8400-e29b-61d4-a716-446655440000"));
    }

    #[test]
    fn test_rejects_out_of_range_variant() {
        // '7' is just below the accepted 8-b range, 'c' just above.
        assert!(!is_uuid_shape("550e8400-e29b-41d4-7716-446655440000"));
        assert!(!is_uuid_shape("550e8400-e29b-41d4-c716-446655440000"));
    }

    #[test]
    fn test_rejects_nil_uuid() {
        // The nil UUID has version 0 and variant 0 - not a UUID by the
        // version/variant rules the identifier patterns encode.
        assert!(!is_uuid_shape("00000000-0000-0000-0000-000000000000"));
    }

    #[test]
    fn test_rejects_wrong_length() {
        assert!(!is_uuid_shape("550e8400-e29b-41d4-a716-44665544000")); // one short
        assert!(!is_uuid_shape("550e8400-e29b-41d4-a716-4466554400000")); // one long
        assert!(!is_uuid_shape(""));
    }

    #[test]
    fn test_rejects_misplaced_separators() {
        // Correct length, hyphens shifted one position right.
        assert!(!is_uuid_shape("550e84000-e29b-41d4-a716-44665544000"));
        // Correct length, separator replaced by a hex digit and vice versa.
        assert!(!is_uuid_shape("550e8400ae29b-41d4-a716-4466554400-0"));
    }

    #[test]
    fn test_rejects_non_hex() {
        assert!(!is_uuid_shape("550e8400-e29b-41d4-a716-44665544000z"));
        assert!(!is_uuid_shape("not-a-uuid"));
    }

    #[test]
    fn test_rejects_surrounding_characters() {
        // Anchored: a valid UUID embedded in a longer value is not a match.
        assert!(!is_uuid_shape("id.550e8400-e29b-41d4-a716-446655440000"));
        assert!(!is_uuid_shape("550e8400-e29b-41d4-a716-446655440000.json"));
        assert!(!is_uuid_shape(" 550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn test_present_finds_embedded_uuid_at_boundaries() {
        assert!(is_uuid_present(
            "report-550e8400-e29b-41d4-a716-446655440000.pdf"
        ));
        assert!(is_uuid_present("v1.550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_uuid_present("/x/550e8400-e29b-41d4-a716-446655440000/y"));
        // A bare UUID is bounded by the ends of the input.
        assert!(is_uuid_present("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn test_present_requires_word_boundaries() {
        // Hex digits glued to either edge: no boundary, so no match.
        assert!(!is_uuid_present("abc550e8400-e29b-41d4-a716-446655440000"));
        assert!(!is_uuid_present("550e8400-e29b-41d4-a716-446655440000def"));
        // An underscore is a word character too.
        assert!(!is_uuid_present("_550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn test_present_word_boundary_is_unicode_aware() {
        // The regexes this mirrors use Unicode `\b`, so a non-ASCII letter is a
        // word character and glueing it to the UUID removes the boundary. A
        // byte-level check would see the accent's continuation byte as non-word
        // and wrongly match.
        assert!(!is_uuid_present("café550e8400-e29b-41d4-a716-446655440000"));
        assert!(!is_uuid_present("550e8400-e29b-41d4-a716-446655440000café"));
        assert!(!is_uuid_present("日本550e8400-e29b-41d4-a716-446655440000"));
        // A non-ASCII NON-word character is still a boundary.
        assert!(is_uuid_present("«550e8400-e29b-41d4-a716-446655440000»"));
    }

    #[test]
    fn test_present_treats_full_unicode_word_class_as_word_chars() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        // Each of these is a `\w` character to the regex crate but NOT
        // `char::is_alphanumeric()`, so an alphanumeric-only check would call
        // these positions boundaries and wrongly match. The reference `is_uuid`
        // rejects every one of them.
        for glue in [
            '\u{301}',  // combining acute accent (Mark)
            '\u{200d}', // zero-width joiner (Join_Control)
            '\u{203f}', // undertie (Connector_Punctuation)
        ] {
            assert!(
                !is_uuid_present(&format!("{glue}{uuid}")),
                "{glue:?} before the UUID is a word char, so there is no boundary"
            );
            assert!(
                !is_uuid_present(&format!("{uuid}{glue}")),
                "{glue:?} after the UUID is a word char, so there is no boundary"
            );
        }
    }

    #[test]
    fn test_present_respects_the_length_cap() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        // Just inside the cap: the UUID is still found.
        let padding = MAX_SCAN_LENGTH.saturating_sub(uuid.len()).saturating_sub(1);
        let inside = format!("{} {uuid}", "x".repeat(padding));
        assert_eq!(inside.len(), MAX_SCAN_LENGTH);
        assert!(is_uuid_present(&inside));

        // One byte over: not scanned at all, matching is_uuid's own guard.
        let over = format!("x{inside}");
        assert_eq!(over.len(), MAX_SCAN_LENGTH.saturating_add(1));
        assert!(!is_uuid_present(&over));
    }

    #[test]
    fn test_present_trims_surrounding_whitespace() {
        // is_uuid trims before matching, so padding must not change the answer.
        assert!(is_uuid_present("  550e8400-e29b-41d4-a716-446655440000\n"));
    }

    #[test]
    fn test_present_rejects_non_uuids() {
        assert!(!is_uuid_present(
            "no identifier here at all, none whatsoever"
        ));
        assert!(!is_uuid_present("550e8400-e29b-41d4-a716-44665544000")); // short
        assert!(!is_uuid_present(""));
        // Right shape, invalid version/variant - the nil UUID must not match.
        assert!(!is_uuid_present("id=00000000-0000-0000-0000-000000000000"));
    }

    #[test]
    fn test_present_scans_past_a_near_miss() {
        // A bad candidate early on must not stop the scan finding a later one.
        let value = "00000000-0000-0000-0000-000000000000 550e8400-e29b-41d4-a716-446655440000";
        assert!(is_uuid_present(value));
    }

    #[test]
    fn test_present_handles_multibyte_without_panicking() {
        // Non-ASCII shifts byte offsets off char boundaries; slicing must not
        // panic, and the trailing UUID must still be found.
        assert!(is_uuid_present(
            "héllo 550e8400-e29b-41d4-a716-446655440000"
        ));
        assert!(!is_uuid_present("héllo there, no identifier in this text"));
    }

    #[test]
    fn test_rejects_multibyte_input_of_same_byte_length() {
        // 36 BYTES but fewer than 36 chars - the check works on bytes, so a
        // multibyte character must not be mistaken for hex digits.
        // 24-byte prefix + 10 ASCII hex digits + 'é' (2 bytes) = 36 bytes.
        let value = "550e8400-e29b-41d4-a716-4466554400é";
        assert_eq!(value.len(), UUID_LEN, "fixture must be 36 bytes");
        assert!(!is_uuid_shape(value));
    }
}
