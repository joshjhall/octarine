//! Indian UPI (Unified Payments Interface) VPA detection
//!
//! Detects UPI virtual payment addresses (VPAs) of the form `account@psp`,
//! where `psp` is one of the NPCI-registered Payment Service Provider handles
//! (`oksbi`, `paytm`, `ybl`, `okhdfcbank`, `upi`, ...).
//!
//! # Why an allowlist, not a regex shape
//!
//! A UPI VPA is syntactically indistinguishable from an email local-part plus
//! `@handle`. The discriminator is the **suffix**: a UPI PSP handle is a bare
//! token with no dot (`oksbi`), whereas an email host carries a TLD
//! (`gmail.com`). Gating on an exact-membership check against a curated NPCI
//! allowlist means `alice@oksbi` matches while `alice@paytm.com` (an email)
//! does not — `paytm.com` is not in the allowlist.
//!
//! Detection is shape/allowlist only (the project-wide lenient `is_*`
//! contract); `validation::validate_india_upi` is the strict counterpart.

use std::collections::HashSet;

use once_cell::sync::Lazy;

use super::super::super::common::patterns;
use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};

/// Maximum input length for ReDoS protection (matches sibling detectors).
const MAX_INPUT_LENGTH: usize = 10_000;

/// Maximum length of the account (local) part of a VPA. NPCI caps handles well
/// below this; the bound is a defensive guard, not a spec limit.
const MAX_ACCOUNT_LENGTH: usize = 256;

/// Bytes of surrounding text scanned on each side of a match for a
/// context keyword when scoring confidence.
const CONTEXT_WINDOW_BYTES: usize = 40;

/// Positive context keywords (English + Hindi) that, when found near a match,
/// upgrade confidence. Lowercased for case-insensitive comparison.
const CONTEXT_KEYWORDS: &[&str] = &["upi", "vpa", "bhim", "यूपीआई"];

/// Curated allowlist of NPCI-registered UPI PSP handle suffixes.
///
/// Sourced from the NPCI list of live UPI handles (banks + third-party apps).
/// All entries are lowercase; matching lowercases the candidate suffix first.
static PSP_SUFFIXES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // Third-party apps / PSPs
        "upi",
        "paytm",
        "ybl",
        "ibl",
        "axl",
        "apl",
        "yapl",
        "rapl",
        "abfspay",
        "waaxis",
        "wasbi",
        "wahdfcbank",
        "waicici",
        "gpay",
        // Google Pay bank handles
        "oksbi",
        "okhdfcbank",
        "okicici",
        "okaxis",
        // State Bank of India
        "sbi",
        "sbibank",
        // HDFC
        "hdfcbank",
        "payzapp",
        "hdfcbankjd",
        "pingpay",
        // ICICI
        "icici",
        "pockets",
        "icicibank",
        // Axis
        "axisbank",
        "axisb",
        "axisgo",
        // Public / private sector banks
        "pnb",
        "unionbank",
        "unionbankofindia",
        "uboi",
        "cnrb",
        "barodampay",
        "barodapay",
        "bandhan",
        "cbin",
        "boi",
        "cboi",
        "indus",
        "indusind",
        "idbi",
        "idbibank",
        "kotak",
        "kmb",
        "kmbl",
        "yesbank",
        "yesbankltd",
        "federal",
        "fbl",
        "rbl",
        "idfcbank",
        "idfcnetc",
        "indianbank",
        "allbank",
        "psb",
        "sib",
        "dbs",
        "dlb",
        "kbl",
        "kbl052",
        "tjsb",
        "uco",
        "utbi",
        "vijb",
        "jkb",
        "jsb",
        "jsbp",
        "mahb",
        "csbpay",
        "dcb",
        "equitas",
        "esfb",
        "finobank",
        "fincare",
        "hsbc",
        "scb",
        "sc",
        "citi",
        "citigold",
        "dlxb",
        "lvb",
        "lvbl",
        // Fintech / wallet PSP handles
        "freecharge",
        "fkaxis",
        "yesg",
        "timecosmos",
        "mobikwik",
        "naviaxis",
        "jupiteraxis",
        "slice",
        "slc",
        "postbank",
        "aubank",
        "internationalbank",
    ]
    .into_iter()
    .collect()
});

// ============================================================================
// Public API
// ============================================================================

/// Check if `value` is an Indian UPI VPA.
///
/// Lenient shape + allowlist check: splits on the last `@`, lowercases, and
/// verifies the suffix is a known NPCI PSP handle. Does not verify that the
/// account part corresponds to a real customer.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::detection;
///
/// assert!(detection::is_india_upi("alice@oksbi"));
/// assert!(detection::is_india_upi("9876543210@paytm"));
/// assert!(!detection::is_india_upi("alice@paytm.com")); // email, not UPI
/// assert!(!detection::is_india_upi("alice@fakebank")); // unknown PSP
/// ```
#[must_use]
pub fn is_india_upi(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_ACCOUNT_LENGTH.saturating_add(MAX_ACCOUNT_LENGTH) {
        return false;
    }

    let Some((account, psp)) = trimmed.rsplit_once('@') else {
        return false;
    };

    // Account part: non-empty, bounded, and made only of the characters NPCI
    // permits in a VPA local-part.
    if account.is_empty() || account.len() > MAX_ACCOUNT_LENGTH {
        return false;
    }
    if !account
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return false;
    }

    let psp_lower = psp.to_ascii_lowercase();
    PSP_SUFFIXES.contains(psp_lower.as_str())
}

/// Find all Indian UPI VPAs in `text`.
///
/// Scans for `@`-bearing candidate tokens, filters each through
/// [`is_india_upi`], and scores confidence: base `Medium`, upgraded to `High`
/// when a UPI context keyword (`upi`, `vpa`, `bhim`, `यूपीआई`) appears within
/// [`CONTEXT_WINDOW_BYTES`] of the match.
///
/// Includes a `MAX_INPUT_LENGTH` ReDoS guard consistent with sibling
/// financial detectors.
#[allow(clippy::expect_used)]
#[must_use]
pub fn find_india_upis_in_text(text: &str) -> Vec<IdentifierMatch> {
    if text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for capture in patterns::financial::upi::CANDIDATE.captures_iter(text) {
        let full_match = capture.get(0).expect("BUG: capture group 0 always exists");
        let candidate = full_match.as_str();

        if !is_india_upi(candidate) {
            continue;
        }

        let confidence = DetectionConfidence::Medium.with_context_boost(has_context_keyword(
            text,
            full_match.start(),
            full_match.end(),
        ));

        matches.push(IdentifierMatch::new(
            full_match.start(),
            full_match.end(),
            candidate.to_string(),
            IdentifierType::IndiaUpi,
            confidence,
        ));
    }

    super::common::deduplicate_matches(matches)
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Scan the ±[`CONTEXT_WINDOW_BYTES`] window around a match for any UPI
/// context keyword. Window endpoints are snapped to UTF-8 codepoint
/// boundaries so a non-ASCII keyword (`यूपीआई`) straddling the window does not
/// split mid-codepoint.
fn has_context_keyword(text: &str, match_start: usize, match_end: usize) -> bool {
    let window_start = floor_char_boundary(text, match_start.saturating_sub(CONTEXT_WINDOW_BYTES));
    let window_end = ceil_char_boundary(
        text,
        match_end
            .saturating_add(CONTEXT_WINDOW_BYTES)
            .min(text.len()),
    );

    let Some(window) = text.get(window_start..window_end) else {
        return false;
    };
    let window_lower = window.to_lowercase();

    CONTEXT_KEYWORDS.iter().any(|kw| window_lower.contains(kw))
}

/// Round `pos` down to the nearest UTF-8 codepoint boundary.
fn floor_char_boundary(text: &str, pos: usize) -> usize {
    let mut p = pos.min(text.len());
    while p > 0 && !text.is_char_boundary(p) {
        p = p.saturating_sub(1);
    }
    p
}

/// Round `pos` up to the nearest UTF-8 codepoint boundary.
fn ceil_char_boundary(text: &str, pos: usize) -> usize {
    let mut p = pos.min(text.len());
    while p < text.len() && !text.is_char_boundary(p) {
        p = p.saturating_add(1);
    }
    p
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_india_upi_valid() {
        assert!(is_india_upi("alice@oksbi"));
        assert!(is_india_upi("9876543210@paytm"));
        assert!(is_india_upi("john.doe@ybl"));
        assert!(is_india_upi("user_name@okhdfcbank"));
        assert!(is_india_upi("merchant-01@icici"));
    }

    #[test]
    fn test_is_india_upi_case_insensitive_suffix() {
        assert!(is_india_upi("Alice@OKSBI"));
        assert!(is_india_upi("BOB@Paytm"));
    }

    #[test]
    fn test_is_india_upi_rejects_email() {
        // Email hosts carry a TLD dot → suffix not in allowlist.
        assert!(!is_india_upi("alice@paytm.com"));
        assert!(!is_india_upi("alice@gmail.com"));
        assert!(!is_india_upi("alice@oksbi.co.in"));
    }

    #[test]
    fn test_is_india_upi_rejects_unknown_psp() {
        assert!(!is_india_upi("alice@fakebank"));
        assert!(!is_india_upi("alice@notapsp"));
    }

    #[test]
    fn test_is_india_upi_rejects_malformed() {
        assert!(!is_india_upi(""));
        assert!(!is_india_upi("noatsign"));
        assert!(!is_india_upi("@oksbi")); // empty account
        assert!(!is_india_upi("alice@")); // empty psp
        assert!(!is_india_upi("ali ce@oksbi")); // space in account
    }

    #[test]
    fn test_is_india_upi_allowlist_boundary() {
        // Real handle vs. near-miss.
        assert!(is_india_upi("x@upi"));
        assert!(!is_india_upi("x@upii"));
        assert!(!is_india_upi("x@up"));
    }

    #[test]
    fn test_find_india_upis_in_text_basic() {
        let matches = find_india_upis_in_text("Send it to 9876543210@paytm please");
        assert_eq!(matches.len(), 1);
        let m = matches.first().expect("one match");
        assert_eq!(m.identifier_type, IdentifierType::IndiaUpi);
        assert_eq!(m.matched_text, "9876543210@paytm");
    }

    #[test]
    fn test_find_india_upis_context_boost() {
        // Keyword present → High confidence.
        let boosted = find_india_upis_in_text("My UPI id is alice@oksbi");
        assert_eq!(boosted.len(), 1);
        assert_eq!(
            boosted.first().expect("match").confidence,
            DetectionConfidence::High
        );

        // No keyword → Medium confidence.
        let plain = find_india_upis_in_text("send money to alice@oksbi now");
        assert_eq!(plain.len(), 1);
        assert_eq!(
            plain.first().expect("match").confidence,
            DetectionConfidence::Medium
        );
    }

    #[test]
    fn test_find_india_upis_hindi_context_boost() {
        let matches = find_india_upis_in_text("यूपीआई: alice@ybl");
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches.first().expect("match").confidence,
            DetectionConfidence::High
        );
    }

    #[test]
    fn test_find_india_upis_ignores_email() {
        let matches = find_india_upis_in_text("Email alice@paytm.com for support");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_find_india_upis_multiple() {
        let matches = find_india_upis_in_text("Pay 9876543210@paytm or bob@oksbi via UPI");
        assert_eq!(matches.len(), 2);
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::IndiaUpi)
        );
    }

    #[test]
    fn test_find_india_upis_empty_and_clean() {
        assert!(find_india_upis_in_text("").is_empty());
        assert!(find_india_upis_in_text("no upi here at all").is_empty());
    }
}
