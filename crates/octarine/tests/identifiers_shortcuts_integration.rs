//! Integration tests for the Layer 3 identifier shortcut surface.
//!
//! Covers the public shortcuts exported from `octarine::identifiers` that
//! previously had no coverage at all (issue #413):
//!
//! - `identifiers/shortcuts/sensitive.rs` — the scanning, field-aware
//!   detection, and `is_*_present` families.
//! - `identifiers/shortcuts/bulk.rs` — `redact_pii`, `redact_credentials`,
//!   and `redact_all`.
//!
//! ## Assertion discipline
//!
//! Redaction assertions check **both** directions: the sensitive substring is
//! gone *and* the surrounding non-sensitive prose survives verbatim. A bare
//! `assert_ne!(output, input)` would pass for a function that returned the
//! empty string, so it is never used alone here.
//!
//! ## Test vectors
//!
//! All identifiers below are synthetic but deliberately *not* the well-known
//! sample values. The detectors filter those on purpose:
//!
//! - `123-45-6789` and `555-55-5555` are rejected by the SSN false-positive
//!   filter (known advertising SSNs / repeating digits), so a realistic
//!   area-group-serial value is used instead.
//! - `4111111111111111` and `5555555555554444` are in the processor test-card
//!   table and are downgraded below the `is_credit_card` confidence floor, so
//!   Luhn-valid non-test numbers are used instead.
//! - Phone detection requires a parseable number (E.164 or a full NANP form);
//!   the `555-867-5309` exchange does not parse.
//!
//! `TEST_API_KEY` deliberately matches the **generic** labelled-key pattern
//! (`api_key:` + 20 or more key characters) rather than any vendor's prefix.
//! Vendor-shaped literals — `sk_live_` and even Stripe's `sk_test_` — are
//! claimed by GitHub secret-scanning push protection, which rejects the push
//! outright regardless of the value being synthetic.

#![allow(clippy::panic, clippy::expect_used)]

use octarine::identifiers::{
    DetectionConfidence, IdentifierMatch, IdentifierType, detect_credit_card, detect_data_type,
    detect_data_type_with_context, detect_email, detect_phone, is_api_keys_present,
    is_credit_cards_present, is_data_type, is_emails_present, is_phones_present,
    is_sensitive_present, is_ssns_present, redact_all, redact_credentials, redact_pii, scan_batch,
    scan_compliance, scan_credentials, scan_payment_data, scan_pii, scan_sensitive,
};

// Synthetic test vectors reused across tests. See the module docs above for
// why the textbook sample values are unsuitable.
const TEST_EMAIL: &str = "alice@example.com";
const TEST_SSN: &str = "517-29-8346";
const TEST_CARD: &str = "4012888888881881";
const TEST_PHONE: &str = "+12125551234";
const TEST_API_KEY: &str = "api_key: ZZZZEXAMPLEZZZZEXAMPLEZZZZ0000";

/// True when any match in the set carries the given identifier type.
fn has_type(matches: &[IdentifierMatch], want: IdentifierType) -> bool {
    matches.iter().any(|m| m.identifier_type == want)
}

/// Describe a match set by **type and span only**, never echoing the matched
/// text.
///
/// Assertion messages are panic output, and interpolating a detected
/// identifier there is cleartext logging of sensitive information — CodeQL
/// flags it, and rightly so: this pattern copied into a non-test context would
/// leak real PII into a log. The vectors in this file are synthetic, but the
/// habit is worth keeping, so failure messages describe *what was found* rather
/// than reproducing it.
fn summarize(matches: &[IdentifierMatch]) -> Vec<String> {
    matches
        .iter()
        .map(|m| {
            format!(
                "{:?}@{}..{} ({:?})",
                m.identifier_type, m.start, m.end, m.confidence
            )
        })
        .collect()
}

// ============================================================================
// Scanning shortcuts
// ============================================================================

/// `scan_pii` finds both personal and government identifiers in one pass.
#[test]
fn test_scan_pii_finds_personal_and_government_identifiers() {
    let text = format!("Contact {TEST_EMAIL}, employee SSN: {TEST_SSN}.");
    let matches = scan_pii(&text);

    assert!(
        has_type(&matches, IdentifierType::Email),
        "expected an Email match, found {:?}",
        summarize(&matches)
    );
    assert!(
        has_type(&matches, IdentifierType::Ssn),
        "expected an Ssn match, found {:?}",
        summarize(&matches)
    );

    // The email match is the address itself, not the whole input.
    let email_match = matches
        .iter()
        .find(|m| m.identifier_type == IdentifierType::Email)
        .expect("email match present");
    assert_eq!(email_match.matched_text, TEST_EMAIL);
    assert!(
        email_match.end > email_match.start,
        "match span must be non-empty, got {}..{}",
        email_match.start,
        email_match.end
    );

    // The SSN match must cover the digits (the labelled-pattern match also
    // spans the "SSN:" label, which is how labelled matches earn High
    // confidence — so assert containment, not equality).
    //
    // The predicate is reduced to a bool before the assertion: taint analysis
    // follows anything derived from the match (even a length), so the failure
    // message describes the whole set via `summarize` instead.
    let ssn_covers_digits = matches
        .iter()
        .filter(|m| m.identifier_type == IdentifierType::Ssn)
        .any(|m| m.matched_text.contains(TEST_SSN));
    assert!(
        ssn_covers_digits,
        "an Ssn match should cover the digits, found {:?}",
        summarize(&matches)
    );
}

/// `scan_pii` returns nothing for prose that contains no identifiers.
#[test]
fn test_scan_pii_empty_for_clean_text() {
    let matches = scan_pii("The quarterly report is ready for review.");
    assert!(
        matches.is_empty(),
        "clean prose should yield no PII matches, got {:?}",
        summarize(&matches)
    );
}

/// `scan_payment_data` finds the card but not the unrelated email.
#[test]
fn test_scan_payment_data_isolates_card() {
    let text = format!("Card {TEST_CARD} billed to {TEST_EMAIL}");
    let matches = scan_payment_data(&text);

    assert!(
        has_type(&matches, IdentifierType::CreditCard),
        "expected a CreditCard match, found {:?}",
        summarize(&matches)
    );
    assert!(
        !has_type(&matches, IdentifierType::Email),
        "payment scan must not report the email, found {:?}",
        summarize(&matches)
    );
}

/// `scan_credentials` reports the credential value, not the label.
#[test]
fn test_scan_credentials_extracts_value_not_label() {
    let text = "database password: hunter2CorrectHorseBattery";
    let matches = scan_credentials(text);

    assert!(
        !matches.is_empty(),
        "expected at least one credential match in {text:?}"
    );
    let first = matches.first().expect("credential match present");
    assert!(
        first.value.contains("hunter2"),
        "credential value should be the secret; matched {} chars labelled {:?}",
        first.value.len(),
        first.label
    );
    assert_ne!(
        first.value, "password",
        "the label must not be reported as the value"
    );
}

/// `scan_compliance` spans more domains than `scan_pii` — it also reports the
/// PCI-DSS credit card that `scan_pii` ignores.
#[test]
fn test_scan_compliance_covers_more_domains_than_scan_pii() {
    let text = format!("{TEST_EMAIL} paid with {TEST_CARD}");

    let pii = scan_pii(&text);
    let compliance = scan_compliance(&text);

    assert!(
        !has_type(&pii, IdentifierType::CreditCard),
        "scan_pii is not expected to cover cards, found {:?}",
        summarize(&pii)
    );
    assert!(
        has_type(&compliance, IdentifierType::CreditCard),
        "scan_compliance must cover PCI-DSS card data, found {:?}",
        summarize(&compliance)
    );
    assert!(
        has_type(&compliance, IdentifierType::Email),
        "scan_compliance must still cover GDPR personal data, found {:?}",
        summarize(&compliance)
    );
}

/// `scan_sensitive` finds identifiers in mixed text.
#[test]
fn test_scan_sensitive_finds_identifiers() {
    let matches = scan_sensitive(&format!("reach me at {TEST_EMAIL}"));
    assert!(
        has_type(&matches, IdentifierType::Email),
        "expected an Email match, found {:?}",
        summarize(&matches)
    );
}

/// `scan_batch` returns one result slot per input, aligned by index.
#[test]
fn test_scan_batch_aligns_results_with_inputs() {
    let values = [TEST_EMAIL, "plain prose", TEST_CARD];
    let results = scan_batch(&values);

    assert_eq!(results.len(), values.len(), "one result slot per input");

    let email_slot = results.first().expect("slot 0");
    let card_slot = results.get(2).expect("slot 2");

    assert!(
        email_slot
            .iter()
            .any(|m| m.identifier_type == IdentifierType::Email),
        "slot 0 should carry the email match, got {:?}",
        summarize(email_slot)
    );
    assert!(
        card_slot
            .iter()
            .any(|m| m.identifier_type == IdentifierType::CreditCard),
        "slot 2 should carry the card match, got {:?}",
        summarize(card_slot)
    );
}

/// `scan_batch` on an empty slice returns an empty vec (not a panic).
#[test]
fn test_scan_batch_empty_input() {
    assert!(scan_batch(&[]).is_empty());
}

// ============================================================================
// Single-value type detection
// ============================================================================

/// `detect_data_type` gives each value its own type — the results are distinct
/// from one another, so a constant-returning implementation fails here.
#[test]
fn test_detect_data_type_discriminates_between_types() {
    assert_eq!(detect_data_type(TEST_EMAIL), Some(IdentifierType::Email));
    assert_eq!(
        detect_data_type("550e8400-e29b-41d4-a716-446655440000"),
        Some(IdentifierType::Uuid)
    );
    assert_eq!(
        detect_data_type("192.168.1.1"),
        Some(IdentifierType::IpAddress)
    );
    assert_eq!(
        detect_data_type("https://example.com/path"),
        Some(IdentifierType::Url)
    );
}

/// Arbitrary prose is not an identifier — `detect_data_type` returns `None`.
///
/// Regression for #772: `is_hostname` matched an unanchored pattern, so the
/// hostname fallthrough (the last arm of network detection) claimed the first
/// bare word of any string and this function effectively never returned `None`.
/// The `#413` integration tests could only assert *discrimination between*
/// known types because of this hole.
#[test]
fn test_detect_data_type_returns_none_for_prose() {
    for prose in [
        "just some words",
        "the quarterly report",
        "Hello, world.",
        "hello world",
        // Same bug class via the port arm, which is checked before hostname:
        // the unanchored PORT pattern matched the ":30" inside this string.
        "meeting at 3:30",
        "aspect ratio 16:9",
    ] {
        assert_eq!(
            detect_data_type(prose),
            None,
            "prose {prose:?} must not be classified as an identifier"
        );
    }
}

/// Values that genuinely are hostnames still classify — the #772 tightening
/// rejects prose without collapsing the Hostname type itself.
///
/// Only `host:port` is asserted here. A bare single-token hostname
/// (`web-server`, `cache-node-3`) is claimed by the personal-domain `Username`
/// heuristic, which runs before network detection in `IdentifierBuilder::detect`
/// and matches any 3-32 character word. That is a separate pre-existing gap
/// (unchanged by #772) — see `test_detect_data_type_single_word_prose_gap`.
#[test]
fn test_detect_data_type_still_detects_hostnames() {
    assert_eq!(
        detect_data_type("db-primary:5432"),
        Some(IdentifierType::Hostname),
        "a host:port value should classify as a hostname"
    );
}

/// Documents a KNOWN REMAINING GAP, so it is visible rather than silent.
///
/// #772 fixed the hostname and port arms, so multi-word prose now returns
/// `None`. A single bare word is still claimed by the `Username` heuristic in
/// `primitives::identifiers::personal::detection::find_personal_identifier`,
/// which accepts any 3-32 char `[a-zA-Z0-9_.-]` token with no dot. That arm is
/// already anchored — it is over-broad, not unanchored — so it is a different
/// defect from #772 and is deliberately out of scope here.
///
/// If this assertion starts failing, the Username heuristic was tightened:
/// flip it to `None` and delete this comment.
#[test]
fn test_detect_data_type_single_word_prose_gap() {
    assert_eq!(
        detect_data_type("report"),
        Some(IdentifierType::Username),
        "known gap: the Username heuristic claims any bare word"
    );
}

/// The field-name hint resolves values the general detector classifies
/// differently — an SSN-shaped string is only reported as an SSN once the
/// field says so.
#[test]
fn test_detect_data_type_with_context_uses_field_name() {
    assert_eq!(
        detect_data_type_with_context(TEST_SSN, "social_security_number"),
        Some(IdentifierType::Ssn)
    );
    assert_ne!(
        detect_data_type(TEST_SSN),
        Some(IdentifierType::Ssn),
        "without the field hint this value is not classified as an SSN — \
         that difference is what the hint is for"
    );

    assert_eq!(
        detect_data_type_with_context(TEST_CARD, "credit_card"),
        Some(IdentifierType::CreditCard)
    );
    assert_eq!(
        detect_data_type_with_context(TEST_EMAIL, "email_address"),
        Some(IdentifierType::Email)
    );
}

/// A mismatched field name does not force a wrong classification — the value
/// still wins. This is what keeps the hint from being a blind override.
#[test]
fn test_detect_data_type_with_context_does_not_override_value() {
    assert_ne!(
        detect_data_type_with_context("192.168.1.1", "email"),
        Some(IdentifierType::Email),
        "a mismatched field hint must not mislabel the value"
    );
    assert_ne!(
        detect_data_type_with_context(TEST_EMAIL, "credit_card"),
        Some(IdentifierType::CreditCard),
        "a mismatched field hint must not mislabel the value"
    );
}

/// `is_data_type` agrees with `detect_data_type` in both directions.
#[test]
fn test_is_data_type_positive_and_negative() {
    assert!(is_data_type(TEST_EMAIL, IdentifierType::Email));
    assert!(
        !is_data_type(TEST_EMAIL, IdentifierType::Ssn),
        "an email must not classify as an SSN"
    );
    assert!(is_data_type("192.168.1.1", IdentifierType::IpAddress));
    assert!(
        !is_data_type("192.168.1.1", IdentifierType::Email),
        "an IP must not classify as an email"
    );
}

/// `detect_email` returns the value only when it really is an email.
#[test]
fn test_detect_email_accepts_and_rejects() {
    assert_eq!(detect_email(TEST_EMAIL), Some(TEST_EMAIL.to_string()));
    assert_eq!(detect_email("alice at example dot com"), None);
    assert_eq!(detect_email(""), None);
}

/// `detect_phone` accepts parseable numbers in two formats and rejects prose.
#[test]
fn test_detect_phone_accepts_and_rejects() {
    assert_eq!(detect_phone(TEST_PHONE), Some(TEST_PHONE.to_string()));
    assert_eq!(
        detect_phone("(212) 555-1234"),
        Some("(212) 555-1234".to_string())
    );
    assert_eq!(detect_phone("call me maybe"), None);
    assert_eq!(detect_phone(""), None);
}

/// `detect_credit_card` returns a fully populated match, not just `Some(_)`.
#[test]
fn test_detect_credit_card_match_fields() {
    let found = detect_credit_card(TEST_CARD).expect("Luhn-valid card should be detected");

    assert_eq!(found.matched_text, TEST_CARD);
    assert_eq!(found.identifier_type, IdentifierType::CreditCard);
    assert_eq!(found.confidence, DetectionConfidence::High);
    assert_eq!(found.start, 0);
    assert_eq!(found.end, TEST_CARD.len());
}

/// A card number that fails the Luhn check is rejected.
#[test]
fn test_detect_credit_card_rejects_invalid_luhn() {
    // TEST_CARD with its final check digit changed.
    assert!(
        detect_credit_card("4012888888881882").is_none(),
        "a number failing the Luhn checksum must not be detected as a card"
    );
    assert!(detect_credit_card("not a card").is_none());
}

// ============================================================================
// Boolean presence family
// ============================================================================

/// Each presence helper is true for its own domain and false for a
/// neighbour's data — so none of them can be a constant `true`.
#[test]
fn test_presence_helpers_are_domain_specific() {
    let ssn_text = format!("Employee SSN: {TEST_SSN}");
    let card_text = format!("Card: {TEST_CARD}");
    let email_text = format!("Email: {TEST_EMAIL}");
    let phone_text = format!("Phone: {TEST_PHONE}");

    assert!(is_ssns_present(&ssn_text));
    assert!(!is_ssns_present(&email_text), "email text has no SSN");

    assert!(is_credit_cards_present(&card_text));
    assert!(
        !is_credit_cards_present(&email_text),
        "email text has no card"
    );

    assert!(is_emails_present(&email_text));
    assert!(!is_emails_present(&ssn_text), "SSN text has no email");

    assert!(is_phones_present(&phone_text));
    assert!(!is_phones_present(&email_text), "email text has no phone");
}

/// Every presence helper is false for prose containing no identifiers.
#[test]
fn test_presence_helpers_false_on_clean_text() {
    let clean = "Please review the attached quarterly summary.";

    assert!(!is_ssns_present(clean));
    assert!(!is_credit_cards_present(clean));
    assert!(!is_emails_present(clean));
    assert!(!is_phones_present(clean));
    assert!(!is_api_keys_present(clean));
    assert!(!is_sensitive_present(clean));
}

/// `is_api_keys_present` fires on an API-key-shaped token but not on prose.
#[test]
fn test_is_api_keys_present_detects_key() {
    assert!(
        is_api_keys_present(&format!("config has {TEST_API_KEY} set")),
        "expected an API key to be detected"
    );
    assert!(
        !is_api_keys_present("authorization uses the usual process"),
        "prose mentioning authorization is not an API key"
    );
}

/// `is_sensitive_present` fires on PII and on a labelled credential.
#[test]
fn test_is_sensitive_present_covers_pii_and_credentials() {
    assert!(
        is_sensitive_present(&format!("write to {TEST_EMAIL}")),
        "PII alone should be sensitive"
    );
    assert!(
        is_sensitive_present("password: hunter2CorrectHorseBattery"),
        "a labelled credential alone should be sensitive"
    );
    assert!(
        !is_sensitive_present("nothing to see in this sentence"),
        "plain prose is not sensitive"
    );
}

// ============================================================================
// Bulk redaction
// ============================================================================

/// `redact_pii` removes the identifiers and keeps the surrounding prose.
#[test]
fn test_redact_pii_removes_identifiers_and_preserves_prose() {
    let input = format!("Dear customer, reach {TEST_EMAIL} or SSN: {TEST_SSN} before Friday.");
    let output = redact_pii(&input);

    assert!(
        !output.contains(TEST_EMAIL),
        "email must be redacted, got {output:?}"
    );
    assert!(
        !output.contains(TEST_SSN),
        "SSN must be redacted, got {output:?}"
    );
    // The non-sensitive framing survives — this is what rules out an
    // implementation that simply returns an empty or wholly-masked string.
    assert!(
        output.contains("Dear customer"),
        "leading prose must survive, got {output:?}"
    );
    assert!(
        output.contains("before Friday"),
        "trailing prose must survive, got {output:?}"
    );
}

/// `redact_pii` leaves identifier-free text byte-for-byte unchanged.
#[test]
fn test_redact_pii_is_identity_on_clean_text() {
    let clean = "The quarterly report is ready for review.";
    assert_eq!(redact_pii(clean), clean);
}

/// `redact_credentials` removes the secret and keeps the surrounding prose.
#[test]
fn test_redact_credentials_removes_secret() {
    let fake_password = "hunter2CorrectHorseBattery";
    let input = format!("deploy note: password: {fake_password} end of note");
    let output = redact_credentials(&input);

    assert!(
        !output.contains(fake_password),
        "credential must be redacted, got {output:?}"
    );
    assert!(
        output.contains("deploy note"),
        "leading prose must survive, got {output:?}"
    );
    assert!(
        output.contains("end of note"),
        "trailing prose must survive, got {output:?}"
    );
}

/// `redact_credentials` leaves credential-free text unchanged.
#[test]
fn test_redact_credentials_is_identity_on_clean_text() {
    let clean = "The deployment finished without incident.";
    assert_eq!(redact_credentials(clean), clean);
}

/// `redact_all` covers domains `redact_pii` does not — it removes the
/// credential *as well as* the PII, which distinguishes the two functions.
#[test]
fn test_redact_all_covers_more_than_redact_pii() {
    let fake_password = "hunter2CorrectHorseBattery";
    let input = format!("owner {TEST_EMAIL} password: {fake_password} done");

    let pii_only = redact_pii(&input);
    let everything = redact_all(&input);

    assert!(
        pii_only.contains(fake_password),
        "redact_pii is not expected to touch credentials \
         (output withheld: it still contains the credential by design)"
    );
    assert!(
        !everything.contains(fake_password),
        "redact_all must remove the credential, got {everything:?}"
    );
    assert!(
        !everything.contains(TEST_EMAIL),
        "redact_all must also remove PII, got {everything:?}"
    );
    assert!(
        everything.contains("done"),
        "trailing prose must survive, got {everything:?}"
    );
}

/// All three bulk redactors handle empty input without panicking.
#[test]
fn test_bulk_redactors_handle_empty_input() {
    assert_eq!(redact_pii(""), "");
    assert_eq!(redact_credentials(""), "");
    assert_eq!(redact_all(""), "");
}
