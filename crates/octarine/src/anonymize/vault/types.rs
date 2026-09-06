//! Value types that flow through every [`StateStore`](super::StateStore)
//! operation.
//!
//! [`SessionId`] is the opaque handle that scopes a run of reversible
//! pseudonymization — every mapping stored in the vault belongs to exactly one
//! session, and a later deanonymize call must present the same session to
//! recover the originals. [`EntityKey`] is the composite key under which a
//! single original value is stored: the detected entity type (`"PERSON"`,
//! `"EMAIL"`, …) paired with the original PII string.
//!
//! Both types are cheap, owned wrappers chosen so they can be used directly as
//! keys in an in-memory map (the default [`StateStore`](super::StateStore)
//! backend) — they derive [`Hash`] and [`Eq`].

use std::fmt;

use crate::primitives::crypto::hash::blake3;

/// Bytes of the BLAKE3 hash [`SessionId::digest`] retains; each becomes two
/// characters, so the rendered digest is twice this long.
///
/// Six bytes (48 bits, 12 characters) is enough to distinguish the sessions
/// alive in one audit stream, and matches the digest length used for
/// `SecureMap` keys so the two schemes read alike in a combined log. The upper
/// bound is set by the redactor's 20-character entropy rule, not by security —
/// see [`SessionId::digest`].
///
/// Two limits of this length, both accepted deliberately:
///
/// - **It is not a defense against guessing the handle.** Truncation does not
///   add brute-force resistance; see the security note on [`SessionId::digest`].
/// - **Collisions become likely around 2^24 (~17M) distinct handles** in one
///   correlation window, by the birthday bound. Two unrelated sessions would
///   then share a digest and their events would be indistinguishable. That is
///   far beyond the live-session count this store is built for, but a
///   deployment logging tens of millions of distinct handles into a single
///   retention window should lengthen the digest — and re-check the entropy
///   rule when it does.
const SESSION_DIGEST_BYTES: usize = 6;

/// Characters in a rendered digest: two per retained byte.
///
/// Test-only: production code never needs the rendered length, but the tests
/// assert on it so the encoding's 2-chars-per-byte contract stays explicit.
#[cfg(test)]
const SESSION_DIGEST_LEN: usize = SESSION_DIGEST_BYTES * 2;

/// An opaque per-session handle that scopes a run of reversible
/// pseudonymization.
///
/// A session groups every `original → token` mapping minted while protecting a
/// conversation or request. The same `SessionId` must be presented to a later
/// deanonymize call to recover the original identities. The value is
/// caller-chosen and carries no entropy requirement of its own — unlike an
/// authentication session token, it is a routing label, not a credential, so
/// [`Display`](fmt::Display) and [`as_str`](Self::as_str) show it in full.
///
/// # Logging
///
/// The vault's own observe events log [`digest`](Self::digest) — a truncated
/// BLAKE3 hash — rather than the handle itself (issue #629), so a handle that
/// accidentally carries PII does not reach an audit writer verbatim. The
/// digest is stable for a given handle, so events for one session still
/// correlate.
///
/// That protection covers **this crate's** events only. `Display`, `Debug`,
/// and [`as_str`](Self::as_str) all yield the raw value by design — if your own
/// code logs a `SessionId`, log `digest()` instead.
///
/// # Examples
///
/// ```
/// use octarine::anonymize::SessionId;
///
/// let session = SessionId::new("chat-42");
/// assert_eq!(session.as_str(), "chat-42");
/// assert_eq!(session.to_string(), "chat-42");
///
/// // What the vault's audit events carry instead of the handle.
/// assert_eq!(session.digest().len(), 12);
/// ```
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct SessionId(String);

impl SessionId {
    /// Creates a session handle from any string-like value.
    ///
    /// Infallible: the value is an opaque label, so no validation is applied.
    ///
    /// # The handle must not be PII
    ///
    /// A `SessionId` is a routing label, not a data field: use a synthetic
    /// identifier (`"chat-42"`, a UUID — see
    /// [`SessionManager::open`](super::SessionManager::open), which mints a
    /// UUID-v7 when given no hint). Do **not** construct one from a user's
    /// email, account name, JWT `sub` claim, or any other personal value.
    ///
    /// Because the value is opaque, nothing here can reject such a handle —
    /// PII detection is heuristic, and a false positive would break a
    /// legitimate label. The vault instead limits the blast radius
    /// structurally: its audit events carry [`digest`](Self::digest), never the
    /// handle (see the `# Logging` section on [`SessionId`]). A PII handle is
    /// still a PII value living in your process and in whatever the *caller*
    /// logs, so keep it out of the handle in the first place.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns a truncated BLAKE3 digest of the handle, for logging.
    ///
    /// This is what the vault emits in its observe events in place of the
    /// handle. It is deterministic, so every event for one session shares a
    /// digest and an operator can still follow that session through a log —
    /// without the handle itself appearing there.
    ///
    /// # What this does and does not protect
    ///
    /// The digest is **unkeyed and unsalted**, so it is not a defense against
    /// an attacker who can *guess* the handle. Anyone holding a log line and a
    /// candidate list computes `blake3(candidate)` for each entry and compares
    /// — millions per second — so a handle drawn from a small or enumerable
    /// space (an email, an employee name, a sequential account id) can be
    /// confirmed and recovered. A longer digest would not change this: the cost
    /// is bounded by the size of the candidate list, not the hash.
    ///
    /// What it does buy is real but narrower: the handle no longer appears
    /// *verbatim* in the log, so it is not exposed to casual reading, to log
    /// aggregation and indexing, or to onward shipping of audit records — and
    /// recovering it takes a deliberate, targeted attack with a candidate list
    /// in hand rather than a `grep`.
    ///
    /// This is a blast-radius reduction, not a license to put PII in a handle
    /// — which is why [`new`](Self::new) says not to. A handle that must be
    /// secret against a motivated attacker is a credential, and `SessionId` is
    /// explicitly not one.
    ///
    /// # Message wording is load-bearing
    ///
    /// The observe PII redactor rewrites message text, and **three** of its
    /// rules will silently destroy this digest — two depending on how the
    /// message is phrased, one on the digest's own alphabet. All three were
    /// measured against `redact_pii_with_profile` across all four
    /// `RedactionProfile` variants, not reasoned about:
    ///
    /// 1. **Keyword masking.** Everything following a `secret:` / `password:`
    ///    style prefix is replaced. Callers therefore write `(session <digest>)`
    ///    and never `session secret: <digest>` — the trap documented on
    ///    `SecureMap`'s equivalent helper in `crypto/secrets/map.rs`.
    /// 2. **Entropy masking.** Any whitespace-delimited token of **20+ chars**
    ///    with >50% unique characters is replaced with `[SESSION]`. This is why
    ///    the digest is separated by a **space**, not `=`: `(session=<12 hex>)`
    ///    is one 22-char token and was replaced wholesale under both production
    ///    profiles, while `(session <12 hex>)` splits into `(session` and
    ///    `<12 hex>)` — 8 and 13 chars — and survives intact.
    /// 3. **Digit-run detectors.** The phone/SSN/card detectors match a long
    ///    run of digits *inside* a token. A 12-char **hex** digest contains a
    ///    10+ digit run about **0.5%** of the time (measured: 15 of 3000
    ///    handles), and those were rewritten to `[PHONE]` under
    ///    `ProductionStrict` and to `***-***-2107c1` under `ProductionLenient`.
    ///    This is why the digest is rendered in an all-letter alphabet
    ///    (`a`..=`p`, one character per nibble) rather than as hex: with no
    ///    digits, no digit-run detector can match. Measured at 0 failures
    ///    across 32,000 profile × message-shape combinations.
    ///
    /// Rule 3 is the nastiest of the three because it is **value-dependent**:
    /// it corrupts a fraction of a percent of sessions, permanently for those
    /// handles, and a test using one hard-coded handle passes or fails purely
    /// on whether that handle's digest happened to contain a digit run.
    ///
    /// Rule 2 also bounds the digest length from above: a 16-hex digest
    /// would render 17 chars with its trailing `)`, still under the threshold,
    /// but leaves no headroom for a caller who reformats the message. Keep any
    /// rendered high-entropy token under 20 characters.
    ///
    /// The consequence of getting this wrong is quiet: the code looks correct,
    /// the handle is still protected, and only the correlation disappears — in
    /// production, where it is needed, while `RedactionProfile::Testing`
    /// (which redacts nothing) shows it working.
    ///
    /// # Examples
    ///
    /// ```
    /// use octarine::anonymize::SessionId;
    ///
    /// let session = SessionId::new("chat-42");
    /// // Stable for a given handle, and never the handle itself.
    /// assert_eq!(session.digest(), SessionId::new("chat-42").digest());
    /// assert_ne!(session.digest(), SessionId::new("chat-43").digest());
    /// assert!(!session.digest().contains("chat-42"));
    /// ```
    #[must_use]
    pub fn digest(&self) -> String {
        // Encode each nibble as a letter (`a`..=`p`) rather than as hex. The
        // alphabet is what makes the digest survive the redactor — see
        // "Message wording is load-bearing" above, rule 3: a hex digest
        // routinely contains a 10+ digit run and is rewritten to `[PHONE]`.
        // Letters carry the same 4 bits per character with no digits at all.
        blake3(self.0.as_bytes())
            .iter()
            .take(SESSION_DIGEST_BYTES)
            .flat_map(|byte| {
                // `>> 4` and `& 0x0f` are both < 16, so each lands in `a`..=`p`
                // and the additions cannot overflow (satisfying the crate's
                // denied `arithmetic_side_effects` lint).
                [
                    char::from(b'a'.saturating_add(byte >> 4)),
                    char::from(b'a'.saturating_add(byte & 0x0f)),
                ]
            })
            .collect()
    }

    /// Borrows the handle as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the handle and returns the inner [`String`].
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for SessionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for SessionId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SessionId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<SessionId> for String {
    fn from(id: SessionId) -> Self {
        id.0
    }
}

/// The composite key a single original value is stored under within a session.
///
/// A vault entry maps one [`EntityKey`] to one stable token. The
/// [`entity_type`](EntityKey::entity_type) (e.g. `"PERSON"`, `"EMAIL"`) is kept
/// alongside the [`original`](EntityKey::original) value so that the store can
/// allocate per-type token indices (`<PERSON_0>`, `<EMAIL_0>`) and so that
/// [`list`](super::StateStore::list) can return every mapping for a given type.
///
/// # Examples
///
/// ```
/// use octarine::anonymize::EntityKey;
///
/// let key = EntityKey::new("PERSON", "Jane Doe");
/// assert_eq!(key.entity_type, "PERSON");
/// assert_eq!(key.original, "Jane Doe");
/// ```
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct EntityKey {
    /// The detected entity label, e.g. `"PERSON"` or `"EMAIL"`.
    pub entity_type: String,
    /// The original (pre-anonymization) value of the detected span.
    pub original: String,
}

impl EntityKey {
    /// Creates a key from an entity type and the original value it covers.
    #[must_use]
    pub fn new(entity_type: impl Into<String>, original: impl Into<String>) -> Self {
        Self {
            entity_type: entity_type.into(),
            original: original.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn session_id_round_trips_through_accessors() {
        let session = SessionId::new("chat-42");
        assert_eq!(session.as_str(), "chat-42");
        assert_eq!(session.clone().into_inner(), "chat-42");
        assert_eq!(session.as_ref(), "chat-42");
    }

    #[test]
    fn session_id_displays_full_value() {
        // Unlike an auth credential, the handle is a routing label shown in full.
        let session = SessionId::new("a-deliberately-long-session-handle");
        assert_eq!(session.to_string(), "a-deliberately-long-session-handle");
    }

    #[test]
    fn session_id_digest_is_stable_and_hides_the_handle() {
        // A PII-shaped handle is exactly the case #629 exists for: the digest
        // must contain no fragment of it — not the local part, not the domain.
        let session = SessionId::new("jane.doe@example.com");
        let digest = session.digest();

        assert_eq!(digest, SessionId::new("jane.doe@example.com").digest());
        assert!(!digest.contains("jane"));
        assert!(!digest.contains("doe"));
        assert!(!digest.contains("example"));
        assert!(!digest.contains('@'));
    }

    #[test]
    fn session_id_digest_distinguishes_handles() {
        // Adjacent handles must not collide, or audit events for two sessions
        // would be indistinguishable in a log.
        assert_ne!(
            SessionId::new("chat-42").digest(),
            SessionId::new("chat-43").digest()
        );
        // Truncation must not erase the distinction between a value and its
        // own prefix.
        assert_ne!(
            SessionId::new("chat").digest(),
            SessionId::new("chat-42").digest()
        );
        // The empty handle still yields a full-length digest rather than "".
        assert_eq!(SessionId::new("").digest().len(), SESSION_DIGEST_LEN);
    }

    #[test]
    fn session_id_digest_is_letters_only() {
        let digest = SessionId::new("chat-42").digest();
        assert_eq!(digest.len(), SESSION_DIGEST_LEN);
        // The alphabet is a security-relevant property, not cosmetics: a digit
        // in the digest can be swallowed by the redactor's phone/SSN/card
        // detectors (see `digest`'s "Message wording is load-bearing", rule 3).
        assert!(
            digest.chars().all(|c| c.is_ascii_lowercase() && c <= 'p'),
            "digest must be a..=p letters only, got {digest}"
        );
        // It encodes the leading BLAKE3 bytes, not a re-hash: each byte becomes
        // two letters, high nibble first.
        let expected: String = blake3(b"chat-42")
            .iter()
            .take(SESSION_DIGEST_BYTES)
            .flat_map(|b| {
                [
                    char::from(b'a'.saturating_add(b >> 4)),
                    char::from(b'a'.saturating_add(b & 0x0f)),
                ]
            })
            .collect();
        assert_eq!(digest, expected);
    }

    #[test]
    fn no_session_digest_contains_a_digit_run() {
        // Regression guard for the value-dependent redaction bug: a *hex*
        // digest contained a 10+ digit run for ~0.5% of handles, and those were
        // rewritten to `[PHONE]` in production. A single hard-coded handle
        // cannot catch that — whether it trips depends on the handle — so sweep
        // enough of them that a 0.5% failure rate is a near-certain catch.
        for i in 0..2_000 {
            let digest = SessionId::new(format!("handle-{i}")).digest();
            assert!(
                !digest.chars().any(|c| c.is_ascii_digit()),
                "digest for handle-{i} contains a digit: {digest}"
            );
        }
    }

    #[test]
    fn session_id_from_conversions() {
        assert_eq!(SessionId::from("borrowed").as_str(), "borrowed");
        assert_eq!(SessionId::from("owned".to_string()).as_str(), "owned");
        let back: String = SessionId::new("x").into();
        assert_eq!(back, "x");
    }

    #[test]
    fn session_id_is_usable_as_a_map_key() {
        let mut map = HashMap::new();
        map.insert(SessionId::new("s1"), 1);
        map.insert(SessionId::new("s2"), 2);
        assert_eq!(map.get(&SessionId::new("s1")), Some(&1));
        assert_eq!(map.get(&SessionId::new("missing")), None);
    }

    #[test]
    fn entity_key_exposes_fields() {
        let key = EntityKey::new("PERSON", "Jane Doe");
        assert_eq!(key.entity_type, "PERSON");
        assert_eq!(key.original, "Jane Doe");
    }

    #[test]
    fn entity_key_equality_distinguishes_type_and_value() {
        let a = EntityKey::new("PERSON", "Jane Doe");
        let b = EntityKey::new("PERSON", "Jane Doe");
        let different_type = EntityKey::new("EMAIL", "Jane Doe");
        let different_value = EntityKey::new("PERSON", "John Roe");
        assert_eq!(a, b);
        assert_ne!(a, different_type);
        assert_ne!(a, different_value);
    }

    #[test]
    fn entity_key_is_usable_as_a_map_key() {
        let mut map = HashMap::new();
        map.insert(EntityKey::new("PERSON", "Jane Doe"), "<PERSON_0>");
        assert_eq!(
            map.get(&EntityKey::new("PERSON", "Jane Doe")),
            Some(&"<PERSON_0>")
        );
        assert_eq!(map.get(&EntityKey::new("EMAIL", "Jane Doe")), None);
    }
}
