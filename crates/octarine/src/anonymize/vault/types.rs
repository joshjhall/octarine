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

use crate::primitives::crypto::hash::blake3_hex;

/// Hex characters of the BLAKE3 digest [`SessionId::digest`] retains.
///
/// 12 hex chars is 48 bits — ample to distinguish the sessions alive in one
/// audit stream while far too short to brute-force a handle back out of a log.
/// Matches the `KEY_DIGEST_HEX_LEN` used for `SecureMap` key digests, so the
/// two redaction schemes read alike in a combined log.
const SESSION_DIGEST_HEX_LEN: usize = 12;

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
    /// # Message wording is load-bearing
    ///
    /// Callers phrase these events as `session=…`, deliberately **not**
    /// `session secret: …`. The PII redactor masks everything following a
    /// `secret:` / `password:` style prefix, which would replace the digest and
    /// destroy the correlation it exists to provide — the trap documented on
    /// `SecureMap`'s equivalent helper in `crypto/secrets/map.rs`.
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
        let mut digest = blake3_hex(self.0.as_bytes());
        // Hex is ASCII, so truncating at a byte index is always a char boundary.
        digest.truncate(SESSION_DIGEST_HEX_LEN);
        digest
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
        assert_eq!(SessionId::new("").digest().len(), SESSION_DIGEST_HEX_LEN);
    }

    #[test]
    fn session_id_digest_is_truncated_lowercase_hex() {
        let digest = SessionId::new("chat-42").digest();
        assert_eq!(digest.len(), SESSION_DIGEST_HEX_LEN);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        // Truncation is a prefix of the full BLAKE3 hex, not a re-hash.
        assert!(blake3_hex(b"chat-42").starts_with(&digest));
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
