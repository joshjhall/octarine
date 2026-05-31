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

/// An opaque per-session handle that scopes a run of reversible
/// pseudonymization.
///
/// A session groups every `original → token` mapping minted while protecting a
/// conversation or request. The same `SessionId` must be presented to a later
/// deanonymize call to recover the original identities. The value is
/// caller-chosen and carries no entropy requirement of its own — unlike an
/// authentication session token, it is a routing label, not a credential, so it
/// is shown in full by [`Display`](fmt::Display) to aid debugging.
///
/// # Examples
///
/// ```
/// use octarine::anonymize::SessionId;
///
/// let session = SessionId::new("chat-42");
/// assert_eq!(session.as_str(), "chat-42");
/// assert_eq!(session.to_string(), "chat-42");
/// ```
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct SessionId(String);

impl SessionId {
    /// Creates a session handle from any string-like value.
    ///
    /// Infallible: the value is an opaque label, so no validation is applied.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
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
