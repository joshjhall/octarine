//! [`InMemoryStore`] — the default, zero-dependency [`StateStore`] backend.
//!
//! A `RwLock<HashMap>` keyed by [`SessionId`], with a per-session inner map
//! from [`EntityKey`] to its stable token. This is the backend tests and
//! single-process deployments use: no Redis, no Postgres, nothing to
//! provision. It is also the *reference* implementation every other backend's
//! trait-conformance suite is checked against.
//!
//! Concurrency is read-optimized. [`get`](StateStore::get) and
//! [`list`](StateStore::list) take the read lock, so many readers proceed in
//! parallel; [`put`](StateStore::put) and [`flush`](StateStore::flush) take the
//! write lock only for the brief span of a map mutation. A poisoned lock (a
//! writer panicked mid-mutation) surfaces as [`Problem::Runtime`] rather than
//! propagating the panic.
//!
//! # Privacy
//!
//! The store holds original PII in memory by definition — that is its job — but
//! it never *emits* it. The observe events on `put`/`flush` carry only the
//! entity type and the (non-secret) [`SessionId`]; the [`Debug`] impl prints a
//! session count, never the map contents. So neither an audit log nor a
//! `{:?}` of the store can leak a protected value.

use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;

use async_trait::async_trait;
use octarine_problem::{Problem, Result};

use super::super::StateStore;
use super::super::types::{EntityKey, SessionId};
use crate::observe;
use crate::observe::metrics::increment_by;

crate::define_metrics! {
    put_count => "anonymize.vault.put_count",
    flush_count => "anonymize.vault.flush_count",
}

/// Operation context label for this backend's observe events.
const OP: &str = "anonymize.vault.memory";

/// The default in-memory [`StateStore`]: a lock-guarded map of per-session
/// `EntityKey → token` mappings.
///
/// Construct one with [`InMemoryStore::new`] (or [`Default`]) and share it
/// across threads as `Arc<dyn StateStore>`. Audit events are emitted on every
/// mutating call; suppress them with [`InMemoryStore::silent`] when the store
/// is used purely as a fixture and the event noise is unwanted.
///
/// # Examples
///
/// Wiring the store behind the trait object the operators consume, then driving
/// one anonymize/deanonymize round trip by hand:
///
/// ```
/// use std::sync::Arc;
/// use octarine::anonymize::{EntityKey, InMemoryStore, SessionId, StateStore};
///
/// # tokio_test::block_on(async {
/// let store: Arc<dyn StateStore> = Arc::new(InMemoryStore::new());
/// let session = SessionId::new("chat-42");
/// let key = EntityKey::new("PERSON", "Jane Doe");
///
/// // First sighting of "Jane Doe": no token yet, so the operator mints one.
/// // `get_or_put` is the atomic mint — it returns the caller's token because
/// // none was stored.
/// assert_eq!(store.get_or_put(&session, &key, "<PERSON_0>".to_string()).await?, "<PERSON_0>");
///
/// // Re-sighting reuses the stored token (stability across the session): a
/// // second mint with a different value still returns the original.
/// assert_eq!(store.get_or_put(&session, &key, "<PERSON_9>".to_string()).await?, "<PERSON_0>");
/// assert_eq!(store.get(&session, &key).await?, Some("<PERSON_0>".to_string()));
///
/// // Enumerate every PERSON mapping to build the reverse lookup.
/// assert_eq!(
///     store.list(&session, "PERSON").await?,
///     vec![("Jane Doe".to_string(), "<PERSON_0>".to_string())],
/// );
///
/// // Conversation over: drop all of the session's state.
/// store.flush(&session).await?;
/// assert_eq!(store.get(&session, &key).await?, None);
/// # Ok::<(), octarine_problem::Problem>(())
/// # });
/// ```
pub struct InMemoryStore {
    sessions: RwLock<HashMap<SessionId, HashMap<EntityKey, String>>>,
    emit_events: bool,
}

impl InMemoryStore {
    /// Creates an empty store that emits an audit event on every mutation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            emit_events: true,
        }
    }

    /// Creates an empty store that emits no observe events.
    ///
    /// Useful when the store is a test fixture or a transient helper and the
    /// per-`put` audit events would only be noise. Metrics and events are both
    /// suppressed; the stored mappings behave identically.
    #[must_use]
    pub fn silent() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            emit_events: false,
        }
    }

    /// Borrows the session map under the read lock, mapping a poisoned lock to
    /// [`Problem::Runtime`].
    fn read(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, HashMap<SessionId, HashMap<EntityKey, String>>>>
    {
        self.sessions
            .read()
            .map_err(|e| Problem::Runtime(format!("vault lock poisoned: {e}")))
    }

    /// Borrows the session map under the write lock, mapping a poisoned lock to
    /// [`Problem::Runtime`].
    fn write(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, HashMap<SessionId, HashMap<EntityKey, String>>>>
    {
        self.sessions
            .write()
            .map_err(|e| Problem::Runtime(format!("vault lock poisoned: {e}")))
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Prints a session count only — never the mapped keys or tokens — so a `{:?}`
/// of the store cannot leak a protected value into a log line.
///
/// Uses `try_read` rather than a blocking `read`: a `Debug` format triggered
/// from a context that already holds the lock (a panic handler or a log line
/// inside `put`/`flush`) would otherwise deadlock, since `std::sync::RwLock` is
/// not reentrant. An unavailable lock prints `<locked>` instead of hanging.
impl fmt::Debug for InMemoryStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("InMemoryStore");
        match self.sessions.try_read() {
            Ok(guard) => dbg.field("sessions", &guard.len()),
            Err(std::sync::TryLockError::WouldBlock) => dbg.field("sessions", &"<locked>"),
            Err(std::sync::TryLockError::Poisoned(_)) => dbg.field("sessions", &"<poisoned>"),
        };
        dbg.field("emit_events", &self.emit_events).finish()
    }
}

#[async_trait]
impl StateStore for InMemoryStore {
    async fn get(&self, session: &SessionId, key: &EntityKey) -> Result<Option<String>> {
        let guard = self.read()?;
        Ok(guard.get(session).and_then(|m| m.get(key)).cloned())
    }

    async fn put(&self, session: &SessionId, key: &EntityKey, value: String) -> Result<()> {
        {
            let mut guard = self.write()?;
            guard
                .entry(session.clone())
                .or_default()
                .insert(key.clone(), value);
        }

        if self.emit_events {
            increment_by(metric_names::put_count(), 1);
            // entity_type + session label only — never the original value or token.
            observe::debug(
                OP,
                format!("stored {} mapping in session {}", key.entity_type, session),
            );
        }

        Ok(())
    }

    async fn list(&self, session: &SessionId, entity_type: &str) -> Result<Vec<(String, String)>> {
        let guard = self.read()?;
        let Some(map) = guard.get(session) else {
            return Ok(Vec::new());
        };
        Ok(map
            .iter()
            .filter(|(k, _)| k.entity_type == entity_type)
            .map(|(k, token)| (k.original.clone(), token.clone()))
            .collect())
    }

    async fn flush(&self, session: &SessionId) -> Result<()> {
        let removed = {
            let mut guard = self.write()?;
            guard.remove(session)
        };

        if self.emit_events {
            increment_by(metric_names::flush_count(), 1);
            let dropped = removed.map_or(0, |m| m.len());
            observe::debug(
                OP,
                format!("flushed session {session} ({dropped} mapping(s) dropped)"),
            );
        }

        Ok(())
    }

    async fn get_or_put(
        &self,
        session: &SessionId,
        key: &EntityKey,
        value: String,
    ) -> Result<String> {
        // Single write-lock acquisition makes the check-and-set atomic: a
        // concurrent caller racing on the same key either sees this token or is
        // serialized behind this write, so no two callers mint divergent tokens.
        let (token, minted) = {
            let mut guard = self.write()?;
            match guard.entry(session.clone()).or_default().entry(key.clone()) {
                std::collections::hash_map::Entry::Occupied(e) => (e.get().clone(), false),
                std::collections::hash_map::Entry::Vacant(e) => (e.insert(value).clone(), true),
            }
        };

        if minted && self.emit_events {
            increment_by(metric_names::put_count(), 1);
            // entity_type + session label only — never the original value or token.
            observe::debug(
                OP,
                format!("minted {} mapping in session {}", key.entity_type, session),
            );
        }

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use std::sync::Arc;

    fn key(entity_type: &str, original: &str) -> EntityKey {
        EntityKey::new(entity_type, original)
    }

    #[tokio::test]
    async fn get_returns_none_for_unknown_key() {
        let store = InMemoryStore::silent();
        let session = SessionId::new("s1");
        assert_eq!(
            store
                .get(&session, &key("PERSON", "Jane"))
                .await
                .expect("get"),
            None
        );
    }

    #[tokio::test]
    async fn put_then_get_returns_stored_token() {
        let store = InMemoryStore::silent();
        let session = SessionId::new("s1");
        let k = key("PERSON", "Jane Doe");

        store
            .put(&session, &k, "<PERSON_0>".to_string())
            .await
            .expect("put");
        assert_eq!(
            store.get(&session, &k).await.expect("get"),
            Some("<PERSON_0>".to_string())
        );
    }

    #[tokio::test]
    async fn put_is_idempotent_for_identical_value() {
        // Re-putting the same key/value is observably a no-op.
        let store = InMemoryStore::silent();
        let session = SessionId::new("s1");
        let k = key("PERSON", "Jane Doe");

        store
            .put(&session, &k, "<PERSON_0>".to_string())
            .await
            .expect("put");
        store
            .put(&session, &k, "<PERSON_0>".to_string())
            .await
            .expect("put again");

        assert_eq!(
            store.get(&session, &k).await.expect("get"),
            Some("<PERSON_0>".to_string())
        );
        // Exactly one mapping for the type — the repeat did not duplicate.
        assert_eq!(store.list(&session, "PERSON").await.expect("list").len(), 1);
    }

    #[tokio::test]
    async fn put_overwrites_with_new_value() {
        let store = InMemoryStore::silent();
        let session = SessionId::new("s1");
        let k = key("PERSON", "Jane Doe");

        store
            .put(&session, &k, "<PERSON_0>".to_string())
            .await
            .expect("put");
        store
            .put(&session, &k, "<PERSON_1>".to_string())
            .await
            .expect("overwrite");

        assert_eq!(
            store.get(&session, &k).await.expect("get"),
            Some("<PERSON_1>".to_string())
        );
    }

    #[tokio::test]
    async fn list_filters_by_entity_type_within_session() {
        let store = InMemoryStore::silent();
        let session = SessionId::new("s1");
        store
            .put(&session, &key("PERSON", "Jane"), "<PERSON_0>".to_string())
            .await
            .expect("put");
        store
            .put(&session, &key("PERSON", "Bob"), "<PERSON_1>".to_string())
            .await
            .expect("put");
        store
            .put(
                &session,
                &key("EMAIL", "jane@acme.com"),
                "<EMAIL_0>".to_string(),
            )
            .await
            .expect("put");

        // Sort before comparing: list() iterates a HashMap, so order is
        // unspecified. The multi-entry case would expose an ordering bug a
        // single-element assertion cannot.
        let mut persons = store.list(&session, "PERSON").await.expect("list");
        persons.sort();
        assert_eq!(
            persons,
            vec![
                ("Bob".to_string(), "<PERSON_1>".to_string()),
                ("Jane".to_string(), "<PERSON_0>".to_string()),
            ]
        );

        // Unknown type and unknown session both yield empty, not error.
        assert!(store.list(&session, "SSN").await.expect("list").is_empty());
        assert!(
            store
                .list(&SessionId::new("other"), "PERSON")
                .await
                .expect("list")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn flush_drops_only_the_named_session() {
        let store = InMemoryStore::silent();
        let k = key("PERSON", "Jane");
        let s1 = SessionId::new("s1");
        let s2 = SessionId::new("s2");
        store
            .put(&s1, &k, "<PERSON_0>".to_string())
            .await
            .expect("put");
        store
            .put(&s2, &k, "<PERSON_0>".to_string())
            .await
            .expect("put");

        store.flush(&s1).await.expect("flush");
        assert_eq!(store.get(&s1, &k).await.expect("get"), None);
        assert_eq!(
            store.get(&s2, &k).await.expect("get"),
            Some("<PERSON_0>".to_string())
        );
    }

    #[tokio::test]
    async fn flush_unknown_session_is_ok() {
        let store = InMemoryStore::silent();
        store
            .flush(&SessionId::new("never-seen"))
            .await
            .expect("flush is a no-op success");
    }

    #[tokio::test]
    async fn usable_as_trait_object_behind_arc() {
        let store: Arc<dyn StateStore> = Arc::new(InMemoryStore::silent());
        let session = SessionId::new("s1");
        let k = key("PERSON", "Jane");
        store
            .put(&session, &k, "<PERSON_0>".to_string())
            .await
            .expect("put");
        assert_eq!(
            store.get(&session, &k).await.expect("get"),
            Some("<PERSON_0>".to_string())
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_puts_in_one_session_converge_without_lost_writes() {
        // 100 distinct keys written concurrently into the same session must all
        // land — no panic, no lost writes — proving the per-session write lock
        // serializes mutations correctly.
        let store = Arc::new(InMemoryStore::silent());
        let session = SessionId::new("hot-session");

        let mut handles = Vec::with_capacity(100);
        for i in 0..100 {
            let store = Arc::clone(&store);
            let session = session.clone();
            handles.push(tokio::spawn(async move {
                let k = EntityKey::new("PERSON", format!("person-{i}"));
                store
                    .put(&session, &k, format!("<PERSON_{i}>"))
                    .await
                    .expect("put");
            }));
        }
        for h in handles {
            h.await.expect("join");
        }

        let mut listed = store.list(&session, "PERSON").await.expect("list");
        assert_eq!(listed.len(), 100, "every concurrent put must be retained");
        listed.sort();
        // Spot-check a representative mapping survived intact.
        assert!(listed.contains(&("person-0".to_string(), "<PERSON_0>".to_string())));
        assert!(listed.contains(&("person-99".to_string(), "<PERSON_99>".to_string())));
    }

    #[test]
    fn debug_exposes_session_count_not_contents() {
        // The Debug impl must expose a count, not the protected map contents.
        // The non-empty case (`debug_with_data_still_hides_originals`) proves
        // data is hidden; this one pins the structural shape for an empty store.
        let store = InMemoryStore::silent();
        let dbg = format!("{store:?}");
        assert!(dbg.contains("InMemoryStore"));
        assert!(dbg.contains("sessions: 0"));
        assert!(dbg.contains("emit_events: false"));
    }

    #[tokio::test]
    async fn debug_with_data_still_hides_originals() {
        let store = InMemoryStore::silent();
        store
            .put(
                &SessionId::new("s1"),
                &key("PERSON", "Jane Doe"),
                "<PERSON_0>".to_string(),
            )
            .await
            .expect("put");
        let dbg = format!("{store:?}");
        assert!(
            !dbg.contains("Jane Doe"),
            "original PII must never appear in Debug"
        );
        assert!(
            !dbg.contains("<PERSON_0>"),
            "token must not appear in Debug"
        );
        assert!(dbg.contains("sessions"));
    }

    #[test]
    fn default_matches_new_emit_events_on() {
        // Guard against a refactor that silently makes Default delegate to
        // silent() instead of new(), which would disable audit events for any
        // caller relying on `InMemoryStore::default()`.
        assert!(format!("{:?}", InMemoryStore::default()).contains("emit_events: true"));
        assert!(format!("{:?}", InMemoryStore::new()).contains("emit_events: true"));
    }

    #[tokio::test]
    async fn new_store_exercises_event_path_without_error() {
        // Every other test uses silent(); this one drives the emit_events=true
        // branch of put/flush (observe::debug + increment_by) so a regression in
        // the metric names or event formatting cannot pass undetected.
        let store = InMemoryStore::new();
        let session = SessionId::new("s1");
        let k = key("PERSON", "Jane Doe");

        store
            .put(&session, &k, "<PERSON_0>".to_string())
            .await
            .expect("put with events");
        assert_eq!(
            store.get(&session, &k).await.expect("get"),
            Some("<PERSON_0>".to_string())
        );
        store.flush(&session).await.expect("flush with events");
        assert_eq!(
            store.get(&session, &k).await.expect("get after flush"),
            None
        );
    }

    #[tokio::test]
    async fn get_or_put_mints_then_returns_stable_token() {
        let store = InMemoryStore::new(); // also covers the emit path for the mint
        let session = SessionId::new("s1");
        let k = key("PERSON", "Jane Doe");

        // First call mints and returns the caller's token.
        assert_eq!(
            store
                .get_or_put(&session, &k, "<PERSON_0>".to_string())
                .await
                .expect("mint"),
            "<PERSON_0>"
        );
        // Second call returns the *stored* token, ignoring the new value.
        assert_eq!(
            store
                .get_or_put(&session, &k, "<PERSON_9>".to_string())
                .await
                .expect("reuse"),
            "<PERSON_0>"
        );
        assert_eq!(
            store.get(&session, &k).await.expect("get"),
            Some("<PERSON_0>".to_string())
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_get_or_put_on_same_key_converges_to_one_token() {
        // The core anti-TOCTOU guarantee: 100 callers racing to mint a token for
        // the SAME key must all observe the SAME winning token, and the store
        // must hold exactly that one mapping. A non-atomic get-then-put would let
        // divergent tokens leak to the losers.
        let store = Arc::new(InMemoryStore::silent());
        let session = SessionId::new("race");
        let k = key("PERSON", "Jane Doe");

        let mut handles = Vec::with_capacity(100);
        for i in 0..100 {
            let store = Arc::clone(&store);
            let session = session.clone();
            let k = k.clone();
            handles.push(tokio::spawn(async move {
                store
                    .get_or_put(&session, &k, format!("<PERSON_{i}>"))
                    .await
                    .expect("get_or_put")
            }));
        }
        let mut tokens = Vec::with_capacity(100);
        for h in handles {
            tokens.push(h.await.expect("join"));
        }

        // Every caller saw the identical winning token...
        let winner = tokens.first().expect("at least one token").clone();
        assert!(
            tokens.iter().all(|t| *t == winner),
            "all racing callers must agree on one token, got divergent: {tokens:?}"
        );
        // ...and exactly one mapping exists for the key.
        assert_eq!(store.list(&session, "PERSON").await.expect("list").len(), 1);
        assert_eq!(store.get(&session, &k).await.expect("get"), Some(winner));
    }
}
