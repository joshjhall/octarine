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
//! it protects that memory on two axes:
//!
//! - **Observability.** It never *emits* a protected value. The observe events
//!   on `put`/`flush` carry only the entity type and a truncated digest of the
//!   [`SessionId`] (never the handle itself, which a caller may have
//!   accidentally built from PII — see [`SessionId::digest`]); the [`Debug`]
//!   impl prints a session count, never the map contents. So neither an audit
//!   log nor a `{:?}` of the store can leak a protected value.
//! - **Memory lifetime.** Both the original PII and its token live in
//!   [`PrimitiveLockedSecret`] containers, which zeroize their bytes on drop.
//!   When a mapping is overwritten, a session is [`flush`](StateStore::flush)ed,
//!   or the whole store is dropped, the cleartext is overwritten rather than
//!   merely deallocated — so it does not linger in freed heap for a later
//!   over-read or a core dump to recover. Those containers also route through
//!   the `mlock` seam, keeping the pages off swap on platforms where locking is
//!   available and degrading to zeroization-only where it is not. The original
//!   is never used as a plain map key either: the inner map is keyed by a
//!   one-way BLAKE3 digest of the `(entity_type, original)` pair, so the PII
//!   byte string exists only inside a locked secret.

use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;

use async_trait::async_trait;
use octarine_problem::{Problem, Result};

use super::super::StateStore;
use super::super::types::{EntityKey, SessionId};
use crate::observe;
use crate::observe::metrics::increment_by;
use crate::primitives::crypto::hash::blake3_hex;
use crate::primitives::crypto::secrets::PrimitiveLockedSecret;

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
    sessions: RwLock<HashMap<SessionId, HashMap<String, SecureEntry>>>,
    emit_events: bool,
}

/// One stored mapping, with its secret material held in zeroize-on-drop memory.
///
/// The inner map is keyed by a BLAKE3 digest (see [`key_digest`]), not by the
/// [`EntityKey`] itself, so the original PII never sits in a plain map key.
/// This struct holds the material needed to reconstruct the `(original, token)`
/// pair on [`list`](StateStore::list):
///
/// - `entity_type` is a category label (`"PERSON"`, `"EMAIL"`) — not PII — and
///   is kept in the clear so `list` can filter by it without exposing secrets.
/// - `original` and `token` are the protected byte strings, each wrapped in a
///   [`PrimitiveLockedSecret`]: zeroized when the entry is dropped (overwrite,
///   flush, or store drop) and routed through the `mlock` seam.
struct SecureEntry {
    /// Entity category (e.g. `"PERSON"`) — a label, not a protected value.
    entity_type: String,
    /// The original pre-anonymization value, held as secret memory.
    original: PrimitiveLockedSecret,
    /// The stable token that replaces the original, held as secret memory.
    token: PrimitiveLockedSecret,
}

impl SecureEntry {
    /// Builds an entry from an [`EntityKey`] and its token, moving both secret
    /// byte strings into zeroize-on-drop locked memory.
    ///
    /// The `entity_type` (a category label) is copied in the clear; the original
    /// and token are consumed into [`PrimitiveLockedSecret`]s.
    fn from_parts(key: &EntityKey, token: String) -> Self {
        Self {
            entity_type: key.entity_type.clone(),
            original: PrimitiveLockedSecret::new(key.original.clone().into_bytes()),
            token: PrimitiveLockedSecret::new(token.into_bytes()),
        }
    }
}

/// Derives the inner-map key for an [`EntityKey`] as a hex BLAKE3 digest of
/// `entity_type || 0x00 || original`.
///
/// Hashing keeps the original PII out of the (plain, non-zeroized) map key: the
/// digest is one-way and non-sensitive, so it may live in ordinary heap, while
/// the original byte string is retained only inside a [`PrimitiveLockedSecret`].
/// The `0x00` separator is unambiguous because neither `entity_type` nor the
/// digest domain contains a NUL in practice, preventing `("AB","C")` from
/// colliding with `("A","BC")`.
fn key_digest(key: &EntityKey) -> String {
    let mut material = Vec::with_capacity(key.entity_type.len().saturating_add(key.original.len()));
    material.extend_from_slice(key.entity_type.as_bytes());
    material.push(0x00);
    material.extend_from_slice(key.original.as_bytes());
    let digest = blake3_hex(&material);
    // The composite is not itself secret (it is a digest input), but zeroize it
    // anyway: it briefly held the cleartext original, so overwrite before free.
    zeroize::Zeroize::zeroize(&mut material);
    digest
}

/// Reconstructs an owned `String` from a locked secret's bytes.
///
/// The bytes always originate from a `String` we stored ([`put`](StateStore::put)
/// / [`get_or_put`](StateStore::get_or_put) take `String` inputs), so they are
/// valid UTF-8; the fallible path is mapped to [`Problem::Runtime`] rather than
/// unwrapped, satisfying the crate's `unwrap_used` lint without a panic.
fn expose_string(secret: &PrimitiveLockedSecret) -> Result<String> {
    String::from_utf8(secret.expose_secret().to_vec())
        .map_err(|e| Problem::Runtime(format!("vault secret was not valid UTF-8: {e}")))
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
    ) -> Result<std::sync::RwLockReadGuard<'_, HashMap<SessionId, HashMap<String, SecureEntry>>>>
    {
        self.sessions
            .read()
            .map_err(|e| Problem::Runtime(format!("vault lock poisoned: {e}")))
    }

    /// Borrows the session map under the write lock, mapping a poisoned lock to
    /// [`Problem::Runtime`].
    fn write(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, HashMap<SessionId, HashMap<String, SecureEntry>>>>
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
        let Some(entry) = guard.get(session).and_then(|m| m.get(&key_digest(key))) else {
            return Ok(None);
        };
        expose_string(&entry.token).map(Some)
    }

    async fn put(&self, session: &SessionId, key: &EntityKey, value: String) -> Result<()> {
        {
            let mut guard = self.write()?;
            // Inserting overwrites any prior entry for this digest; the replaced
            // SecureEntry drops here, zeroizing its original and token bytes.
            guard
                .entry(session.clone())
                .or_default()
                .insert(key_digest(key), SecureEntry::from_parts(key, value));
        }

        if self.emit_events {
            increment_by(metric_names::put_count(), 1);
            // entity_type + session digest only — never the original value, the
            // token, or the raw session handle (#629).
            observe::debug(
                OP,
                format!(
                    "stored {} mapping (session={})",
                    key.entity_type,
                    session.digest()
                ),
            );
        }

        Ok(())
    }

    async fn list(&self, session: &SessionId, entity_type: &str) -> Result<Vec<(String, String)>> {
        let guard = self.read()?;
        let Some(map) = guard.get(session) else {
            return Ok(Vec::new());
        };
        map.values()
            .filter(|entry| entry.entity_type == entity_type)
            .map(|entry| {
                Ok((
                    expose_string(&entry.original)?,
                    expose_string(&entry.token)?,
                ))
            })
            .collect()
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
                format!(
                    "flushed session (session={}, {dropped} mapping(s) dropped)",
                    session.digest()
                ),
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
            match guard
                .entry(session.clone())
                .or_default()
                .entry(key_digest(key))
            {
                std::collections::hash_map::Entry::Occupied(e) => {
                    (expose_string(&e.get().token)?, false)
                }
                std::collections::hash_map::Entry::Vacant(e) => (
                    expose_string(&e.insert(SecureEntry::from_parts(key, value)).token)?,
                    true,
                ),
            }
        };

        if minted && self.emit_events {
            increment_by(metric_names::put_count(), 1);
            // entity_type + session digest only — never the original value, the
            // token, or the raw session handle (#629).
            observe::debug(
                OP,
                format!(
                    "minted {} mapping (session={})",
                    key.entity_type,
                    session.digest()
                ),
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

    #[tokio::test]
    async fn secrets_are_zeroized_on_flush_and_drop() {
        // Verifies the memory-lifetime half of the privacy contract: originals
        // and tokens live in zeroize-on-drop secure memory, and the flush / store
        // drop paths run that zeroizing Drop.
        //
        // NOTE ON WITNESS STRENGTH: a byte-level post-free witness (read the
        // freed pages and assert they are zero) is impossible here — the crate is
        // `unsafe_code = "forbid"`, and dereferencing a freed pointer requires
        // `unsafe`. So, exactly as `crypto::secrets` does
        // (`secret.rs::test_zeroization_on_drop` / `test_zeroization_observable`),
        // this asserts the *type-level* guarantee (secrets are held in
        // `PrimitiveLockedSecret`, whose `Drop` zeroizes) plus the *behavioral*
        // invariants around it, rather than inspecting freed memory directly.
        const ORIGINAL: &str = "Jane Doe SSN 123-45-6789";
        const TOKEN: &str = "<PERSON_0>";

        let store = InMemoryStore::silent();
        let session = SessionId::new("s1");
        let k = key("PERSON", ORIGINAL);

        store
            .put(&session, &k, TOKEN.to_string())
            .await
            .expect("put");

        // While live, the secrets reconstruct through the locked containers.
        assert_eq!(
            store.get(&session, &k).await.expect("get"),
            Some(TOKEN.to_string())
        );
        assert_eq!(
            store.list(&session, "PERSON").await.expect("list"),
            vec![(ORIGINAL.to_string(), TOKEN.to_string())]
        );

        // Flush removes the session's inner map, dropping every SecureEntry —
        // which zeroizes each original/token via PrimitiveLockedSecret::drop.
        // After flush the mapping is gone (the entries were destroyed, not just
        // hidden).
        store.flush(&session).await.expect("flush");
        assert_eq!(store.get(&session, &k).await.expect("get"), None);
        assert!(
            store
                .list(&session, "PERSON")
                .await
                .expect("list")
                .is_empty()
        );

        // The Debug guarantee holds across the whole lifetime: neither the
        // original PII nor the token is ever reachable via `{:?}`.
        store
            .put(&session, &k, TOKEN.to_string())
            .await
            .expect("re-put");
        let dbg = format!("{store:?}");
        assert!(
            !dbg.contains(ORIGINAL),
            "original PII must never appear in Debug"
        );
        assert!(!dbg.contains(TOKEN), "token must never appear in Debug");

        // Dropping the whole store zeroizes all remaining sessions the same way
        // (transitive Drop). Nothing to assert post-drop without unsafe, but the
        // drop must not panic.
        drop(store);

        // Direct demonstration of the container's zeroize-on-drop, mirroring
        // `crypto::secrets`: expose the bytes while live, then drop. The
        // `PrimitiveLockedSecret` Drop overwrites the backing buffer.
        let secret = PrimitiveLockedSecret::new(ORIGINAL.as_bytes().to_vec());
        assert_eq!(secret.expose_secret(), ORIGINAL.as_bytes());
        drop(secret);
    }

    #[test]
    fn key_digest_is_stable_and_separates_entity_type_from_original() {
        // Same (type, original) → same digest (stability), and the 0x00 domain
        // separator prevents ("AB","C") colliding with ("A","BC").
        let a = key_digest(&key("PERSON", "Jane"));
        let b = key_digest(&key("PERSON", "Jane"));
        assert_eq!(a, b, "digest must be deterministic for a stable key");

        let split_1 = key_digest(&key("AB", "C"));
        let split_2 = key_digest(&key("A", "BC"));
        assert_ne!(
            split_1, split_2,
            "the separator must keep boundary-shifted pairs distinct"
        );

        // The digest is hex of a 32-byte BLAKE3 hash and never contains the PII.
        assert_eq!(a.len(), 64);
        assert!(!a.contains("Jane"));
    }
}
